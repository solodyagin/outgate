#!/usr/bin/env python3
"""Check grant, provider and registration contract fixtures without performing authentication."""
import base64
import hashlib
import hmac
import json
from datetime import datetime, timedelta
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
FIXTURES = ROOT / "tests/fixtures"


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def check(condition, message):
    if not condition:
        raise ValueError(message)


def rejects(label, check_case):
    try:
        check_case()
    except ValueError:
        return
    raise ValueError(f"Accepted invalid fixture: {label}")


def valid(validator, instance, label):
    error = next(validator.iter_errors(instance), None)
    if error is not None:
        raise ValueError(f"{label}: {error.json_path} violates {error.validator}")


def decode_part(value, minimum):
    raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    canonical = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    check(hmac.compare_digest(canonical, value) and len(raw) >= minimum, "Invalid grant part")
    return raw


def timestamp(value):
    return datetime.fromisoformat(value)


def check_grant_lifetime(issued_at, expires_at):
    issued, expires = timestamp(issued_at), timestamp(expires_at)
    check(issued < expires <= issued + timedelta(hours=1), "Grant expiry outside issuance bounds")


def check_issuance(openapi, grant_validator, record_validator, fixture):
    endpoint = openapi["paths"]["/admin/deployment-grants"]["post"]
    request = endpoint["requestBody"]["content"]["application/json"]["example"]
    examples = endpoint["responses"]["200"]["content"]["application/json"]["examples"]
    first, repeat = (examples[name]["value"] for name in ("first", "repeat"))
    binding = {key: value for key, value in request.items() if key not in {"expected_revision", "reason"}}
    valid(grant_validator, binding, "grant binding")
    valid(grant_validator, {key: value for key, value in binding.items() if key != "credential_generation"},
          "static grant binding")
    check(all(first.get(key) == repeat.get(key) == value for key, value in binding.items()),
          "Grant responses changed immutable binding")
    grant_id, secret = first["deployment_grant"].split(".")
    check(grant_id == first["grant_id"] == repeat["grant_id"], "Grant ID differs between responses")
    decode_part(grant_id, 16)
    digest = hashlib.sha256(decode_part(secret, 32)).hexdigest()
    check(hmac.compare_digest(digest, fixture["secret_sha256"]), "Secret digest vector mismatch")
    check("deployment_grant" not in repeat and "secret_sha256" not in repeat and not repeat["secret_available"],
          "Repeated response discloses secret material")

    record = binding | {"grant_id": grant_id, "secret_sha256": digest, "issued_at": fixture["now"], "revoked_at": None}
    valid(record_validator, record, "control record")
    check_grant_lifetime(record["issued_at"], record["expires_at"])
    for expiry in (record["issued_at"], "2026-01-01T13:00:01Z"):
        rejects("invalid issuance lifetime", lambda: check_grant_lifetime(record["issued_at"], expiry))
    rejects("plaintext secret in control state", lambda: valid(
        record_validator, record | {"deployment_grant": first["deployment_grant"]}, "control record"))
    rejects("non-canonical base64url", lambda: decode_part(grant_id[:-1] + "B", 16))
    rejects("undersized secret", lambda: decode_part(secret[:40], 32))
    return binding


def check_binding(binding, register, cert, now):
    fields = ("service_id", "instance_id", "version", "path_mode", "rewrite_mount_headers", "credential_generation")
    check(all(binding.get(key) == register.get(key) for key in fields), "Register identity or mount mode differs")
    check(set(binding["paths"]) == set(register["paths"]), "Register paths differ")
    check(binding["mounts"] == register.get("mounts", {}), "Register mounts differ")
    check(set(binding["mounts"].values()) <= set(binding["paths"]), "Mount target is absent from paths")
    for paths in (binding["paths"], register["paths"]):
        check(len({path.rstrip("/") or "/" for path in paths}) == len(paths), "Duplicate normalized prefix")
    identity = f"spiffe://outgate.example/service/{binding['service_id']}/instance/{binding['instance_id']}"
    check(cert["uri_san"] == identity, "Certificate URI SAN differs")
    check(hmac.compare_digest(cert["spki_sha256"], binding["spki_sha256"]), "Certificate SPKI differs")
    expiry = timestamp(binding["expires_at"])
    not_before, not_after = timestamp(cert["not_before"]), timestamp(cert["not_after"])
    check(now < expiry, "Grant expired before registration")
    check(not_before <= now < not_after <= not_before + timedelta(hours=24), "Certificate outside time bounds")
    return int(min(expiry, not_after).timestamp())


def check_registration(binding, fixture, protocol_validator):
    control = read_json(FIXTURES / "protocol/v1/control-messages.json")
    golden = {sample["type"]: sample for sample in control["positive"]}
    fields = ("service_id", "instance_id", "version", "paths", "mounts", "path_mode", "rewrite_mount_headers",
              "credential_generation")
    register = golden["register"] | {key: binding[key] for key in fields}
    ack = golden["register_ack"] | {"credential_generation": binding["credential_generation"]}
    for message in (register, ack):
        for field in ("capabilities", "required_capabilities"):
            message[field] = [*message[field], "credential_generation"]
    check(register["credential_generation"] == fixture["snapshots"][-1]["generation"], "Manifest/register generation differs")
    cert, now = fixture["certificate"], timestamp(fixture["now"])
    ack["credential_expires_at"] = check_binding(binding, register, cert, now)
    check(ack["credential_expires_at"] == int(timestamp(cert["not_after"]).timestamp()), "Certificate expiry must cap ack")
    ack["paths"] = [{"path": path, "state": "pending"} for path in binding["paths"]]
    for frame in (register, ack):
        valid(protocol_validator, frame, frame["type"])
    check(ack["credential_generation"] == register["credential_generation"], "Ack must echo the accepted generation")

    static_binding = {key: value for key, value in binding.items() if key != "credential_generation"} | {"mounts": {}}
    static_register = {key: value for key, value in register.items() if key not in {"credential_generation", "mounts"}}
    for field in ("capabilities", "required_capabilities"):
        static_register[field] = [name for name in static_register[field] if name not in {"credential_generation", "mount_discovery"}]
    valid(protocol_validator, static_register, "static register")
    check_binding(static_binding, static_register, cert, now)

    for field, value in (
        ("service_id", "other"), ("version", "1.0.1"), ("instance_id", "reports-2"),
        ("paths", ["/api/reports/"]), ("mounts", {}), ("path_mode", "strip"), ("rewrite_mount_headers", True),
        ("credential_generation", fixture["snapshots"][0]["generation"]),
    ):
        rejects(f"register mismatch for {field}", lambda: check_binding(binding, register | {field: value}, cert, now))
    for new_cert in (cert | {"uri_san": cert["uri_san"] + "-other"}, cert | {"spki_sha256": "b" * 64}):
        rejects("certificate binding", lambda: check_binding(binding, register, new_cert, now))
    rejects("expired grant", lambda: check_binding(binding | {"expires_at": fixture["now"]}, register, cert, now))
    duplicate_paths = [*binding["paths"], binding["paths"][0] + "/"]
    rejects("duplicate normalized paths", lambda: check_binding(
        binding | {"paths": duplicate_paths}, register | {"paths": duplicate_paths}, cert, now))
    outside_mount = {"api": "/ungranted"}
    rejects("mount outside granted paths", lambda: check_binding(
        binding | {"mounts": outside_mount}, register | {"mounts": outside_mount}, cert, now))


def main():
    grant_schema = read_json(DOCS / "deployment-grant.schema.json")
    provider_schema = read_json(DOCS / "credential-provider.schema.json")
    for schema in (grant_schema, provider_schema):
        Draft202012Validator.check_schema(schema)
    registry = Registry().with_resource(grant_schema["$id"], Resource.from_contents(grant_schema))
    grant = Draft202012Validator(grant_schema, registry=registry, format_checker=Draft202012Validator.FORMAT_CHECKER)
    record = grant.evolve(schema={"$ref": grant_schema["$id"] + "#/$defs/controlRecord"})
    provider = Draft202012Validator(provider_schema, registry=registry, format_checker=grant.format_checker)
    fixture = read_json(FIXTURES / "credentials/v1/rotation.json")
    for snapshot in fixture["snapshots"]:
        valid(provider, snapshot, "provider manifest")
    previous, current = fixture["snapshots"]
    check(int(previous["generation"]) < int(current["generation"]), "Fixture does not advance provider generation")
    valid(provider, current | {"generation": "18446744073709551615"}, "maximum generation")
    for generation in ("0", "01", "18446744073709551616", 8, None):
        rejects("invalid generation", lambda: valid(provider, current | {"generation": generation}, "provider"))
    for field in ("server_ca_file", "private_key", "deployment_grant", "admin_token"):
        rejects("provider contains an unsupported value", lambda: valid(provider, current | {field: "example-only"}, "provider"))
    incomplete = {key: val for key, val in current.items() if key != "deployment_grant_file"}
    rejects("incomplete pair", lambda: valid(provider, incomplete, "provider"))

    openapi = yaml.safe_load((DOCS / "admin-openapi.yaml").read_text(encoding="utf-8"))
    binding = check_issuance(openapi, grant, record, fixture)
    protocol = Draft202012Validator(read_json(DOCS / "protocol.schema.json"))
    check_registration(binding, fixture, protocol)
    print("PASS: deployment grant issuance, control record, protected provider manifests and registration bindings.")


if __name__ == "__main__":
    main()
