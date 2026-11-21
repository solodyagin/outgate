#!/usr/bin/env python3
"""Verify Outgate startup configuration and Admin API import fixtures offline."""
import json
import re
from copy import deepcopy
from fractions import Fraction
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

DOCS = Path(__file__).resolve().parents[1] / "docs"
EXAMPLES = DOCS / "examples"
UNITS = {
    "h": 3600, "m": 60, "s": 1, "ms": Fraction(1, 1000),
    "us": Fraction(1, 10**6), "µs": Fraction(1, 10**6),
    "μs": Fraction(1, 10**6), "ns": Fraction(1, 10**9),
}
DURATION = re.compile(r"([0-9]+(?:\.[0-9]*)?|\.[0-9]+)(ns|us|µs|μs|ms|s|m|h)")


class ConfigLoader(yaml.SafeLoader):
    # PyYAML's default YAML 1.1 implicit resolvers also convert yes/on and dates.
    yaml_implicit_resolvers = {}

    def construct_mapping(self, node, deep=False):
        values = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in values:
                raise ValueError(f"Invalid or duplicate YAML key on line {key_node.start_mark.line + 1}")
            values[key] = self.construct_object(value_node, deep=deep)
        return values


ConfigLoader.add_implicit_resolver("tag:yaml.org,2002:bool", re.compile(r"^(?:true|false)$"), ["t", "f"])
ConfigLoader.add_implicit_resolver("tag:yaml.org,2002:null", re.compile(r"^(?:null)?$"), ["n", ""])
ConfigLoader.add_implicit_resolver("tag:yaml.org,2002:int", re.compile(r"^-?(?:0|[1-9][0-9]*)$"),
                                   list("-0123456789"))


def parse(source):
    return yaml.load(source, Loader=ConfigLoader)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate(validator, value, label):
    error = next(validator.iter_errors(value), None)
    if error is not None:
        # Errors report field location and rule, without a potentially secret value.
        raise ValueError(f"{label}: {error.json_path} violates {error.validator}")


def seconds(section, key, default):
    value = section.get(key, default)
    duration = sum(Fraction(amount) * UNITS[unit] for amount, unit in DURATION.findall(value))
    require(1 <= duration * 10**9 <= 2**63 - 1, f"{key} is outside positive Go duration range")
    return duration


def check_gateway_invariants(config):
    services = config["services"]
    root = config.get("frontend_override", {}).get("service_id")
    require(root is None or root in services, "Unknown frontend service")
    strategy = config.get("routing", {}).get("strategy", "round_robin")
    for sid, service in services.items():
        normalized = {path.rstrip("/") or "/" for path in service["allowed_paths"]}
        require(len(normalized) == len(service["allowed_paths"]), "Duplicate normalized prefix")
        require("/" not in normalized or sid == root, "Root permission granted to an unassigned service")
        rollout = service["rollout"]
        stable, canary = rollout["stable_version"], rollout.get("canary_version")
        require(stable != canary, "Stable and canary must differ")
        routing = service.get("instance_routing", {})
        if routing.get("strategy", strategy) == "active_passive":
            pools = routing.get("versions", {})
            percent = rollout.get("canary_percent", 0)
            require(percent == 100 or stable in pools, "Active stable version has no instance order")
            require(percent == 0 or canary in pools, "Active canary version has no instance order")
            instances = [instance for pool in pools.values() for instance in pool["instance_order"]]
            require(len(instances) == len(set(instances)), "Instance ID is shared between version orders")
            readiness = routing.get("readiness", {})
            interval = seconds(readiness, "interval", "5s")
            require(seconds(readiness, "timeout", "2s") < interval, "Readiness timeout >= interval")
            require(seconds(readiness, "status_timeout", "15s") >= 2 * interval, "Status timeout below two intervals")

    tunnel = config["tunnel"]
    quic, wss = tunnel.get("quic", {}), tunnel.get("wss", {})
    if quic.get("enabled", True):
        require(seconds(quic, "keepalive_interval", "15s") < seconds(quic, "idle_timeout", "45s"),
                "QUIC idle timeout <= keepalive")
    if wss.get("enabled", False):
        require(seconds(wss, "pong_timeout", "10s") < seconds(wss, "ping_interval", "15s"),
                "WSS pong timeout >= ping interval")
    require(seconds(tunnel, "connect_timeout", "5s") + seconds(tunnel, "tls_handshake_timeout", "5s") <= 10,
            "Combined connect/TLS timeout exceeds ten seconds")

    access = config.get("interservice", {})
    callers, recipients = access.get("callers", {}), access.get("recipients", {})
    active_service_ids = set(services)
    require(callers.keys() <= active_service_ids and recipients.keys() <= active_service_ids, "Unknown keyring service")
    for keyrings in (callers, recipients):
        for keyring in keyrings.values():
            keys = {key["key_id"] for key in keyring["keys"]}
            require(len(keys) == len(keyring["keys"]), "Duplicate HMAC key ID")
            require(keyring.get("active_key_id", next(iter(keys))) in keys, "Active HMAC key is absent")
    for rule in access.get("policies", []):
        require(rule["caller"] in callers and rule["target"] in recipients, "Policy lacks caller/recipient keyring")

    deployment = config.get("deployment", {})
    if deployment.get("mode", "production") == "development":
        for entry in config["auth"]["bearer_tokens"]:
            require(entry["service_id"] in services, "Bearer points to an unknown service")
        return

    security = config["security"]
    rates = security["rate_limits"]
    capacity = access.get("replay_cache_max_entries", 200000)
    minimum_capacity = rates.get("signed_per_second", 1000) * 150 + rates.get("signed_burst", 2000)
    require(capacity >= minimum_capacity, "Replay capacity below ceil(RPS × 120 × 1.25) + burst")
    require(access.get("replay_max_entries_per_caller", 20000) < capacity, "Caller capacity must leave global space")
    resources = security["resource_limits"]
    require(resources.get("buffer_bytes_global", 536870912) >= resources.get("buffer_bytes_per_service", 67108864)
            >= resources.get("buffer_bytes_per_tunnel", 16777216), "Buffer budgets out of order")
    barrier = seconds(config["storage"]["replay"], "recovery_barrier", "120s")
    require(barrier >= 120, "Replay barrier below 120 seconds")
    require(seconds(deployment, "startup_grace", "180s") >= barrier, "Startup grace shorter than replay barrier")
    auth = config["auth"]
    require(seconds(auth, "certificate_max_lifetime", "24h") <= 86400, "Certificate lifetime exceeds 24h")
    require(seconds(auth, "grant_max_lifetime", "1h") <= 3600, "Grant lifetime exceeds one hour")


def check_bff_invariants(config):
    options = config["admin_web"]
    require(options["oidc"]["redirect_uri"] == options["public_origin"] + "/auth/callback",
            "BFF redirect does not match public origin and callback path")
    session = options["session"]
    idle = seconds(session, "idle_timeout", "15m")
    lifetime = seconds(session, "absolute_timeout", "8h")
    require(idle <= min(900, lifetime) and lifetime <= 28800, "BFF session lifetime exceeds bounds")
    require(seconds(session, "privileged_auth_max_age", "5m") <= 300, "BFF MFA age exceeds five minutes")


def postgres_examples(gateway, bff):
    requirements = (DOCS / "requirements.md").read_text(encoding="utf-8")
    section = requirements.split("### 6.4. Конфигурация PostgreSQL", 1)[1]
    postgres = parse(section.split("```yaml\n", 1)[1].split("\n```", 1)[0])
    mixed = deepcopy(gateway)
    mixed["storage"]["control"] = postgres["storage"]["control"]
    full = deepcopy(gateway)
    full["storage"] = postgres["storage"]
    full_bff = deepcopy(bff)
    full_bff["admin_web"]["session"] = postgres["admin_web"]["session"]
    return mixed, full, full_bff


def verify_admin_import(import_validator):
    openapi = yaml.safe_load((DOCS / "admin-openapi.yaml").read_text(encoding="utf-8"))
    candidate = openapi["components"]["schemas"]["ConfigCandidateYaml"]
    require(candidate["contentSchema"]["$ref"] == "config.schema.json#/$defs/importCandidate",
            "OpenAPI import schema points to a different contract")
    paths = openapi["paths"]
    apply = paths["/admin/config/import"]["post"]["requestBody"]["content"]["application/json"]["example"]
    preview = paths["/admin/changes/validate"]["post"]["requestBody"]["content"]["application/json"]["examples"]
    preview_value = preview["configImport"]["value"]
    for label, raw in (("config apply", apply["config_yaml"]),
                       ("config preview", preview_value["candidate"]["config_yaml"])):
        require(len(raw.encode("utf-8")) <= candidate["maxLength"], f"{label} exceeds UTF-8 limit")
        validate(import_validator, parse(raw), label)
    for field in ("scope_service_ids", "expected_revision"):
        require(apply[field] == preview_value[field], f"Import example differs from preview in {field}")
    require(parse(apply["config_yaml"]) == parse(preview_value["candidate"]["config_yaml"]),
            "Import example differs from preview payload")
    return 2


def rejected(label, run):
    try:
        run()
    except (ValueError, yaml.YAMLError):
        return
    raise ValueError(f"Accepted invalid configuration: {label}")


def verify_boundaries(gateway_validator, bff_validator, import_validator, dev, prod, pg, bff):
    redis = {
        "driver": "redis", "url": "rediss://redis.example.net:6379", "username": "gateway",
        "password_env": "OUTGATE_REDIS", "ca_file": "./redis.pem", "namespace": "outgate:gateway",
        "require_aof": True, "require_noeviction": True, "require_appendfsync": "always",
    }
    gateway_cases = [
        ("implicit production with development auth", {k: v for k, v in dev.items() if k != "deployment"}),
        ("unknown key", dev | {"unknown": True}),
        ("boolean string", dev | {"frontend_override": {"enabled": "yes"}}),
        ("disabled transports", dev | {"tunnel": dev["tunnel"] | {"quic": {"enabled": False}, "wss": {}}}),
        ("production HTTP upstream", prod | {"upstream": dev["upstream"]}),
        ("development public admin listener", dev | {"admin": dev["admin"] | {"addr": "0.0.0.0:9091"}}),
        ("bearer in production", prod | {"auth": dev["auth"]}),
        ("zero register timeout", dev | {"tunnel": dev["tunnel"] | {"register_timeout": "0s"}}),
        ("PostgreSQL with SQLite path", pg | {"storage": pg["storage"] | {
            "control": pg["storage"]["control"] | {"path": "control.db"},
        }}),
        ("PostgreSQL without verify-full", pg | {"storage": pg["storage"] | {
            "control": pg["storage"]["control"] | {"sslmode": "require"},
        }}),
        ("PostgreSQL with two password sources", pg | {"storage": pg["storage"] | {
            "control": pg["storage"]["control"] | {"password_file": "./secrets/pg-password"},
        }}),
        ("SQLite relaxed durability", prod | {"storage": prod["storage"] | {
            "replay": prod["storage"]["replay"] | {"synchronous": "NORMAL"},
        }}),
        ("insecure inline media", prod | {"security": prod["security"] | {
            "browser": prod["security"]["browser"] | {"api_inline_mime_types": ["text/html"]},
        }}),
        ("insecure Redis without always fsync", prod | {"storage": prod["storage"] | {
            "replay": redis | {"require_appendfsync": "everysec"},
        }}),
    ]
    validate(gateway_validator, prod | {"storage": prod["storage"] | {"replay": redis}}, "optional Redis shape")
    for label, value in gateway_cases:
        rejected(label, lambda: validate(gateway_validator, value, label))

    replay = prod["storage"]["replay"]
    for barrier in ("119s", "1m59s"):
        bad_barrier = prod | {"storage": prod["storage"] | {"replay": replay | {"recovery_barrier": barrier}}}
        validate(gateway_validator, bad_barrier, "barrier form")
        rejected("short replay barrier", lambda: check_gateway_invariants(bad_barrier))
    low_capacity = prod | {"interservice": prod["interservice"] | {"replay_cache_max_entries": 151999}}
    rejected("insufficient replay capacity", lambda: check_gateway_invariants(low_capacity))

    rejected("gateway as BFF", lambda: validate(bff_validator, prod, "gateway as BFF"))
    rejected("gateway section in BFF", lambda: validate(bff_validator, bff | {"admin": {}}, "BFF"))
    for fragment in (
        {}, {"admin": {"token": "example-only"}}, {"storage": {"replay": {"driver": "redis"}}},
        {"services": {"reports": {"stable_version": "1.0.0"}}},
        {"interservice": {"callers": {"reports": {"keys": []}}}},
    ):
        rejected("field outside Admin import", lambda: validate(import_validator, fragment, "import"))
    for source in ("paths: [/api]\npaths: [/other]", "services: {reports: {allowed_paths: [/api], allowed_paths: []}}",
                   "services: {123: {}}"):
        rejected("duplicate or non-string YAML key", lambda: parse(source))
    require(parse("version: 2026-11-21\nenabled: on\nnullvalue: null\ncount: 12") ==
            {"version": "2026-11-21", "enabled": "on", "nullvalue": None, "count": 12},
            "Unexpected implicit YAML scalar conversion")


def main():
    gateway_schema = json.loads((DOCS / "config.schema.json").read_text(encoding="utf-8"))
    bff_schema = json.loads((DOCS / "admin-web.schema.json").read_text(encoding="utf-8"))
    registry = Registry().with_resource(gateway_schema["$id"], Resource.from_contents(gateway_schema))
    for schema in (gateway_schema, bff_schema):
        Draft202012Validator.check_schema(schema)
    gateway = Draft202012Validator(gateway_schema, registry=registry, format_checker=Draft202012Validator.FORMAT_CHECKER)
    bff = gateway.evolve(schema=bff_schema)
    importer = gateway.evolve(schema={"$ref": gateway_schema["$id"] + "#/$defs/importCandidate"})

    def example(name):
        return parse((EXAMPLES / name).read_text(encoding="utf-8"))

    development = example("gateway.development.yaml")
    production = example("gateway.production.yaml")
    production_bff = example("admin-web.production.yaml")
    mixed, postgres, postgres_bff = postgres_examples(production, production_bff)
    # Omitting deployment must select production.
    default_production = {k: v for k, v in production.items() if k != "deployment"}
    gateway_examples = {
        "development": development, "production": production, "default production": default_production,
        "Windows SQLite": example("gateway.windows.yaml"), "PostgreSQL control only": mixed, "full PostgreSQL": postgres,
    }
    bff_examples = {
        "BFF SQLite": production_bff, "BFF Windows SQLite": example("admin-web.windows.yaml"),
        "BFF PostgreSQL": postgres_bff,
    }
    for label, config in gateway_examples.items():
        validate(gateway, config, label)
        check_gateway_invariants(config)
    for label, config in bff_examples.items():
        validate(bff, config, label)
        check_bff_invariants(config)
    imports = verify_admin_import(importer)
    verify_boundaries(gateway, bff, importer, development, production, postgres, production_bff)
    print(f"PASS: {len(gateway_examples)} gateway and {len(bff_examples)} BFF profiles, "
          f"{imports} Admin import examples and rejection cases.")


if __name__ == "__main__":
    main()
