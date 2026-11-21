#!/usr/bin/env python3
"""Check the Admin API contract and its examples without running a gateway."""
import json
import re
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator
from openapi_spec_validator import validate
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]
API = ROOT / "docs/admin-openapi.yaml"
METHODS = {"get", "post", "put", "delete", "patch", "head", "options", "trace"}
EXPLICIT_ENDPOINT = re.compile(
    r"`(GET|POST|PUT|DELETE) (/admin/[a-z0-9_/{}/-]+)`"
)


class UniqueKeyLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        seen = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in seen:
                raise ValueError(f"Duplicate YAML key {key!r} on line {key_node.start_mark.line + 1}")
            seen.add(key)
        return super().construct_mapping(node, deep=deep)


def check(condition, message):
    if not condition:
        raise ValueError(message)


def resolve(document, value):
    if "$ref" not in value:
        return value
    parts = value["$ref"].split("/")
    check(parts[0] == "#", f"Expected a local reference: {value['$ref']}")
    for part in parts[1:]:
        document = document[part]
    return document


def value_validator(document):
    grant_file = API.with_name("deployment-grant.schema.json")
    grant_schema = json.loads(grant_file.read_text(encoding="utf-8"))
    registry = Registry().with_resource(grant_file.as_uri(), Resource.from_contents(grant_schema))

    def validator(schema):
        # Preserve component pointers and resolve sibling schemas without network access.
        return Draft202012Validator(
            {"$id": API.as_uri(), "allOf": [schema], "components": document["components"]},
            registry=registry,
            format_checker=Draft202012Validator.FORMAT_CHECKER,
        )

    return validator


def verify_examples(media, validator, label):
    examples = [media["example"]] if "example" in media else [
        example["value"] for example in media.get("examples", {}).values()
    ]
    check(examples, f"{label} is missing an example")
    for example in examples:
        errors = list(validator(media["schema"]).iter_errors(example))
        check(not errors, f"{label}: {errors[0].json_path} {errors[0].message}" if errors else "")
    return len(examples)


def verify_operations(document, validator):
    explicit = {
        (method.lower(), path.replace("{id}", "{service_id}"))
        for method, path in EXPLICIT_ENDPOINT.findall(
            (ROOT / "docs/requirements.md").read_text(encoding="utf-8")
        )
    }
    operations = {
        (method, path): operation
        for path, item in document["paths"].items()
        for method, operation in item.items()
        if method in METHODS
    }
    check(explicit <= operations.keys(), f"Missing requirements endpoints: {explicit - operations.keys()}")
    count = 0
    for (method, path), operation in operations.items():
        label = f"{method.upper()} {path}"
        parameters = {
            parameter["name"]: parameter
            for ref in operation["parameters"]
            for parameter in [resolve(document, ref)]
        }
        version = parameters.get("X-Outgate-Admin-API-Version", {})
        check(version.get("required") and version["schema"].get("const") == "1", f"{label} version")
        check(operation["x-outgate-scope"], f"{label} scope")
        security = operation.get("security", document["security"])
        for profile in security:
            check(
                profile == {"DevelopmentAdminToken": []}
                or ("AdminMTLS" in profile and len({"CLIAdminToken", "BFFAdminJWT"} & profile.keys()) == 1),
                f"{label} credentials",
            )
        if operation["x-outgate-role"] == "security_admin":
            check(all("CLIAdminAssertion" in profile or "BFFAdminJWT" in profile for profile in security),
                  f"{label} MFA")
        if operation["operationId"] == "issueDeploymentGrant":
            check(security == [{"AdminMTLS": [], "CLIAdminToken": []}], f"{label} secret delivery profile")
        if operation["x-outgate-mutating"]:
            check(parameters.get("Idempotency-Key", {}).get("required"), f"{label} operation key")
            for name in ("If-Match", "X-Outgate-Change-Reason"):
                check(parameters[name]["required"] == ("requestBody" not in operation), f"{label} {name}")
            if "requestBody" in operation:
                body = operation["requestBody"]["content"]["application/json"]
                schema = resolve(document, body["schema"])
                check({"expected_revision", "reason"} <= set(schema["required"]), f"{label} change fields")
                check(schema.get("additionalProperties", schema.get("unevaluatedProperties")) is False,
                      f"{label} unknown request fields")
        if "requestBody" in operation:
            count += verify_examples(operation["requestBody"]["content"]["application/json"], validator, label)
        for status, ref in operation["responses"].items():
            response = resolve(document, ref)
            if status == "200":
                count += verify_examples(response["content"]["application/json"], validator, label)
            else:
                problem = response["content"]["application/problem+json"]
                schema = problem["schema"]["allOf"][1]
                check(schema["properties"]["status"]["const"] == int(status), f"{label} error status")
    return len(operations), count


def verify_rejections(document, validator):
    def schema(name):
        return document["components"]["schemas"][name]

    def accepts(name, value):
        return validator(schema(name)).is_valid(value)

    for value in ("0", "1", "18446744073709551615"):
        check(accepts("Revision", value), f"Rejects valid revision {value}")
    for value in (1, "01", "-1", "1.0", "1\n", "18446744073709551616", "100000000000000000000"):
        check(not accepts("Revision", value), f"Accepts invalid revision {value!r}")
    for value in (" \t ", "\x00", "release\n", "release\x7f"):
        check(not accepts("Version", value), f"Accepts invalid build ID {value!r}")

    for value in ("/", "/api/reports/", "/отчёты"):
        check(accepts("Prefix", value), f"Rejects valid route prefix {value}")
    for value in ("/..", "/./api", "/api/..", "/api/./x", "/api//", "//api", "/%2e", "/a\\b"):
        check(not accepts("Prefix", value), f"Accepts invalid route prefix {value}")
    for value in ("*", "G ET", "x\n"):
        check(not accepts("Method", value), f"Accepts invalid policy method {value!r}")
    check(not accepts("ServiceScope", ["*", "reports"]), "Accepts mixed global and scoped IDs")

    rollout = {"stable_version": "1.0", "canary_version": None, "canary_percent": 0,
               "expected_revision": "7", "reason": "deploy"}
    check(accepts("RolloutUpdate", rollout), "Rejects valid zero-percent rollout")
    for fields in ({"canary_percent": 1}, {"canary_percent": 101}, {"extra": True}, {"reason": ""}):
        check(not accepts("RolloutUpdate", rollout | fields), f"Accepts invalid rollout {fields}")

    paths = document["paths"]
    for name in ("RouteRelease", "RouteRetirement"):
        check(not accepts(name, {
            "service_id": "reports", "path": "/", "expected_revision": "7", "reason": "retire",
            **({"scope_service_ids": ["reports"], "preview_id": "preview"} if name == "RouteRelease" else {}),
        }), f"{name} accepts the frontend root")

    first, repeat = (
        paths["/admin/deployment-grants"]["post"]["responses"]["200"]
        ["content"]["application/json"]["examples"][name]["value"]
        for name in ("first", "repeat")
    )
    operation_result = (
        paths["/admin/operations/{operation_id}"]["get"]["responses"]["200"]
        ["content"]["application/json"]["example"]
    )
    grant_result = operation_result | {"operation": "issueDeploymentGrant"}
    check(accepts("OperationResult", grant_result | {"result": repeat}), "Rejects safe grant lookup")
    check(not accepts("OperationResult", grant_result | {"result": first}), "Grant lookup accepts a secret")
    check(not accepts("GrantResponse", repeat | {"deployment_grant": first["deployment_grant"]}),
          "Repeated grant response accepts a secret")
    check(not accepts("GrantSummary", first | {"state": "active"}), "Grant list accepts a secret")

    try:
        yaml.load("schema: first\nschema: second\n", Loader=UniqueKeyLoader)
    except ValueError:
        pass
    else:
        raise ValueError("Duplicate YAML key accepted")


def main():
    document = yaml.load(API.read_text(encoding="utf-8"), Loader=UniqueKeyLoader)
    validate(document, base_uri=API.as_uri())
    validator = value_validator(document)
    operations, count = verify_operations(document, validator)
    for label, response in document["components"]["responses"].items():
        count += verify_examples(response["content"]["application/problem+json"], validator, label)
    verify_rejections(document, validator)
    print(f"PASS: OpenAPI 3.1, {operations} Admin API operations, {count} examples and rejection cases.")


if __name__ == "__main__":
    main()
