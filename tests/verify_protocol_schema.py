"""Validate the control schema and structural protocol fixtures."""
import json
from collections import Counter
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/protocol/v1"


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def main():
    schema = read_json(ROOT / "docs/protocol.schema.json")
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(
        schema, format_checker=Draft202012Validator.FORMAT_CHECKER
    )
    cases = read_json(FIXTURES / "control-messages.json")
    declared = {branch["$ref"].removeprefix("#/$defs/") for branch in schema["oneOf"]}
    defined = {
        name for name, definition in schema["$defs"].items()
        if definition.get("properties", {}).get("type", {}).get("const") == name
    }
    covered = Counter(message["type"] for message in cases["positive"])
    if declared != defined or len(schema["oneOf"]) != len(declared) or covered != Counter(declared):
        raise ValueError("The control union, message definitions and fixtures must cover the same types once")

    for message in cases["positive"]:
        validator.validate(message)
    bootstrap = read_json(FIXTURES / "quic-bootstrap.json")
    validator.validate(bootstrap["register"])
    for case in cases["negative"]:
        if validator.is_valid(case["message"]):
            raise ValueError(f"Accepted invalid control fixture {case['name']}")
    fences = read_json(FIXTURES / "quic-quiescent-fence.json")
    for case in fences["positive"]:
        validator.validate(case["message"])
    for case in fences["negative"]:
        message = {"type": "drain_ack", "command_id": "7", "extensions": case["extensions"]}
        if validator.is_valid(message) != case["schema_valid"]:
            raise ValueError(f"Fence schema mismatch: {case['name']}")

    print(f"PASS: Draft 2020-12 control schema, {len(covered)} positive types, "
          f"QUIC register and {len(cases['negative'])} negative fixtures")


if __name__ == "__main__":
    main()
