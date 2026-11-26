"""Validate the normative discovery schema and fixture semantics offline."""
import importlib.util
import json
from pathlib import Path
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
schema = json.loads((DOCS / "discovery.schema.json").read_text(encoding="utf-8"))
Draft202012Validator.check_schema(schema)
resources = []
for name in ["discovery.schema.json", "protocol.schema.json"]:
    data = json.loads((DOCS / name).read_text(encoding="utf-8"))
    resources.append((data["$id"], Resource.from_contents(data)))
validator = Draft202012Validator(schema, registry=Registry().with_resources(resources))
fixture_dir = ROOT / "tests/fixtures/discovery/v1"
spec = importlib.util.spec_from_file_location("discovery_vectors", fixture_dir / "verify.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.main()
fixtures = json.loads((fixture_dir / "responses.json").read_text(encoding="utf-8"))
for response in fixtures["positive"]:
    validator.validate(response)
print("PASS: discovery Draft 2020-12 schema and positive fixtures")
