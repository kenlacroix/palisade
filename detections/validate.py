#!/usr/bin/env python3
"""Validate every detection YAML in this directory against detection.schema.json.

Prints a PASS/FAIL line per file and exits nonzero if any file fails.
"""
import json
import sys
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

HERE = Path(__file__).resolve().parent
SCHEMA_PATH = HERE / "detection.schema.json"


def main() -> int:
    schema = json.loads(SCHEMA_PATH.read_text())
    validator = Draft202012Validator(schema)

    yaml_files = sorted(HERE.glob("*.yaml")) + sorted(HERE.glob("*.yml"))
    if not yaml_files:
        print("FAIL: no detection YAML files found", file=sys.stderr)
        return 1

    ok = True
    for path in yaml_files:
        try:
            doc = yaml.safe_load(path.read_text())
        except yaml.YAMLError as exc:
            print(f"FAIL {path.name}: YAML parse error: {exc}")
            ok = False
            continue

        errors = sorted(validator.iter_errors(doc), key=lambda e: e.path)
        if errors:
            ok = False
            print(f"FAIL {path.name}")
            for err in errors:
                loc = "/".join(str(p) for p in err.path) or "<root>"
                print(f"  - {loc}: {err.message}")
        else:
            print(f"PASS {path.name}")

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
