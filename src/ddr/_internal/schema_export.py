"""Generate DDRRecord JSON Schema from Pydantic models and write to spec/."""

from __future__ import annotations

import json
from pathlib import Path

from ddr.models.record import DDRRecord

_SPEC_DIR = Path(__file__).parent.parent.parent.parent / "spec"
SCHEMA_PATH = _SPEC_DIR / "ddr-v0.3.schema.json"


def generate_schema() -> dict:
    return DDRRecord.model_json_schema()


def write_schema(output: Path | None = None) -> None:
    schema = generate_schema()
    target = output or SCHEMA_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(schema, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Export DDRRecord JSON Schema")
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()
    write_schema(args.output)
    print(f"Schema written to {args.output or SCHEMA_PATH}")


if __name__ == "__main__":
    main()
