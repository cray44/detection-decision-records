"""CI tool: fail if regenerated JSON Schema differs from the checked-in copy."""

from __future__ import annotations

import json
import sys

from ddr._internal.schema_export import SCHEMA_PATH, generate_schema


def main() -> None:
    if not SCHEMA_PATH.exists():
        print(f"ERROR: {SCHEMA_PATH} not found.", file=sys.stderr)
        print("Run: python -m ddr._internal.schema_export", file=sys.stderr)
        sys.exit(1)

    current = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    regenerated = generate_schema()

    if current != regenerated:
        print("SCHEMA DRIFT DETECTED.", file=sys.stderr)
        print("Regenerate with: python -m ddr._internal.schema_export", file=sys.stderr)
        sys.exit(1)

    print("Schema is up to date.")


if __name__ == "__main__":
    main()
