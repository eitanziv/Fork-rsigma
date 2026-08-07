#!/usr/bin/env python3
"""Generate ``gate-expectations.json`` from ``manifest.toml``.

Run from the repository root when the TAXII interop manifest changes:

    python3 scripts/generate-taxii-interop-gate-expectations.py

The committed JSON is checked by the taxii_interop harness (Layer 2) and
``scripts/taxii-interop-report-gate.py`` (Layer 3). Semantics mirror
``crates/rstix/tests/taxii_interop/harness/gate_expectations.rs``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    print(
        "generate-taxii-interop-gate-expectations: Python 3.11+ required (tomllib)",
        file=sys.stderr,
    )
    sys.exit(1)


REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST = REPO_ROOT / "crates/rstix/tests/fixtures/taxii-interop/manifest.toml"
OUTPUT = REPO_ROOT / "crates/rstix/tests/fixtures/taxii-interop/gate-expectations.json"
TRACEABILITY_HEADER = "req_id,section,test_case,verification,disposition,outcome"
CHECKLIST_ROW_COUNT = 44


def checklist_result_for_export(row: dict[str, object]) -> str:
    disposition = row.get("disposition", "TESTED")
    if disposition == "REPORT_ONLY":
        return "Pending (optional additional filters)"
    return "Pass"


def expected_csv_outcome(disposition: str) -> str:
    return {"TESTED": "Pass", "REPORT_ONLY": "REPORT_ONLY"}[disposition]


def checklist_rows(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    filtered = [row for row in rows if row.get("checklist_row")]
    filtered.sort(key=lambda row: row["section"])
    return filtered


def checklist_expectations(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    return [
        {
            "req_id": row["req_id"],
            "test_case": row["test_case"],
            "section": row["section"],
            "verification": row["verification"],
            "disposition": row.get("disposition", "TESTED"),
            "expected_result": checklist_result_for_export(row),
        }
        for row in rows
    ]


def disposition_counts(rows: list[dict[str, object]]) -> dict[str, int]:
    counts = {"tested": 0, "report_only": 0}
    mapping = {"TESTED": "tested", "REPORT_ONLY": "report_only"}
    for row in rows:
        key = mapping[row.get("disposition", "TESTED")]
        counts[key] += 1
    return counts


def main() -> None:
    if not MANIFEST.is_file():
        print(
            f"generate-taxii-interop-gate-expectations: missing {MANIFEST}",
            file=sys.stderr,
        )
        sys.exit(1)

    rows: list[dict[str, object]] = tomllib.loads(MANIFEST.read_text(encoding="utf-8"))[
        "requirement"
    ]
    table_51 = checklist_expectations(checklist_rows(rows))

    if len(table_51) != CHECKLIST_ROW_COUNT:
        print(
            "generate-taxii-interop-gate-expectations: expected "
            f"{CHECKLIST_ROW_COUNT} checklist rows, got {len(table_51)}",
            file=sys.stderr,
        )
        sys.exit(1)

    expectations = {
        "manifest_rows_total": len(rows),
        "manifest_rows_by_disposition": disposition_counts(rows),
        "traceability_header": TRACEABILITY_HEADER,
        "checklist_row_count": CHECKLIST_ROW_COUNT,
        "table_51": table_51,
        "traceability_rows": [
            {
                "req_id": row["req_id"],
                "disposition": row.get("disposition", "TESTED"),
                "expected_outcome": expected_csv_outcome(row.get("disposition", "TESTED")),
            }
            for row in rows
        ],
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(expectations, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUTPUT}")


if __name__ == "__main__":
    main()
