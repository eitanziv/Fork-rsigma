#!/usr/bin/env python3
"""Gate on rstix TAXII 2.1 TXC self-certification report artifacts (Table 51).

Used by CI (and locally after ``cargo test -p rstix --test taxii_interop``) to ensure
``target/taxii-interop-report/`` was produced by this run and that every ``TESTED``
manifest row recorded ``Pass``. That report package is the operational TXC
self-certification evidence against Interoperability CSD01.

Layer 3 (this script): parse Table 51 and ``traceability.csv`` against committed
``gate-expectations.json`` (manifest-derived golden expectations).

Environment:

- ``TAXII_INTEROP_RUN_START`` — required UTC RFC 3339 timestamp taken before the
  suite ran. ``summary.json`` ``generated_at`` must be >= this value so a stale
  report from a previous run cannot satisfy the gate.

Exits 0 on success, 1 on failure. Stdlib only.
"""

from __future__ import annotations

import csv
import json
import os
import sys
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
REPORT_DIR = REPO_ROOT / "target/taxii-interop-report"
EXPECTATIONS_PATH = (
    REPO_ROOT / "crates/rstix/tests/fixtures/taxii-interop/gate-expectations.json"
)
REQUIRED_ARTIFACTS = (
    "summary.json",
    "traceability.csv",
    "txc-table-51.md",
    "risks.md",
)
TABLE_HEADER = ["Test Case", "Section", "Verification", "Result"]


def parse_rfc3339(value: str) -> datetime:
    normalized = value.strip().replace("Z", "+00:00")
    dt = datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def fail(message: str) -> None:
    print(f"taxii-interop-report-gate: {message}", file=sys.stderr)
    sys.exit(1)


def require_int(data: dict[str, object], key: str) -> int:
    value = data.get(key)
    if not isinstance(value, int):
        fail(f"summary.json field {key!r} must be an integer, got {value!r}")
    return value


def require_non_empty_file(path: Path) -> None:
    try:
        size = path.stat().st_size
    except OSError as err:
        fail(f"cannot stat artifact {path}: {err}")
    if size <= 0:
        fail(f"artifact is empty: {path}")


def load_expectations() -> dict[str, object]:
    if not EXPECTATIONS_PATH.is_file():
        fail(
            f"missing expectations file {EXPECTATIONS_PATH} "
            "(run scripts/generate-taxii-interop-gate-expectations.py)"
        )
    try:
        data = json.loads(EXPECTATIONS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as err:
        fail(f"cannot read {EXPECTATIONS_PATH}: {err}")
    if not isinstance(data, dict):
        fail(f"{EXPECTATIONS_PATH} must be a JSON object")
    return data


def parse_markdown_table(path: Path) -> list[dict[str, str]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as err:
        fail(f"cannot read table artifact {path}: {err}")

    table_lines = [line for line in lines if line.startswith("|")]
    body_lines = [line for line in table_lines if not line.startswith("|---")]
    if len(body_lines) < 2:
        fail(f"table artifact has no header/body rows: {path}")

    header = [cell.strip() for cell in body_lines[0].strip("|").split("|")]
    if header != TABLE_HEADER:
        fail(f"{path.name} header mismatch: expected {TABLE_HEADER}, got {header}")

    rows: list[dict[str, str]] = []
    for line in body_lines[1:]:
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if len(cells) != len(TABLE_HEADER):
            fail(f"{path.name} row has {len(cells)} cells, expected {len(TABLE_HEADER)}: {line}")
        row = dict(zip(TABLE_HEADER, cells, strict=True))
        rows.append(row)
    return rows


def checklist_key(row: dict[str, str]) -> tuple[str, str, str]:
    return (row["Test Case"], row["Section"], row["Verification"])


def validate_checklist_table(
    path: Path,
    expected_rows: list[dict[str, object]],
    label: str,
) -> None:
    actual_rows = parse_markdown_table(path)
    if len(actual_rows) != len(expected_rows):
        fail(
            f"{label} {path.name} has {len(actual_rows)} body rows, "
            f"expected {len(expected_rows)}"
        )

    expected_by_key = {
        (
            str(row["test_case"]),
            str(row["section"]),
            str(row["verification"]),
        ): row
        for row in expected_rows
    }
    seen_keys: set[tuple[str, str, str]] = set()
    for actual in actual_rows:
        key = checklist_key(actual)
        if key in seen_keys:
            fail(f"{path.name} duplicate checklist row: {key}")
        seen_keys.add(key)

        expected = expected_by_key.get(key)
        if expected is None:
            fail(f"{path.name} unexpected checklist row: {key}")

        result = actual["Result"]
        expected_result = str(expected["expected_result"])
        if not result:
            fail(f"{path.name} empty Result for {key}")
        if result != expected_result:
            fail(
                f"{path.name} Result mismatch for {key}: "
                f"got {result!r}, expected {expected_result!r}"
            )

    missing = set(expected_by_key.keys()) - seen_keys
    if missing:
        fail(f"{path.name} missing checklist rows: {sorted(missing)}")


def validate_traceability_csv(
    path: Path,
    expectations: dict[str, object],
) -> None:
    expected_header = expectations.get("traceability_header")
    if not isinstance(expected_header, str):
        fail("gate-expectations.json missing traceability_header string")

    expected_rows = expectations.get("traceability_rows")
    if not isinstance(expected_rows, list):
        fail("gate-expectations.json missing traceability_rows array")

    try:
        text = path.read_text(encoding="utf-8")
    except OSError as err:
        fail(f"cannot read {path}: {err}")

    reader = csv.reader(StringIO(text))
    try:
        header = next(reader)
    except StopIteration:
        fail(f"{path.name} is empty")

    if header != expected_header.split(","):
        fail(
            f"{path.name} header mismatch: expected {expected_header.split(',')}, got {header}"
        )

    actual_rows: list[dict[str, str]] = []
    for row in reader:
        if not row:
            continue
        if len(row) != 6:
            fail(f"{path.name} row has {len(row)} columns, expected 6: {row}")
        actual_rows.append(
            {
                "req_id": row[0],
                "disposition": row[4],
                "outcome": row[5],
            }
        )

    if len(actual_rows) != len(expected_rows):
        fail(
            f"{path.name} has {len(actual_rows)} data rows, expected {len(expected_rows)}"
        )

    seen_req_ids: set[str] = set()
    for index, (actual, expected_raw) in enumerate(zip(actual_rows, expected_rows, strict=True)):
        if not isinstance(expected_raw, dict):
            fail(f"gate-expectations.json traceability_rows[{index}] must be an object")

        req_id = expected_raw.get("req_id")
        expected_disposition = expected_raw.get("disposition")
        expected_outcome = expected_raw.get("expected_outcome")
        if not isinstance(req_id, str):
            fail(f"gate-expectations.json traceability_rows[{index}] missing req_id")
        if not isinstance(expected_disposition, str):
            fail(
                f"gate-expectations.json traceability_rows[{index}] missing disposition"
            )
        if not isinstance(expected_outcome, str):
            fail(f"gate-expectations.json traceability_rows[{index}] missing expected_outcome")

        if req_id in seen_req_ids:
            fail(f"{path.name} duplicate req_id: {req_id}")
        seen_req_ids.add(req_id)

        if actual["req_id"] != req_id:
            fail(
                f"{path.name} row order mismatch at index {index}: "
                f"got req_id={actual['req_id']!r}, expected {req_id!r}"
            )
        if actual["disposition"] != expected_disposition:
            fail(
                f"{path.name} disposition mismatch for {req_id}: "
                f"got {actual['disposition']!r}, expected {expected_disposition!r}"
            )
        if actual["outcome"] == "MISSING":
            fail(f"{path.name} outcome MISSING for {req_id}")
        if actual["outcome"] != expected_outcome:
            fail(
                f"{path.name} outcome mismatch for {req_id}: "
                f"got {actual['outcome']!r}, expected {expected_outcome!r}"
            )


def validate_summary(
    summary: dict[str, object],
    expectations: dict[str, object],
) -> tuple[int, int, str]:
    expected_total = expectations.get("manifest_rows_total")
    if not isinstance(expected_total, int):
        fail("gate-expectations.json manifest_rows_total must be an integer")

    expected_by = expectations.get("manifest_rows_by_disposition")
    if not isinstance(expected_by, dict):
        fail("gate-expectations.json missing manifest_rows_by_disposition object")

    generated_raw = summary.get("generated_at")
    if not isinstance(generated_raw, str) or not generated_raw:
        fail("summary.json missing string field generated_at")

    by = summary.get("manifest_rows_by_disposition")
    if not isinstance(by, dict):
        fail("summary.json missing manifest_rows_by_disposition object")

    tested = require_int(by, "tested")
    report_only = require_int(by, "report_only")
    tested_passed = require_int(summary, "tested_rows_passed")
    manifest_rows_total = require_int(summary, "manifest_rows_total")
    features = summary.get("features_enabled")

    expected_tested = expected_by.get("tested")
    expected_report_only = expected_by.get("report_only")
    for name, value in (("tested", expected_tested), ("report_only", expected_report_only)):
        if not isinstance(value, int):
            fail(f"gate-expectations.json manifest_rows_by_disposition.{name} must be int")

    if manifest_rows_total != expected_total:
        fail(
            "manifest_rows_total mismatch: "
            f"summary={manifest_rows_total} expectations={expected_total}"
        )
    if tested != expected_tested:
        fail(f"tested count mismatch: summary={tested} expectations={expected_tested}")
    if report_only != expected_report_only:
        fail(
            f"report_only count mismatch: summary={report_only} "
            f"expectations={expected_report_only}"
        )
    if tested_passed != tested:
        fail(f"TESTED rows not fully passed: tested_rows_passed={tested_passed} tested={tested}")
    if not isinstance(features, dict) or features.get("taxii") is not True:
        fail(f"features_enabled.taxii must be true, got {features!r}")

    return tested_passed, report_only, generated_raw


def main() -> None:
    start_raw = os.environ.get("TAXII_INTEROP_RUN_START")
    if not start_raw:
        fail("TAXII_INTEROP_RUN_START is required (UTC RFC 3339 from before the suite ran)")

    try:
        run_start = parse_rfc3339(start_raw)
    except ValueError as err:
        fail(f"TAXII_INTEROP_RUN_START is not RFC 3339: {start_raw!r} ({err})")

    expectations = load_expectations()

    if not REPORT_DIR.is_dir():
        fail(f"missing report directory {REPORT_DIR}")

    for name in REQUIRED_ARTIFACTS:
        path = REPORT_DIR / name
        if not path.is_file():
            fail(f"missing required artifact {path}")
        require_non_empty_file(path)

    table_51 = expectations.get("table_51")
    if not isinstance(table_51, list):
        fail("gate-expectations.json missing table_51 array")

    validate_checklist_table(
        REPORT_DIR / "txc-table-51.md",
        table_51,
        "Table 51",
    )
    validate_traceability_csv(REPORT_DIR / "traceability.csv", expectations)

    summary_path = REPORT_DIR / "summary.json"
    try:
        summary_obj = json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as err:
        fail(f"cannot read {summary_path}: {err}")
    if not isinstance(summary_obj, dict):
        fail(f"{summary_path} must be a JSON object")

    tested_passed, report_only, generated_raw = validate_summary(summary_obj, expectations)

    try:
        generated_at = parse_rfc3339(generated_raw)
    except ValueError as err:
        fail(f"summary.json generated_at is not RFC 3339: {generated_raw!r} ({err})")

    if generated_at < run_start:
        fail(
            "summary.json is stale: "
            f"generated_at={generated_raw} < TAXII_INTEROP_RUN_START={start_raw}"
        )

    print(
        "taxii-interop-report-gate ok: "
        f"generated_at={generated_raw} "
        f"tested_passed={tested_passed} "
        f"report_only={report_only} "
        f"table_rows={len(table_51)} "
        f"csv_rows={expectations.get('manifest_rows_total')}"
    )


if __name__ == "__main__":
    main()
