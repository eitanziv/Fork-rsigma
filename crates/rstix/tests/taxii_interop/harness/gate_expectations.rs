//! Manifest-derived expectations for TXC self-certification report gating (Layer 2).
//!
//! `gate-expectations.json` is generated from `manifest.toml` and checked into
//! `tests/fixtures/taxii-interop/`. CI (`scripts/taxii-interop-report-gate.py`,
//! Layer 3) and the taxii_interop harness both use it so table/CSV content is
//! pinned, not only row counts.

use std::fs;

use serde::{Deserialize, Serialize};

use super::certification::{checklist_result_for_export, expected_csv_outcome};
use super::manifest::{Disposition, Manifest, RequirementRow};

const EXPECTATIONS_FILE: &str = "gate-expectations.json";
const TRACEABILITY_HEADER: &str = "req_id,section,test_case,verification,disposition,outcome";

/// One §4.1 Table 51 checklist row pinned for content gates.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChecklistExpectation {
    pub req_id: String,
    pub test_case: String,
    pub section: String,
    pub verification: String,
    pub disposition: String,
    pub expected_result: String,
}

/// One traceability CSV row pinned for content gates (outcome after a passing run).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceabilityExpectation {
    pub req_id: String,
    pub disposition: String,
    pub expected_outcome: String,
}

/// Full gate expectation bundle derived from `manifest.toml`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateExpectations {
    pub manifest_rows_total: usize,
    pub manifest_rows_by_disposition: DispositionCounts,
    pub traceability_header: String,
    pub checklist_row_count: usize,
    pub table_51: Vec<ChecklistExpectation>,
    pub traceability_rows: Vec<TraceabilityExpectation>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispositionCounts {
    pub tested: usize,
    pub report_only: usize,
}

pub fn expectations_path() -> std::path::PathBuf {
    super::manifest::fixtures_root().join(EXPECTATIONS_FILE)
}

/// Build expectations from the loaded manifest (single source of truth for semantics).
pub fn from_manifest(manifest: &Manifest) -> GateExpectations {
    let mut counts = DispositionCounts {
        tested: 0,
        report_only: 0,
    };
    for row in &manifest.requirements {
        match row.disposition {
            Disposition::Tested => counts.tested += 1,
            Disposition::ReportOnly => counts.report_only += 1,
        }
    }

    let table_51 = checklist_expectations(manifest.checklist_rows());
    let traceability_rows = manifest
        .requirements
        .iter()
        .map(|row| TraceabilityExpectation {
            req_id: row.req_id.clone(),
            disposition: row.disposition.as_str().to_owned(),
            expected_outcome: expected_csv_outcome(row.disposition),
        })
        .collect();

    GateExpectations {
        manifest_rows_total: manifest.requirements.len(),
        manifest_rows_by_disposition: counts,
        traceability_header: TRACEABILITY_HEADER.to_owned(),
        checklist_row_count: table_51.len(),
        table_51,
        traceability_rows,
    }
}

fn checklist_expectations(rows: Vec<&RequirementRow>) -> Vec<ChecklistExpectation> {
    rows.into_iter()
        .map(|row| ChecklistExpectation {
            req_id: row.req_id.clone(),
            test_case: row.test_case.clone(),
            section: row.section.clone(),
            verification: row.verification.clone(),
            disposition: row.disposition.as_str().to_owned(),
            expected_result: checklist_result_for_export(row),
        })
        .collect()
}

/// Committed expectations must match the manifest (regenerate when manifest changes).
pub fn assert_gate_expectations_file_current() {
    let manifest = super::manifest::load_manifest();
    let computed = from_manifest(&manifest);
    let path = expectations_path();
    let text =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    let committed: GateExpectations =
        serde_json::from_str(&text).unwrap_or_else(|err| panic!("parse {}: {err}", path.display()));
    assert_eq!(
        computed, committed,
        "gate-expectations.json is stale — regenerate with:\n  \
         python3 scripts/generate-taxii-interop-gate-expectations.py"
    );
}

/// Write `gate-expectations.json` when `RSTIX_WRITE_TAXII_GATE_EXPECTATIONS=1`.
pub fn maybe_write_gate_expectations_file(manifest: &Manifest) {
    if std::env::var("RSTIX_WRITE_TAXII_GATE_EXPECTATIONS").as_deref() != Ok("1") {
        return;
    }
    let path = expectations_path();
    let expectations = from_manifest(manifest);
    let json = serde_json::to_string_pretty(&expectations).expect("serialize gate expectations");
    fs::write(&path, format!("{json}\n")).expect("write gate expectations");
    eprintln!("wrote {}", path.display());
}
