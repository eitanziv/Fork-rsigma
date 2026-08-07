//! TXC certification outcomes and §4.1 Table 51 report generation.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use super::manifest::{Disposition, Manifest, RequirementRow};

static OUTCOMES: OnceLock<Mutex<HashMap<&'static str, Outcome>>> = OnceLock::new();

fn outcomes() -> &'static Mutex<HashMap<&'static str, Outcome>> {
    OUTCOMES.get_or_init(|| Mutex::new(HashMap::new()))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Pass,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "Pass",
        }
    }
}

pub fn record_outcome(req_id: &'static str, outcome: Outcome) {
    outcomes()
        .lock()
        .expect("txc outcomes lock")
        .insert(req_id, outcome);
}

fn report_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/taxii-interop-report")
}

pub fn finalize(manifest: &Manifest) {
    verify_registry_drift(manifest);
    verify_coverage(manifest);
    let recorded = outcomes().lock().expect("txc outcomes lock");
    verify_export_invariants(manifest, &recorded);
    drop(recorded);
    write_report_artifacts(manifest);
}

/// Checklist `Result` cell for a manifest row after a fully passing TXC run.
pub fn checklist_result_for_export(row: &RequirementRow) -> String {
    match row.disposition {
        Disposition::ReportOnly => "Pending (optional additional filters)".to_owned(),
        Disposition::Tested => "Pass".to_owned(),
    }
}

/// Expected traceability CSV `outcome` column after a fully passing TXC run.
pub fn expected_csv_outcome(disposition: Disposition) -> String {
    match disposition {
        Disposition::Tested => Outcome::Pass.as_str().to_owned(),
        Disposition::ReportOnly => "REPORT_ONLY".to_owned(),
    }
}

fn verify_export_invariants(manifest: &Manifest, recorded: &HashMap<&'static str, Outcome>) {
    let expectations = super::gate_expectations::from_manifest(manifest);
    assert_eq!(
        expectations.checklist_row_count, 44,
        "§4.1 Table 51 must have 44 checklist rows"
    );

    let checklist = manifest.checklist_rows();
    assert_eq!(
        checklist.len(),
        expectations.checklist_row_count,
        "Table 51 row count mismatch"
    );

    for row in checklist {
        let result = checklist_result(row, recorded);
        assert_exportable_checklist_result(row, &result);
        assert_eq!(
            result,
            checklist_result_for_export(row),
            "{}: checklist Result must match export contract",
            row.req_id
        );
    }

    let csv_lines = render_traceability_csv(manifest, recorded).lines().count();
    assert_eq!(
        csv_lines,
        manifest.requirements.len() + 1,
        "traceability.csv must have one row per manifest requirement plus header"
    );

    for row in &manifest.requirements {
        let expected_outcome = expected_csv_outcome(row.disposition);
        match row.disposition {
            Disposition::Tested => {
                assert_eq!(
                    recorded.get(row.req_id.as_str()),
                    Some(&Outcome::Pass),
                    "{}: TESTED row must record Pass before export",
                    row.req_id
                );
                assert_eq!(expected_outcome, "Pass");
            }
            Disposition::ReportOnly => {
                assert_eq!(expected_outcome, "REPORT_ONLY");
            }
        }
    }
}

fn assert_exportable_checklist_result(row: &RequirementRow, result: &str) {
    assert!(
        !result.is_empty(),
        "{}: checklist Result must not be empty",
        row.req_id
    );
    match row.disposition {
        Disposition::ReportOnly => {
            assert_eq!(result, "Pending (optional additional filters)");
        }
        Disposition::Tested => {
            assert_eq!(
                result, "Pass",
                "{}: TESTED row must export Pass",
                row.req_id
            );
        }
    }
}

fn checklist_result(row: &RequirementRow, recorded: &HashMap<&'static str, Outcome>) -> String {
    match row.disposition {
        Disposition::ReportOnly => "Pending (optional additional filters)".to_owned(),
        Disposition::Tested => match recorded.get(row.req_id.as_str()) {
            Some(Outcome::Pass) => "Pass".to_owned(),
            None => "Pending".to_owned(),
        },
    }
}

fn verify_registry_drift(manifest: &Manifest) {
    let registered: std::collections::HashSet<&str> = super::registry::all_tests()
        .iter()
        .map(|e| e.descriptor.test_id)
        .collect();
    let manifest_ids: std::collections::HashSet<&str> = manifest
        .tested_requirements()
        .filter_map(|r| r.test_id.as_deref())
        .collect();
    let missing: Vec<_> = manifest_ids.difference(&registered).copied().collect();
    assert!(
        missing.is_empty(),
        "manifest TESTED rows without registered scenarios: {missing:?}"
    );
    let orphan: Vec<_> = registered.difference(&manifest_ids).copied().collect();
    assert!(
        orphan.is_empty(),
        "registered scenarios without manifest rows: {orphan:?}"
    );
}

fn verify_coverage(manifest: &Manifest) {
    let recorded = outcomes().lock().expect("txc outcomes lock");
    let missing: Vec<_> = manifest
        .tested_requirements()
        .filter(|row| !recorded.contains_key(row.req_id.as_str()))
        .map(|row| row.req_id.clone())
        .collect();
    assert!(
        missing.is_empty(),
        "TESTED TXC rows without Pass outcomes: {missing:?}"
    );
}

fn write_report_artifacts(manifest: &Manifest) {
    let dir = report_dir();
    fs::create_dir_all(&dir).expect("create taxii-interop-report");
    let recorded = outcomes().lock().expect("txc outcomes lock");

    let tested = manifest.tested_requirements().count();
    let report_only = manifest
        .requirements
        .iter()
        .filter(|r| r.disposition == Disposition::ReportOnly)
        .count();
    let tested_passed = manifest
        .tested_requirements()
        .filter(|row| recorded.get(row.req_id.as_str()) == Some(&Outcome::Pass))
        .count();
    let generated_at = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .expect("rfc3339");

    let summary = serde_json::json!({
        "document": "TAXII 2.1 Interoperability Test Document Version 1.0 CSD01",
        "document_stage": "Committee Specification Draft 01 (2022-03-30)",
        "generated_at": generated_at,
        "personas_target": ["TXC"],
        "checklist": "§4.1 Table 51",
        "manifest_rows_total": manifest.requirements.len(),
        "manifest_rows_by_disposition": {
            "tested": tested,
            "report_only": report_only,
        },
        "tested_rows_passed": tested_passed,
        "report_only_rows": report_only,
        "checklist_rows": 44,
        "mandatory_rows": 39,
        "optional_rows": 5,
        "features_enabled": { "taxii": true },
        "not_claimed": [
            "TXS (TAXII Server persona)",
            "OASIS-issued certificate",
            "TAXII Channels (§6 RESERVED)"
        ]
    });
    fs::write(
        dir.join("summary.json"),
        serde_json::to_string_pretty(&summary).expect("summary"),
    )
    .expect("write summary.json");

    fs::write(
        dir.join("traceability.csv"),
        render_traceability_csv(manifest, &recorded),
    )
    .expect("write traceability.csv");

    let checklist = manifest.checklist_rows();
    fs::write(
        dir.join("txc-table-51.md"),
        render_checklist_table(&checklist, &recorded),
    )
    .expect("write txc-table-51.md");

    fs::write(dir.join("risks.md"), render_risks(manifest)).expect("write risks.md");
}

fn render_traceability_csv(
    manifest: &Manifest,
    recorded: &HashMap<&'static str, Outcome>,
) -> String {
    let mut lines = vec!["req_id,section,test_case,verification,disposition,outcome".to_owned()];
    for row in &manifest.requirements {
        let outcome = match row.disposition {
            Disposition::Tested => recorded
                .get(row.req_id.as_str())
                .map(|o| o.as_str())
                .unwrap_or("MISSING"),
            Disposition::ReportOnly => "REPORT_ONLY",
        };
        lines.push(format!(
            "{},{},{},{},{},{}",
            row.req_id,
            row.section,
            csv_escape(&row.test_case),
            row.verification,
            row.disposition.as_str(),
            outcome
        ));
    }
    lines.join("\n")
}

fn csv_escape(value: &str) -> String {
    if value.contains(',') || value.contains('"') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_owned()
    }
}

fn render_checklist_table(
    rows: &[&RequirementRow],
    recorded: &HashMap<&'static str, Outcome>,
) -> String {
    let mut out = String::from("# TAXII 2.1 Client (TXC) — §4.1 Table 51\n\n");
    out.push_str("| Test Case | Section | Verification | Result |\n");
    out.push_str("|---|---|---|---|\n");
    for row in rows {
        let result = checklist_result(row, recorded);
        assert_exportable_checklist_result(row, &result);
        out.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            row.test_case, row.section, row.verification, result
        ));
    }
    out
}

fn render_risks(manifest: &Manifest) -> String {
    let mut out = String::from("# TAXII TXC interop risks\n\n");
    out.push_str("## Scope boundaries\n\n");
    out.push_str(
        "- Persona claim is **TXC only**. TAXII Server (TXS) Table 52 is out of scope for `rstix`.\n",
    );
    out.push_str("- TAXII Channels (spec §6) are RESERVED and are not part of CSD01 Table 51.\n");
    out.push_str(
        "- This package is **self-certification evidence** against CSD01 — not an OASIS-issued certificate.\n\n",
    );
    out.push_str("## Optional Table 51 rows (REPORT_ONLY)\n\n");
    for row in manifest
        .requirements
        .iter()
        .filter(|r| r.disposition == Disposition::ReportOnly)
    {
        out.push_str(&format!(
            "- `{}` ({}/{}): optional additional match filters (§3.13.2) — not required for TXC Mandatory verification.\n",
            row.req_id, row.section, row.test_case
        ));
    }
    out.push_str("\n## Mock TXS note\n\n");
    out.push_str(
        "- Mandatory HTTP scenarios use a local wiremock TAXII Server stand-in with OASIS-shaped responses.\n",
    );
    out.push_str(
        "- Mock collection IDs follow OASIS examples where unique; no-read/no-write uses a distinct id so wiremock routes do not collide with the reused CSD01 example id in Tables 12–13.\n\n",
    );
    out.push_str("## Assertion depth (docx-aligned)\n\n");
    out.push_str(
        "- Authority text is `plan/taxii-2.1-interop-v1.0.docx` (CSD01 2022-03-30). Scenario depth matches Tables 2–50 request/response shapes, not only Table 51 row titles.\n",
    );
    out.push_str(
        "- §2.1.4: mocks require `User-Agent: rstix/…`. §3.1.1: `WWW-Authenticate` parsed as two Basic challenges (Table 2).\n",
    );
    out.push_str(
        "- §3.14.1: versions pagination continues with `added_after` from `X-TAXII-Date-Added-Last` (Tables 48–49). CSD01 Table 49 prints `added-after` (hyphen); rstix follows TAXII 2.1 OS `added_after` (underscore).\n",
    );
    out.push_str(
        "- §3.13.1.10: Table 42 shows a deliberately duplicate `match[type]` query; rstix encodes OR as one comma-joined parameter (TAXII OS) and still proves HTTP 400 handling.\n",
    );
    out.push_str(
        "- §3.15.1: `TaxiiEnvelope::with_custom` posts `x_*` and preserves custom Status properties (Table 50).\n",
    );
    out
}

pub fn run_helper_self_tests() {
    super::gate_expectations::assert_gate_expectations_file_current();

    let manifest = super::manifest::load_manifest();
    assert_eq!(manifest.requirements.len(), 44);
    assert_eq!(super::registry::all_tests().len(), 39);
}
