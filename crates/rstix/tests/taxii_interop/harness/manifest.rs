//! Parse and validate `fixtures/taxii-interop/manifest.toml`.

use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

/// How a TXC checklist row participates in certification.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Disposition {
    #[default]
    Tested,
    ReportOnly,
}

impl Disposition {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tested => "TESTED",
            Self::ReportOnly => "REPORT_ONLY",
        }
    }
}

#[derive(Clone, Debug, serde::Deserialize)]
pub struct RequirementRow {
    pub req_id: String,
    pub section: String,
    pub test_case: String,
    pub verification: String,
    #[serde(default)]
    pub disposition: Disposition,
    #[serde(default)]
    pub checklist_row: bool,
    pub test_id: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct ManifestFile {
    requirement: Vec<RequirementRow>,
}

#[derive(Debug)]
pub struct Manifest {
    pub requirements: Vec<RequirementRow>,
}

pub fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/taxii-interop")
}

impl Manifest {
    pub fn load_from_disk() -> Self {
        let path = fixtures_root().join("manifest.toml");
        let text =
            fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Self {
        let parsed: ManifestFile =
            toml::from_str(text).unwrap_or_else(|e| panic!("parse taxii-interop manifest: {e}"));
        let manifest = Self {
            requirements: parsed.requirement,
        };
        manifest.validate();
        manifest
    }

    fn validate(&self) {
        let mut seen = HashSet::new();
        for row in &self.requirements {
            assert!(
                seen.insert(row.req_id.clone()),
                "duplicate req_id: {}",
                row.req_id
            );
            if row.disposition == Disposition::Tested {
                assert!(
                    row.test_id.is_some(),
                    "{}: TESTED disposition requires test_id",
                    row.req_id
                );
            }
            assert!(
                row.checklist_row,
                "{}: TXC Table 51 rows must set checklist_row",
                row.req_id
            );
        }
        let mandatory = self
            .requirements
            .iter()
            .filter(|r| r.verification == "Mandatory")
            .count();
        let optional = self
            .requirements
            .iter()
            .filter(|r| r.verification == "Optional")
            .count();
        assert_eq!(
            self.requirements.len(),
            44,
            "Table 51 must have 44 rows (39 Mandatory + 5 Optional)"
        );
        assert_eq!(mandatory, 39, "expected 39 Mandatory Table 51 rows");
        assert_eq!(optional, 5, "expected 5 Optional Table 51 rows");
    }

    pub fn checklist_rows(&self) -> Vec<&RequirementRow> {
        let mut rows: Vec<_> = self
            .requirements
            .iter()
            .filter(|r| r.checklist_row)
            .collect();
        rows.sort_by(|a, b| a.section.cmp(&b.section));
        rows
    }

    pub fn tested_requirements(&self) -> impl Iterator<Item = &RequirementRow> {
        self.requirements
            .iter()
            .filter(|row| row.disposition == Disposition::Tested)
    }
}

pub fn load_manifest() -> Manifest {
    Manifest::load_from_disk()
}
