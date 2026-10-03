//! Runs the LynxDB backend's queries in a real LynxDB server.
//!
//! The image in `tests/engines/lynxdb/` starts a pinned LynxDB release, ingests
//! each case's events into its own index (`c<n>`, selected through the
//! backend's `index` pipeline state), waits until every event is flushed to a
//! segment, runs the generated queries unmodified, and reports the matched
//! events. A second test runs SigmaHQ rules whose conditions need grouping
//! against eval; it reads the checkout in `RSIGMA_SIGMA_CORPUS`. Run with
//! `RSIGMA_SIGMA_CORPUS=<sigma checkout> cargo test -p rsigma-convert --test engine_lynxdb -- --ignored`.

mod engines;

use std::path::Path;
use std::process::Command;

use engines::{Case, IDX_FIELD, Outcome};
use rsigma_convert::backends::lynxdb::LynxDbBackend;
use rsigma_eval::pipeline::parse_pipeline;

const IMAGE: &str = "rsigma-engine-lynxdb:v0.2.5";

fn index_pipeline(index: &str) -> rsigma_eval::pipeline::Pipeline {
    parse_pipeline(&format!(
        "name: engine-index\ntransformations:\n  - type: set_state\n    key: index\n    value: {index}\n"
    ))
    .unwrap()
}

/// Write the case events and queries; `None` when conversion was rejected.
fn prepare(dir: &Path, n: usize, case: &Case) -> Result<usize, String> {
    let queries = engines::convert(
        &LynxDbBackend::new(),
        case,
        &[index_pipeline(&format!("c{n}"))],
        "default",
    )?;
    let case_dir = dir.join(n.to_string());
    std::fs::create_dir_all(&case_dir).unwrap();
    let events: Vec<String> = case
        .indexed_events()
        .iter()
        .map(|e| e.to_string())
        .collect();
    std::fs::write(case_dir.join("events.ndjson"), events.join("\n") + "\n").unwrap();
    for (k, q) in queries.iter().enumerate() {
        std::fs::write(case_dir.join(format!("q{k}.txt")), q).unwrap();
    }
    Ok(queries.len())
}

fn collect(dir: &Path, n: usize, query_count: usize) -> Result<Outcome, String> {
    let case_dir = dir.join(n.to_string());
    let mut matched = Vec::new();
    for k in 0..query_count {
        let read =
            |ext: &str| std::fs::read_to_string(case_dir.join(format!("q{k}.{ext}"))).unwrap();
        if read("rc").trim() != "0" {
            return Err(format!(
                "query failed: {}\n    query: {}",
                read("err").trim(),
                read("txt")
            ));
        }
        for line in read("out").lines().filter(|l| l.starts_with('{')) {
            let row: serde_json::Value =
                serde_json::from_str(line).map_err(|e| format!("unparseable row {line}: {e}"))?;
            // Rows read from segments carry only the fields the query
            // references, so take the index from the original event.
            let idx = row["_raw"]
                .as_str()
                .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())
                .and_then(|raw| raw[IDX_FIELD].as_u64())
                .ok_or_else(|| format!("row without {IDX_FIELD} in _raw: {line}"))?;
            matched.push(idx as usize);
        }
    }
    Ok(Outcome::Matched(matched))
}

/// Run every case in one LynxDB server and return the outcomes.
fn run_cases(label: &str, cases: Vec<Case>) -> Vec<(Case, Result<Outcome, String>)> {
    engines::require_docker();
    let image = engines::docker_build("lynxdb", IMAGE);

    let work = std::env::temp_dir().join(format!(
        "rsigma-engine-lynxdb-{label}-{}",
        std::process::id()
    ));
    let cases_dir = work.join("cases");
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&cases_dir).unwrap();

    let prepared: Vec<Result<usize, String>> = cases
        .iter()
        .enumerate()
        .map(|(n, case)| prepare(&cases_dir, n, case))
        .collect();

    engines::run_ok(
        Command::new("docker")
            .args(["run", "--rm", "-v"])
            .arg(format!("{}:/work", work.display()))
            .arg(&image),
    );

    let results: Vec<(Case, Result<Outcome, String>)> = cases
        .into_iter()
        .zip(prepared)
        .enumerate()
        .map(|(n, (case, prep))| {
            let outcome = match prep {
                Err(e) => Ok(Outcome::ConversionRejected(e)),
                Ok(count) => collect(&cases_dir, n, count),
            };
            (case, outcome)
        })
        .collect();
    let _ = std::fs::remove_dir_all(&work);
    results
}

#[test]
#[ignore = "engine test: needs Docker; run by the LynxDB engine workflow"]
fn lynxdb_executes_cases() {
    let results = run_cases("cases", engines::load_cases());
    engines::assert_outcomes("lynxdb", &results);
}

/// Differential test against eval over the SigmaHQ rules whose conditions
/// need grouping (see `engines::corpus`).
#[test]
#[ignore = "engine test: needs Docker and a SigmaHQ checkout in RSIGMA_SIGMA_CORPUS; run by the LynxDB engine workflow"]
fn lynxdb_agrees_with_eval_on_sigma_corpus() {
    let Some(corpus) = std::env::var_os("RSIGMA_SIGMA_CORPUS") else {
        assert!(
            std::env::var_os("CI").is_none(),
            "set RSIGMA_SIGMA_CORPUS to a SigmaHQ checkout"
        );
        eprintln!("skipping: RSIGMA_SIGMA_CORPUS is not set");
        return;
    };
    let sample = engines::corpus::grouping_cases(Path::new(&corpus), |case| {
        engines::convert(
            &LynxDbBackend::new(),
            case,
            &[index_pipeline("c")],
            "default",
        )
        .is_ok_and(|q| q.len() == 1)
    });
    let with_both = sample
        .cases
        .iter()
        .filter(|c| !c.matches.is_empty() && c.matches.len() < c.events.len())
        .count();
    eprintln!(
        "{} rules convert; {with_both} have matching and non-matching events",
        sample.cases.len()
    );
    assert!(
        with_both >= 700,
        "only {with_both} corpus rules have both matching and non-matching events"
    );

    let results = run_cases("corpus", sample.cases);
    let failures = engines::check_outcomes("lynxdb", &results);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
