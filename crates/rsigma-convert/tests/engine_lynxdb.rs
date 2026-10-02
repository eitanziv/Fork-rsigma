//! Runs the LynxDB backend's queries in a real LynxDB server.
//!
//! The image in `tests/engines/lynxdb/` starts a pinned LynxDB release, ingests
//! each case's events into its own index (`c<n>`, selected through the
//! backend's `index` pipeline state), runs the generated queries unmodified,
//! and reports the matched events. Run with
//! `cargo test -p rsigma-convert --test engine_lynxdb -- --ignored`.

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
            let idx = row
                .get(IDX_FIELD)
                .and_then(|v| {
                    v.as_u64()
                        .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
                })
                .ok_or_else(|| format!("row without {IDX_FIELD}: {line}"))?;
            matched.push(idx as usize);
        }
    }
    Ok(Outcome::Matched(matched))
}

#[test]
#[ignore = "engine test: needs Docker; run by the LynxDB engine workflow"]
fn lynxdb_executes_cases() {
    engines::require_docker();
    let image = engines::docker_build("lynxdb", IMAGE);

    let work = std::env::temp_dir().join(format!("rsigma-engine-lynxdb-{}", std::process::id()));
    let cases_dir = work.join("cases");
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&cases_dir).unwrap();

    let cases = engines::load_cases();
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
    engines::assert_outcomes("lynxdb", &results);
}
