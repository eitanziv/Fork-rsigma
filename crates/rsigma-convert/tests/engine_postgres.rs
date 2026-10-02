//! Runs the PostgreSQL backend's SQL in a real PostgreSQL server.
//!
//! Each case runs in both storage modes the backend supports: events in one
//! JSONB column (`json_field`), and events spread over typed columns, one per
//! field (integers as `bigint`, everything else as `text`). The generated
//! query runs unmodified as a subquery, and the matched rows are compared with
//! the case expectations. A second test runs SigmaHQ rules whose conditions
//! need grouping against eval; it reads the checkout in `RSIGMA_SIGMA_CORPUS`.
//! Run with
//! `RSIGMA_SIGMA_CORPUS=<sigma checkout> cargo test -p rsigma-convert --test engine_postgres -- --ignored`.

mod engines;

use std::collections::{BTreeMap, HashMap};

use engines::{Case, IDX_FIELD, Outcome};
use rsigma_convert::backends::postgres::PostgresBackend;
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, ImageExt};
use testcontainers_modules::postgres::Postgres;
use tokio_postgres::NoTls;

const POSTGRES_TAG: &str =
    "18-alpine@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873";

#[derive(Clone, Copy)]
enum Mode {
    Jsonb,
    Columns,
}

fn backend_for(table: &str, mode: Mode) -> PostgresBackend {
    let mut opts = HashMap::from([
        ("table".to_string(), table.to_string()),
        ("timestamp_field".to_string(), "time".to_string()),
    ]);
    if let Mode::Jsonb = mode {
        opts.insert("json_field".to_string(), "data".to_string());
    }
    PostgresBackend::from_options(&opts)
}

fn quote_ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

async fn create_and_load(
    client: &tokio_postgres::Client,
    table: &str,
    mode: Mode,
    case: &Case,
) -> Result<(), tokio_postgres::Error> {
    let events = case.indexed_events();
    match mode {
        Mode::Jsonb => {
            client
                .batch_execute(&format!(
                    "CREATE TABLE {table} (time TIMESTAMPTZ NOT NULL DEFAULT now(), data JSONB NOT NULL)"
                ))
                .await?;
            for event in events {
                client
                    .execute(
                        &format!("INSERT INTO {table} (data) VALUES ($1::text::jsonb)"),
                        &[&event.to_string()],
                    )
                    .await?;
            }
        }
        Mode::Columns => {
            let mut columns: BTreeMap<String, &'static str> = BTreeMap::new();
            for event in &events {
                for (k, v) in event.as_object().unwrap() {
                    let ty = if v.is_i64() || v.is_u64() {
                        "bigint"
                    } else {
                        "text"
                    };
                    columns.entry(k.clone()).or_insert(ty);
                }
            }
            let defs: Vec<String> = columns
                .iter()
                .map(|(k, ty)| format!("{} {ty}", quote_ident(k)))
                .collect();
            client
                .batch_execute(&format!(
                    "CREATE TABLE {table} (time TIMESTAMPTZ NOT NULL DEFAULT now(), {})",
                    defs.join(", ")
                ))
                .await?;
            for event in events {
                // jsonb_populate_record casts each JSON value to its column type
                // and leaves absent keys NULL.
                client
                    .execute(
                        &format!(
                            "INSERT INTO {table} SELECT * FROM jsonb_populate_record(NULL::{table}, $1::text::jsonb || '{{\"time\": \"2026-01-01T00:00:00Z\"}}')"
                        ),
                        &[&event.to_string()],
                    )
                    .await?;
            }
        }
    }
    Ok(())
}

async fn run_case(
    client: &tokio_postgres::Client,
    table: &str,
    mode: Mode,
    case: &Case,
) -> Result<Outcome, String> {
    let queries = match engines::convert(&backend_for(table, mode), case, &[], "default") {
        Ok(q) => q,
        Err(e) => return Ok(Outcome::ConversionRejected(e)),
    };
    create_and_load(client, table, mode, case)
        .await
        .map_err(|e| e.to_string())?;
    let idx = match mode {
        Mode::Jsonb => format!("(q.data->>'{IDX_FIELD}')::int"),
        Mode::Columns => format!("q.{IDX_FIELD}::int"),
    };
    let mut matched = Vec::new();
    for query in queries {
        let sql = format!(
            "SELECT {idx} FROM ({}) AS q",
            query.trim().trim_end_matches(';')
        );
        let rows = client
            .query(&sql, &[])
            .await
            .map_err(|e| format!("{}\n    query: {query}", db_error(&e)))?;
        matched.extend(rows.iter().map(|r| r.get::<_, i32>(0) as usize));
    }
    Ok(Outcome::Matched(matched))
}

fn db_error(e: &tokio_postgres::Error) -> String {
    e.as_db_error()
        .map(|d| d.message().to_string())
        .unwrap_or_else(|| e.to_string())
}

async fn start_postgres() -> (ContainerAsync<Postgres>, tokio_postgres::Client) {
    engines::require_docker();
    let container = Postgres::default()
        .with_tag(POSTGRES_TAG)
        .start()
        .await
        .expect("failed to start PostgreSQL");
    let port = container.get_host_port_ipv4(5432).await.unwrap();
    let (client, connection) = tokio_postgres::connect(
        &format!("host=127.0.0.1 port={port} user=postgres password=postgres dbname=postgres"),
        NoTls,
    )
    .await
    .expect("failed to connect to PostgreSQL");
    tokio::spawn(connection);
    (container, client)
}

/// Run every case in both storage modes and return the failures.
async fn run_cases(client: &tokio_postgres::Client, prefix: &str, cases: &[Case]) -> Vec<String> {
    let mut failures = Vec::new();
    for (mode, label) in [
        (Mode::Jsonb, "postgres-jsonb"),
        (Mode::Columns, "postgres-columns"),
    ] {
        let mut results = Vec::new();
        for (i, case) in cases.iter().enumerate() {
            let table = format!("{prefix}_{}_{i}", label.replace('-', "_"));
            results.push((case.clone(), run_case(client, &table, mode, case).await));
        }
        failures.extend(engines::check_outcomes(label, &results));
    }
    failures
}

#[tokio::test]
#[ignore = "engine test: needs Docker; run by the PostgreSQL engine workflow"]
async fn postgres_executes_cases() {
    let (_container, client) = start_postgres().await;
    let failures = run_cases(&client, "case", &engines::load_cases()).await;
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Differential test against eval over the SigmaHQ rules whose conditions
/// need grouping (see `engines::corpus`).
#[tokio::test]
#[ignore = "engine test: needs Docker and a SigmaHQ checkout in RSIGMA_SIGMA_CORPUS; run by the PostgreSQL engine workflow"]
async fn postgres_agrees_with_eval_on_sigma_corpus() {
    let Some(corpus) = std::env::var_os("RSIGMA_SIGMA_CORPUS") else {
        assert!(
            std::env::var_os("CI").is_none(),
            "set RSIGMA_SIGMA_CORPUS to a SigmaHQ checkout"
        );
        eprintln!("skipping: RSIGMA_SIGMA_CORPUS is not set");
        return;
    };
    let sample = engines::corpus::grouping_cases(std::path::Path::new(&corpus), |case| {
        engines::convert(&backend_for("t", Mode::Jsonb), case, &[], "default")
            .is_ok_and(|q| q.len() == 1)
    });
    let with_both = sample
        .cases
        .iter()
        .filter(|c| !c.matches.is_empty() && c.matches.len() < c.events.len())
        .count();
    eprintln!(
        "{} rule files, {} need grouping, {} use only plain string values, {} convert; {} have matching and non-matching events",
        sample.files,
        sample.needs_grouping,
        sample.plain_values,
        sample.cases.len(),
        with_both,
    );
    assert!(
        with_both >= 1000,
        "only {with_both} corpus rules have both matching and non-matching events"
    );

    let (_container, client) = start_postgres().await;
    let failures = run_cases(&client, "corpus", &sample.cases).await;
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
