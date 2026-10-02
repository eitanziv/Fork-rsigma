use std::collections::HashSet;
use std::path::PathBuf;
use std::process;

use clap::Args;
use rsigma_eval::Engine;
use rsigma_parser::parse_sigma_directory;
use serde::Serialize;

use crate::output::{OutputCtx, OutputFormat, Tabular, render_report};

/// Arguments for `rsigma rule validate` (and the deprecated `rsigma validate`).
#[derive(Args, Debug)]
pub(crate) struct ValidateArgs {
    /// Path to a directory containing Sigma YAML files
    pub path: PathBuf,

    /// Show details for each file (not just summary)
    #[arg(short, long)]
    pub verbose: bool,

    /// Processing pipeline(s) to apply. Accepts builtin names (ecs_windows, sysmon) or YAML file paths
    #[arg(short = 'p', long = "pipeline")]
    pub pipelines: Vec<PathBuf>,

    /// Also resolve dynamic pipeline sources during validation.
    /// Sources must be reachable (file/command/HTTP) for validation to pass.
    #[arg(long = "resolve-sources")]
    pub resolve_sources: bool,

    /// External source file(s) or directory of source files
    #[arg(long = "source", value_name = "FILE_OR_DIR")]
    pub source_files: Vec<PathBuf>,
}

#[derive(Debug, Serialize)]
struct ValidateSummary {
    path: String,
    total: usize,
    detection_rules: usize,
    correlation_rules: usize,
    filter_rules: usize,
    parse_errors: usize,
    compile_ok: usize,
    compile_errors: usize,
    pipelines: usize,
}

#[derive(Debug, Serialize)]
struct ValidateRow {
    path: String,
    status: String,
    errors: String,
}

impl Tabular for ValidateRow {
    fn headers() -> &'static [&'static str] {
        &["PATH", "STATUS", "ERRORS"]
    }
    fn row(&self) -> Vec<String> {
        vec![self.path.clone(), self.status.clone(), self.errors.clone()]
    }
}

pub(crate) fn cmd_validate(args: ValidateArgs, ctx: OutputCtx) {
    let ValidateArgs {
        path,
        verbose,
        pipelines: pipeline_paths,
        resolve_sources,
        source_files,
    } = args;
    // Dynamic source resolution (`--resolve-sources` / `--source`) needs the
    // async runtime + source resolver, which ship with the `daemon` feature.
    #[cfg(feature = "daemon")]
    let pipelines = resolve_validate_sources(
        crate::load_pipelines(&pipeline_paths),
        resolve_sources,
        &source_files,
        !ctx.explicit_format,
    );
    #[cfg(not(feature = "daemon"))]
    let pipelines = {
        let loaded = crate::load_pipelines(&pipeline_paths);
        if resolve_sources || !source_files.is_empty() {
            eprintln!(
                "error: --resolve-sources/--source require the `daemon` feature; \
                 rebuild with `--features daemon`"
            );
            process::exit(crate::exit_code::CONFIG_ERROR);
        }
        loaded
    };

    match parse_sigma_directory(&path) {
        Ok(collection) => {
            let total = collection.len();
            let rules = collection.rules.len();
            let correlations = collection.correlations.len();
            let filters = collection.filters.len();
            let parse_errors = collection.errors.len();

            let mut engine = Engine::new();
            for p in &pipelines {
                engine.add_pipeline(p.clone());
            }

            // Batch all rules through `add_rules` so the inverted index and
            // bloom filter rebuild exactly once for the whole corpus instead
            // of once per rule (the latter is O(N²) and turns 3K-rule loads
            // into a multi-minute stall).
            let batch_errors = engine.add_rules(&collection.rules);
            let compile_ok = collection.rules.len() - batch_errors.len();
            let mut compile_errors: Vec<String> = batch_errors
                .into_iter()
                .map(|(idx, e)| {
                    let rule = &collection.rules[idx];
                    let id = rule.id.as_deref().unwrap_or(&rule.title);
                    format!("{id}: {e}")
                })
                .collect();
            compile_errors.extend(validate_correlation_references(&collection));

            let parse_error_msgs: Vec<String> =
                collection.errors.iter().map(|e| e.to_string()).collect();

            let summary = ValidateSummary {
                path: path.display().to_string(),
                total,
                detection_rules: rules,
                correlation_rules: correlations,
                filter_rules: filters,
                parse_errors,
                compile_ok,
                compile_errors: compile_errors.len(),
                pipelines: pipelines.len(),
            };

            if ctx.explicit_format {
                let mut rows = Vec::new();
                for err in &parse_error_msgs {
                    rows.push(ValidateRow {
                        path: path.display().to_string(),
                        status: "parse_error".into(),
                        errors: err.clone(),
                    });
                }
                for err in &compile_errors {
                    rows.push(ValidateRow {
                        path: path.display().to_string(),
                        status: "compile_error".into(),
                        errors: err.clone(),
                    });
                }
                if rows.is_empty() {
                    rows.push(ValidateRow {
                        path: path.display().to_string(),
                        status: "ok".into(),
                        errors: String::new(),
                    });
                }
                let envelope = serde_json::json!({
                    "summary": summary,
                    "parse_errors": parse_error_msgs,
                    "compile_errors": compile_errors,
                });
                // NDJSON: one row per finding (or a single ok row). JSON: envelope.
                match ctx.format {
                    OutputFormat::Ndjson
                    | OutputFormat::Table
                    | OutputFormat::Csv
                    | OutputFormat::Tsv => render_report(&ctx, &envelope, &rows),
                    OutputFormat::Json => {
                        crate::output::render_json(&envelope, ctx.pretty_json());
                    }
                }
            } else {
                println!("Parsed {total} documents from {}", path.display());
                println!("  Detection rules:   {rules}");
                println!("  Correlation rules: {correlations}");
                println!("  Filter rules:      {filters}");
                println!("  Parse errors:      {parse_errors}");
                tracing::info!(
                    total,
                    detection_rules = rules,
                    correlation_rules = correlations,
                    filter_rules = filters,
                    parse_errors,
                    rules_path = %path.display(),
                    "Validation parsed",
                );

                if !pipelines.is_empty() {
                    println!("  Pipeline applied:  {} pipeline(s)", pipelines.len(),);
                }
                println!("  Compiled OK:       {compile_ok}");
                println!("  Compile errors:    {}", compile_errors.len());

                if verbose {
                    if !collection.errors.is_empty() {
                        println!("\nParse errors:");
                        for err in &collection.errors {
                            println!("  - {err}");
                        }
                    }
                    if !compile_errors.is_empty() {
                        println!("\nCompile errors:");
                        for err in &compile_errors {
                            println!("  - {err}");
                        }
                    }
                }
            }

            if parse_errors > 0 || !compile_errors.is_empty() {
                process::exit(crate::exit_code::RULE_ERROR);
            }
        }
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(crate::exit_code::RULE_ERROR);
        }
    }
}

fn validate_correlation_references(collection: &rsigma_parser::SigmaCollection) -> Vec<String> {
    let mut known = HashSet::new();
    for rule in &collection.rules {
        known.extend(rule.id.iter().map(String::as_str));
        known.extend(rule.name.iter().map(String::as_str));
    }
    for correlation in &collection.correlations {
        known.extend(correlation.id.iter().map(String::as_str));
        known.extend(correlation.name.iter().map(String::as_str));
    }

    collection
        .correlations
        .iter()
        .flat_map(|correlation| {
            correlation
                .rules
                .iter()
                .filter(|rule_ref| !known.contains(rule_ref.as_str()))
                .map(|rule_ref| {
                    let identity = correlation
                        .id
                        .as_deref()
                        .or(correlation.name.as_deref())
                        .unwrap_or(&correlation.title);
                    format!("{identity}: unknown rule reference: {rule_ref}")
                })
        })
        .collect()
}

/// Load external sources and, when `--resolve-sources` is set, resolve every
/// dynamic pipeline and external source, returning the expanded pipelines.
/// Exits with `CONFIG_ERROR` on a load or resolution failure.
#[cfg(feature = "daemon")]
fn resolve_validate_sources(
    mut pipelines: Vec<rsigma_eval::Pipeline>,
    resolve_sources: bool,
    source_files: &[PathBuf],
    print_human_ok: bool,
) -> Vec<rsigma_eval::Pipeline> {
    // Load external sources alongside pipeline-embedded ones (validating that
    // the source files parse, regardless of whether we resolve them).
    let external_sources = if !source_files.is_empty() {
        match rsigma_runtime::sources::registry::load_external_sources(source_files) {
            Ok(ext) => ext.into_iter().map(|(s, _)| s).collect::<Vec<_>>(),
            Err(e) => {
                eprintln!("Error loading external sources: {e}");
                process::exit(crate::exit_code::CONFIG_ERROR);
            }
        }
    } else {
        Vec::new()
    };

    if resolve_sources {
        let has_dynamic = pipelines.iter().any(|p| p.is_dynamic()) || !external_sources.is_empty();
        if has_dynamic {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap_or_else(|e| {
                    eprintln!("Failed to create async runtime for source resolution: {e}");
                    process::exit(crate::exit_code::CONFIG_ERROR);
                });

            let resolver = rsigma_runtime::DefaultSourceResolver::new();
            let mut resolved_pipelines = Vec::with_capacity(pipelines.len());
            let mut source_errors: Vec<String> = Vec::new();

            // Resolve the external sources once into a shared data map that
            // every dynamic pipeline's `${source.*}` references expand against.
            let resolved_data = match rt.block_on(rsigma_runtime::sources::resolve_all(
                &resolver,
                &external_sources,
            )) {
                Ok(data) => data,
                Err(e) => {
                    source_errors.push(format!("external sources: {e}"));
                    std::collections::HashMap::new()
                }
            };

            for pipeline in &pipelines {
                if pipeline.is_dynamic() {
                    let mut expanded = rsigma_runtime::sources::template::TemplateExpander::expand(
                        pipeline,
                        &resolved_data,
                    );
                    if let Err(e) = rsigma_runtime::sources::include::expand_includes(
                        &mut expanded,
                        &resolved_data,
                        &external_sources,
                        false,
                    ) {
                        source_errors.push(format!("pipeline '{}': {e}", pipeline.name));
                    }
                    resolved_pipelines.push(expanded);
                } else {
                    resolved_pipelines.push(pipeline.clone());
                }
            }

            if !source_errors.is_empty() {
                eprintln!("Source resolution errors:");
                for err in &source_errors {
                    eprintln!("  - {err}");
                }
                process::exit(crate::exit_code::CONFIG_ERROR);
            }

            pipelines = resolved_pipelines;
            if print_human_ok {
                println!("  Sources resolved:  OK");
            }
        }
    }

    pipelines
}
