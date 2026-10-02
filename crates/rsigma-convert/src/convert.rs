use std::collections::HashMap;

use rsigma_eval::pipeline::{Pipeline, apply_pipelines_to_correlation, apply_pipelines_with_state};
use rsigma_parser::{CorrelationRule, SigmaCollection, SigmaRule};

use crate::backend::Backend;
use crate::error::{ConvertError, Result};
use crate::output::{ConversionOutput, ConversionResult};

/// Convert a collection of Sigma rules using the given backend and pipelines.
///
/// Applies each pipeline to every rule, then delegates to the backend for
/// conversion. Errors from individual rules are collected rather than aborting
/// the entire batch.
///
/// For backends that support correlation, a rule-to-table mapping is built from
/// each detection rule's pipeline state and `postgres.table` custom attribute.
/// This mapping is injected into the correlation pipeline state under
/// `_rule_tables` so that temporal correlations can generate multi-table
/// `UNION ALL` queries when referenced rules target different tables.
pub fn convert_collection(
    backend: &dyn Backend,
    collection: &SigmaCollection,
    pipelines: &[Pipeline],
    output_format: &str,
) -> Result<ConversionOutput> {
    if backend.requires_pipeline() && pipelines.is_empty() {
        return Err(ConvertError::PipelineRequired);
    }

    let mut output = ConversionOutput::new();
    let mut rule_table_map: HashMap<String, String> = HashMap::new();
    let mut rule_schema_map: HashMap<String, String> = HashMap::new();
    let mut rule_query_map: HashMap<String, String> = HashMap::new();

    for rule in &collection.rules {
        let emit_standalone = !backend.supports_correlation()
            || should_emit_standalone(rule, &collection.correlations);
        let mut rule = rule.clone();
        let pipeline_state = if !pipelines.is_empty() {
            apply_pipelines_with_state(pipelines, &mut rule)?
        } else {
            Default::default()
        };

        // Record rule → table/schema for multi-table correlation support.
        // custom_attributes["postgres.*"] takes precedence over pipeline state.
        let resolved_table = rule
            .custom_attributes
            .get("postgres.table")
            .and_then(|v| v.as_str())
            .or_else(|| pipeline_state.state.get("table").and_then(|v| v.as_str()));

        if let Some(table) = resolved_table {
            if let Some(id) = &rule.id {
                rule_table_map.insert(id.clone(), table.to_string());
            }
            if let Some(name) = &rule.name {
                rule_table_map.insert(name.clone(), table.to_string());
            }
            rule_table_map.insert(rule.title.clone(), table.to_string());
        }

        let resolved_schema = rule
            .custom_attributes
            .get("postgres.schema")
            .and_then(|v| v.as_str())
            .or_else(|| pipeline_state.state.get("schema").and_then(|v| v.as_str()));

        if let Some(schema) = resolved_schema {
            if let Some(id) = &rule.id {
                rule_schema_map.insert(id.clone(), schema.to_string());
            }
            if let Some(name) = &rule.name {
                rule_schema_map.insert(name.clone(), schema.to_string());
            }
            rule_schema_map.insert(rule.title.clone(), schema.to_string());
        }

        match backend.convert_rule(&rule, output_format, &pipeline_state) {
            Ok(queries) => {
                if let Some(q) = queries.first() {
                    if let Some(id) = &rule.id {
                        rule_query_map.insert(id.clone(), q.clone());
                    }
                    if let Some(name) = &rule.name {
                        rule_query_map.insert(name.clone(), q.clone());
                    }
                    rule_query_map.insert(rule.title.clone(), q.clone());
                }
                if emit_standalone {
                    output.queries.push(ConversionResult {
                        rule_title: rule.title.clone(),
                        rule_id: rule.id.clone(),
                        queries,
                        warnings: Vec::new(),
                    });
                }
            }
            Err(e) => {
                output.errors.push((rule.title.clone(), e));
            }
        }
    }

    if backend.supports_correlation() {
        for corr in &collection.correlations {
            let mut corr = corr.clone();
            let mut pipeline_state = if !pipelines.is_empty() {
                apply_pipelines_to_correlation(pipelines, &mut corr)?
            } else {
                Default::default()
            };

            if !rule_table_map.is_empty() {
                let map_value = serde_json::to_value(&rule_table_map)
                    .unwrap_or(serde_json::Value::Object(Default::default()));
                pipeline_state.set_state("_rule_tables".to_string(), map_value);
            }
            if !rule_schema_map.is_empty() {
                let map_value = serde_json::to_value(&rule_schema_map)
                    .unwrap_or(serde_json::Value::Object(Default::default()));
                pipeline_state.set_state("_rule_schemas".to_string(), map_value);
            }
            if !rule_query_map.is_empty() {
                let map_value = serde_json::to_value(&rule_query_map)
                    .unwrap_or(serde_json::Value::Object(Default::default()));
                pipeline_state.set_state("_rule_queries".to_string(), map_value);
            }

            let mut warnings = Vec::new();
            match backend.convert_correlation_rule_with_warnings(
                &corr,
                output_format,
                &pipeline_state,
                &mut warnings,
            ) {
                Ok(queries) => {
                    output.queries.push(ConversionResult {
                        rule_title: corr.title.clone(),
                        rule_id: corr.id.clone(),
                        queries,
                        warnings,
                    });
                }
                Err(e) => {
                    output.errors.push((corr.title.clone(), e));
                }
            }
        }
    }

    Ok(output)
}

fn should_emit_standalone(rule: &SigmaRule, correlations: &[CorrelationRule]) -> bool {
    let mut referenced = false;
    for correlation in correlations {
        let matches = correlation.rules.iter().any(|rule_ref| {
            rule.id.as_deref() == Some(rule_ref) || rule.name.as_deref() == Some(rule_ref)
        });
        if matches {
            referenced = true;
            if correlation.generate {
                return true;
            }
        }
    }
    !referenced
}

/// True if any dot-segment of a field path is a positional array index
/// (`name[N]`, including a negative `name[-N]`). The quantifier selectors never
/// reach field names (the parser desugars them into `Detection::ArrayMatch`),
/// so a bracketed integer is the positional-index signal.
pub(crate) fn field_has_positional_index(field: &str) -> bool {
    field.split('.').any(|seg| {
        // Only an unescaped trailing `[...]` is a selector; `\[` / `\]` are a
        // literal bracket in the field name, not a positional index.
        let Some(open) = rsigma_parser::fieldpath::first_unescaped(seg, b'[') else {
            return false;
        };
        if !rsigma_parser::fieldpath::ends_with_unescaped(seg, b']') {
            return false;
        }
        let inner = &seg[open + 1..seg.len() - 1];
        let digits = inner.strip_prefix('-').unwrap_or(inner);
        !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
    })
}

#[cfg(test)]
mod tests {
    use super::{convert_collection, field_has_positional_index, should_emit_standalone};
    use crate::backends::postgres::PostgresBackend;
    use rsigma_parser::parse_sigma_yaml;

    #[test]
    fn positional_index_detection_respects_escaping() {
        assert!(field_has_positional_index("args[0]"));
        assert!(field_has_positional_index("args[-1]"));
        assert!(field_has_positional_index("connections[0].ip"));
        // Escaped brackets are a literal field name, not a positional index.
        assert!(!field_has_positional_index("args\\[0\\]"));
        assert!(!field_has_positional_index("weird\\[x\\]"));
        // Quantifier selectors never reach field names, and plain fields have
        // no index.
        assert!(!field_has_positional_index("process.args"));
    }

    #[test]
    fn referenced_rules_are_standalone_only_when_generate_is_true() {
        let yaml = r#"
title: Base
name: base
logsource:
    category: test
detection:
    selection:
        EventID: 1
    condition: selection
---
title: Count
correlation:
    type: event_count
    rules: [base]
    group-by: [User]
    timespan: 1m
    condition:
        gte: 2
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        assert!(!should_emit_standalone(
            &collection.rules[0],
            &collection.correlations
        ));

        let mut generated = collection.correlations.clone();
        generated[0].generate = true;
        assert!(should_emit_standalone(&collection.rules[0], &generated));
    }

    #[test]
    fn collection_conversion_omits_referenced_rule_by_default() {
        let yaml = r#"
title: Base
name: base
logsource:
    category: test
detection:
    selection:
        EventID: 1
    condition: selection
---
title: Count
correlation:
    type: event_count
    rules: [base]
    group-by: [User]
    timespan: 1m
    condition:
        gte: 2
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        let output =
            convert_collection(&PostgresBackend::new(), &collection, &[], "default").unwrap();
        let titles: Vec<_> = output
            .queries
            .iter()
            .map(|result| result.rule_title.as_str())
            .collect();
        assert_eq!(titles, ["Count"]);

        let mut generated = collection;
        generated.correlations[0].generate = true;
        let output =
            convert_collection(&PostgresBackend::new(), &generated, &[], "default").unwrap();
        let titles: Vec<_> = output
            .queries
            .iter()
            .map(|result| result.rule_title.as_str())
            .collect();
        assert_eq!(titles, ["Base", "Count"]);
    }
}
