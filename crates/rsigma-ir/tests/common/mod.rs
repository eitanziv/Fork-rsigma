//! Shared helpers for IR fixture tests.
//!
//! Prefer [`compiled_from`] + [`rule_matches`] for pure condition/matcher
//! semantics. [`engine_from`] goes through [`Engine`] indices/prefilters and
//! can drop rules whose unused detections constrain the index.

// Each integration test binary includes this module but uses a subset of helpers.
#![allow(dead_code)]

use rsigma_eval::{CompiledRule, Engine, EvaluationResult, JsonEvent, compile_rule, evaluate_rule};
use rsigma_parser::{CorrelationRule, FilterRule, SigmaCollection, SigmaRule, parse_sigma_yaml};
use serde_json::Value;

/// Parse a full Sigma collection (rules + correlations + filters).
pub fn collection_from(yaml: &str) -> SigmaCollection {
    parse_sigma_yaml(yaml).expect("fixture YAML must parse")
}

/// Parse the first detection rule from a YAML fixture.
pub fn rule_from(yaml: &str) -> SigmaRule {
    collection_from(yaml)
        .rules
        .into_iter()
        .next()
        .expect("fixture must contain a detection rule")
}

/// Parse the first correlation rule from a YAML fixture.
pub fn correlation_from(yaml: &str) -> CorrelationRule {
    collection_from(yaml)
        .correlations
        .into_iter()
        .next()
        .expect("fixture must contain a correlation rule")
}

/// Parse the first filter rule from a YAML fixture.
pub fn filter_from(yaml: &str) -> FilterRule {
    collection_from(yaml)
        .filters
        .into_iter()
        .next()
        .expect("fixture must contain a filter rule")
}

/// Compile via the legacy [`compile_rule`] path (no engine indices).
pub fn compiled_from(yaml: &str) -> CompiledRule {
    compile_rule(&rule_from(yaml)).expect("fixture must compile on the legacy path")
}

/// Parse YAML and load into an [`Engine`] (includes rule index / bloom).
pub fn engine_from(yaml: &str) -> Engine {
    let collection = parse_sigma_yaml(yaml).expect("fixture YAML must parse");
    let mut engine = Engine::new();
    engine
        .add_collection(&collection)
        .expect("fixture must compile on the legacy path");
    engine
}

/// Attempt to compile; used by contradiction fixtures that expect Err.
pub fn try_compile(yaml: &str) -> Result<(), rsigma_eval::EvalError> {
    let collection = parse_sigma_yaml(yaml).expect("fixture YAML must parse");
    Engine::new().add_collection(&collection)
}

/// Sorted matching rule titles for stable assertions.
pub fn sorted_titles(results: Vec<EvaluationResult>) -> Vec<String> {
    let mut titles: Vec<String> = results.into_iter().map(|m| m.header.rule_title).collect();
    titles.sort();
    titles
}

/// Whether [`evaluate_rule`] produces a match (bypasses engine prefilters).
pub fn rule_matches(rule: &CompiledRule, event: &Value) -> bool {
    evaluate_rule(rule, &JsonEvent::borrow(event)).is_some()
}

/// Whether the engine produces at least one match for `event`.
pub fn matches(engine: &Engine, event: &Value) -> bool {
    !engine.evaluate(&JsonEvent::borrow(event)).is_empty()
}

/// Matching titles for one event via the engine.
pub fn titles_for(engine: &Engine, event: &Value) -> Vec<String> {
    sorted_titles(engine.evaluate(&JsonEvent::borrow(event)))
}
