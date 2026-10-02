//! End-to-end checks that value modifiers follow the Sigma specification.
//!
//! Each test compiles a rule into an [`Engine`] and evaluates it against
//! events, so the candidate index and prefilters take part as they do in
//! production.

use rsigma_eval::{Engine, JsonEvent};
use rsigma_parser::parse_sigma_yaml;
use serde_json::{Value, json};

/// Build an engine from a rule whose `detection` block is `detection`.
fn engine(detection: &str) -> Engine {
    let detection = detection
        .lines()
        .map(|l| format!("  {l}"))
        .collect::<Vec<_>>()
        .join("\n");
    let yaml = format!(
        "title: t\nlogsource: {{category: test}}\ndetection:\n{detection}\n  condition: selection\n"
    );
    let collection = parse_sigma_yaml(&yaml).expect("rule parses");
    let mut engine = Engine::new();
    engine.add_collection(&collection).expect("rule compiles");
    engine
}

/// Indexes of the events the rule matches.
fn matching(detection: &str, events: &[Value]) -> Vec<usize> {
    let engine = engine(detection);
    events
        .iter()
        .enumerate()
        .filter(|(_, e)| !engine.evaluate(&JsonEvent::borrow(e)).is_empty())
        .map(|(i, _)| i)
        .collect()
}

#[test]
fn base64offset_ignores_characters_that_depend_on_surrounding_bytes() {
    let events = [
        json!({"Data": "VGVzdGluZw=="}), // "Testing"
        json!({"Data": "eFRlc3Rpbmc="}), // "xTesting"
        json!({"Data": "eHhUZXN0aW5n"}), // "xxTesting"
        json!({"Data": "QVRlc3Qh"}),     // "ATest!"
        json!({"Data": "VGVzbGE="}),     // "Tesla"
    ];
    assert_eq!(
        matching("selection:\n  Data|base64offset|contains: Test", &events),
        [0, 1, 2, 3]
    );
}
