//! End-to-end checks that keyword detections and condition selectors follow
//! the Sigma specification.
//!
//! Each test compiles a rule into an [`Engine`] and evaluates it against
//! events, so the candidate index and prefilters take part as they do in
//! production.

use rsigma_eval::{Engine, JsonEvent};
use rsigma_parser::parse_sigma_yaml;
use serde_json::{Value, json};

/// Compile a rule whose `detection` block (including its condition) is
/// `detection`.
fn try_engine(detection: &str) -> Result<Engine, String> {
    let detection = detection
        .lines()
        .map(|l| format!("  {l}"))
        .collect::<Vec<_>>()
        .join("\n");
    let yaml = format!("title: t\nlogsource: {{category: test}}\ndetection:\n{detection}\n");
    let collection = parse_sigma_yaml(&yaml).map_err(|e| e.to_string())?;
    if let Some(error) = collection.errors.first() {
        return Err(error.clone());
    }
    let mut engine = Engine::new();
    engine
        .add_collection(&collection)
        .map_err(|e| e.to_string())?;
    Ok(engine)
}

/// Indexes of the events the rule matches.
fn matching(detection: &str, events: &[Value]) -> Vec<usize> {
    let engine = try_engine(detection).expect("rule compiles");
    events
        .iter()
        .enumerate()
        .filter(|(_, e)| !engine.evaluate(&JsonEvent::borrow(e)).is_empty())
        .map(|(i, _)| i)
        .collect()
}

#[test]
fn numeric_keywords_match_numbers_and_their_decimal_text() {
    let detection = "keywords:\n  - 4624\ncondition: keywords";
    let events = [
        json!({"EventID": 4624}),
        json!({"Message": "logon 4624 succeeded"}),
        json!({"Nested": {"Codes": [1, 46240]}}),
        json!({"EventID": 4625}),
        json!({"EventID": "4688"}),
    ];
    assert_eq!(matching(detection, &events), vec![0, 1, 2]);

    let detection = "keywords:\n  - 1.5\ncondition: keywords";
    let events = [json!({"Ratio": 1.5}), json!({"Ratio": 2.5})];
    assert_eq!(matching(detection, &events), vec![0]);
}
