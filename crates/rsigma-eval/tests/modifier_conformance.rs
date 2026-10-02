//! End-to-end checks that value modifiers follow the Sigma specification.
//!
//! Each test compiles a rule into an [`Engine`] and evaluates it against
//! events, so the candidate index and prefilters take part as they do in
//! production.

use rsigma_eval::{Engine, JsonEvent, parse_pipeline};
use rsigma_parser::parse_sigma_yaml;
use serde_json::{Value, json};

/// Compile a rule whose `detection` block is `detection`.
fn try_engine(detection: &str) -> Result<Engine, String> {
    try_engine_with(detection, None)
}

fn try_engine_with(detection: &str, pipeline: Option<&str>) -> Result<Engine, String> {
    let detection = detection
        .lines()
        .map(|l| format!("  {l}"))
        .collect::<Vec<_>>()
        .join("\n");
    let yaml = format!(
        "title: t\nlogsource: {{category: test}}\ndetection:\n{detection}\n  condition: selection\n"
    );
    let collection = parse_sigma_yaml(&yaml).map_err(|e| e.to_string())?;
    let mut engine = Engine::new();
    if let Some(pipeline) = pipeline {
        engine.add_pipeline(parse_pipeline(pipeline).map_err(|e| e.to_string())?);
    }
    engine
        .add_collection(&collection)
        .map_err(|e| e.to_string())?;
    Ok(engine)
}

/// The compile error for a rule that must be rejected.
fn rejection(detection: &str) -> String {
    match try_engine(detection) {
        Ok(_) => panic!("rule should be rejected:\n{detection}"),
        Err(e) => e,
    }
}

/// Indexes of the events the rule matches.
fn matching(detection: &str, events: &[Value]) -> Vec<usize> {
    matching_with(detection, None, events)
}

/// Indexes of the events the rule matches after `pipeline` is applied.
fn matching_with(detection: &str, pipeline: Option<&str>, events: &[Value]) -> Vec<usize> {
    let engine = try_engine_with(detection, pipeline).expect("rule compiles");
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

#[test]
fn windash_treats_every_dash_character_in_the_value_as_interchangeable() {
    let events = [
        json!({"CommandLine": "taskkill /f /im x.exe"}),
        json!({"CommandLine": "taskkill -f -im x.exe"}),
        json!({"CommandLine": "taskkill \u{2013}f \u{2014}im x.exe"}),
        json!({"CommandLine": "taskkill \u{2015}f /im x.exe"}),
        json!({"CommandLine": "taskkill /fim x.exe"}),
        json!({"CommandLine": "taskkill +f +im x.exe"}),
    ];
    assert_eq!(
        matching(
            "selection:\n  CommandLine|windash|contains: ' /f /im '",
            &events
        ),
        [0, 1, 2, 3]
    );
    assert_eq!(
        matching(
            "selection:\n  CommandLine|windash|contains: ' \u{2013}f -im '",
            &events
        ),
        [0, 1, 2, 3]
    );
}

#[test]
fn windash_keeps_wildcards() {
    let events = [
        json!({"CommandLine": "cmd /c dir C:\\ /s"}),
        json!({"CommandLine": "cmd /c DIR c:\\users -s /b"}),
        json!({"CommandLine": "cmd /c dir* -x"}),
        json!({"CommandLine": "dir*-s"}),
    ];
    assert_eq!(
        matching(
            "selection:\n  CommandLine|windash|contains: 'dir*-s'",
            &events
        ),
        [0, 1, 3]
    );
}

#[test]
fn utf16_modifiers_without_base64_match_the_encoded_string() {
    let events = [
        json!({"Data": "c\u{0}m\u{0}d\u{0}"}),
        json!({"Data": "\u{0}c\u{0}m\u{0}d"}),
        json!({"Data": "\u{feff}c\u{0}m\u{0}d\u{0}"}),
        json!({"Data": "cmd"}),
        json!({"Data": "x\u{0}c\u{0}M\u{0}d\u{0}.\u{0}"}),
    ];
    assert_eq!(
        matching("selection:\n  Data|wide|contains: cmd", &events),
        [0, 2, 4]
    );
    assert_eq!(matching("selection:\n  Data|wide: cmd", &events), [0]);
    assert_eq!(matching("selection:\n  Data|utf16be: cmd", &events), [1]);
    assert_eq!(
        matching("selection:\n  Data|utf16|startswith: cmd", &events),
        [2]
    );
}

#[test]
fn utf16_modifiers_keep_wildcards() {
    let events = [
        json!({"Data": "c\u{0}x\u{0}y\u{0}d\u{0}"}),
        json!({"Data": "c\u{0}d\u{0}"}),
        json!({"Data": "cxd"}),
    ];
    assert_eq!(matching("selection:\n  Data|wide: 'c*d'", &events), [0, 1]);
    assert_eq!(
        matching("selection:\n  Data|wide: 'c?d'", &events),
        Vec::<usize>::new()
    );
}

#[test]
fn base64_rejects_wildcards() {
    for m in [
        "base64",
        "base64offset|contains",
        "wide|base64offset|contains",
    ] {
        let err = rejection(&format!("selection:\n  Data|{m}: 'a*b'"));
        assert!(err.contains("do not support wildcards"), "{m}: {err}");
    }
    let events = [json!({"Data": "YSpi"})]; // "a*b"
    assert_eq!(matching("selection:\n  Data|base64: 'a\\*b'", &events), [0]);
}

#[test]
fn utf16_modifiers_without_base64_reject_non_ascii_values() {
    let err = rejection("selection:\n  Data|wide|contains: 'caf\u{e9}'");
    assert!(err.contains("require an ASCII value"), "{err}");
    let events = [json!({"Data": "YwBhAGYA6QA="})]; // "café" in UTF-16LE
    assert_eq!(
        matching("selection:\n  Data|wide|base64: 'caf\u{e9}'", &events),
        [0]
    );
}

#[test]
fn windash_applies_before_base64() {
    let events = [
        json!({"Data": "LWVuYw=="}), // "-enc"
        json!({"Data": "L2VuYw=="}), // "/enc"
    ];
    assert_eq!(
        matching("selection:\n  Data|windash|base64: '-enc'", &events),
        [0, 1]
    );
}

#[test]
fn expand_resolved_by_a_pipeline_honors_the_operator_and_wildcards() {
    let pipeline = "name: p\nvars:\n  x: [ab]\ntransformations:\n  - type: value_placeholders\n";
    let events = [
        json!({"F": "zabz"}),
        json!({"F": "ab"}),
        json!({"F": "AB"}),
        json!({"F": "a b"}),
    ];
    assert_eq!(
        matching_with(
            "selection:\n  F|contains|expand: '%x%'",
            Some(pipeline),
            &events
        ),
        [0, 1, 2]
    );
    assert_eq!(
        matching_with(
            "selection:\n  F|endswith|expand: 'z%x%'",
            Some(pipeline),
            &events
        ),
        Vec::<usize>::new()
    );
    assert_eq!(
        matching_with(
            "selection:\n  F|expand|cased: '%x%'",
            Some(pipeline),
            &events
        ),
        [1]
    );

    let pipeline = "name: p\ntransformations:\n  - type: wildcard_placeholders\n";
    let events = [
        json!({"F": "xyz"}),
        json!({"F": "x"}),
        json!({"F": "x*"}),
        json!({"F": "yx"}),
    ];
    assert_eq!(
        matching_with("selection:\n  F|expand: 'x%any%'", Some(pipeline), &events),
        [0, 1, 2]
    );
}

#[test]
fn expand_fills_unresolved_placeholders_from_event_fields_with_the_operator() {
    let events = [
        json!({"F": "hello bob!", "user": "bob"}),
        json!({"F": "bob", "user": "bob"}),
        json!({"F": "hello BOB", "user": "bob"}),
        json!({"F": "hello alice", "user": "bob"}),
    ];
    assert_eq!(
        matching("selection:\n  F|contains|expand: '%user%'", &events),
        [0, 1, 2]
    );
    assert_eq!(
        matching("selection:\n  F|startswith|expand: '%user%'", &events),
        [1]
    );
    assert_eq!(
        matching("selection:\n  F|endswith|cased|expand: ' %user%'", &events),
        Vec::<usize>::new()
    );
    assert_eq!(matching("selection:\n  F|expand: '%user%'", &events), [1]);
}

#[test]
fn expand_treats_escaped_percent_as_a_literal() {
    let events = [
        json!({"F": "100%", "user": "x"}),
        json!({"F": "%user%", "user": "x"}),
        json!({"F": "x", "user": "x"}),
    ];
    assert_eq!(matching("selection:\n  F|expand: '100\\%'", &events), [0]);
    assert_eq!(
        matching("selection:\n  F|expand: '\\%user\\%'", &events),
        [1]
    );
    assert_eq!(matching("selection:\n  F|expand: '%user%'", &events), [2]);

    // The specification's own example, and a backslash before a placeholder.
    let events = [
        json!({"F": "%plainbob", "name": "bob", "user": "bob"}),
        json!({"F": "C:\\Users\\bob\\AppData", "user": "bob"}),
        json!({"F": "C:\\Users%user%\\AppData", "user": "bob"}),
    ];
    assert_eq!(
        matching("selection:\n  F|expand: '\\%plain%name%'", &events),
        [0]
    );
    assert_eq!(
        matching(
            "selection:\n  F|expand: 'C:\\Users\\\\%user%\\AppData'",
            &events
        ),
        [1]
    );
    assert_eq!(
        matching(
            "selection:\n  F|expand: 'C:\\Users\\%user%\\AppData'",
            &events
        ),
        [2]
    );
}

#[test]
fn expand_rejects_wildcards_next_to_unresolved_placeholders() {
    let err = rejection("selection:\n  F|expand: '%user%*'");
    assert!(err.contains("cannot be combined with wildcards"), "{err}");
}

#[test]
fn placeholder_pipelines_skip_escaped_percent_and_unresolved_placeholders() {
    let pipeline = "name: p\ntransformations:\n  - type: wildcard_placeholders\n";
    let events = [json!({"F": "%user%"}), json!({"F": "anything"})];
    assert_eq!(
        matching_with(
            "selection:\n  F|expand: '\\%user\\%'",
            Some(pipeline),
            &events
        ),
        [0]
    );

    let pipeline = "name: p\nvars:\n  b: [two]\ntransformations:\n  - type: value_placeholders\n";
    let events = [
        json!({"F": "one-two", "a": "one"}),
        json!({"F": "x-two", "a": "one"}),
    ];
    assert_eq!(
        matching_with("selection:\n  F|expand: '%a%-%b%'", Some(pipeline), &events),
        [0]
    );
}

#[test]
fn exists_checks_presence_and_counts_null_as_present() {
    let events = [
        json!({"User": "admin"}),
        json!({"User": ""}),
        json!({"User": null}),
        json!({"Image": "x"}),
    ];
    assert_eq!(
        matching("selection:\n  User|exists: true", &events),
        [0, 1, 2]
    );
    assert_eq!(matching("selection:\n  User|exists: false", &events), [3]);
}
