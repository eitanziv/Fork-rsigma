//! End-to-end tests for the gated match-detail enrichment.
//!
//! Exercises `Engine::set_match_detail` across `Off` / `Summary` / `Full`,
//! pinning the three behaviors that motivated the feature:
//!
//! 1. `Off` is byte-for-byte the historical shape (field + value only, no
//!    keyword or absence entries).
//! 2. `Summary` attaches the selection, matcher kind, and case sensitivity,
//!    and reports the previously dropped keyword match.
//! 3. `Full` additionally records the matched pattern.

use rsigma_eval::event::JsonEvent;
use rsigma_eval::{Engine, Event, MatchDetailLevel, MatcherKind};
use rsigma_parser::parse_sigma_yaml;
use serde_json::json;

const RULE: &str = r#"
title: PS Encoded
id: ps-enc
logsource:
    product: windows
    category: process_creation
detection:
    selection_img:
        Image|endswith: \powershell.exe
    selection_args:
        CommandLine|contains: -enc
    keywords:
        - FromBase64String
    condition: selection_img and selection_args and keywords
level: high
"#;

fn engine_at(level: MatchDetailLevel) -> Engine {
    let collection = parse_sigma_yaml(RULE).unwrap();
    let mut engine = Engine::new();
    engine.set_match_detail(level);
    engine.add_collection(&collection).unwrap();
    engine
}

fn matching_event() -> serde_json::Value {
    json!({
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell -nop -enc ZWNobwo= ; FromBase64String(x)"
    })
}

#[test]
fn off_level_preserves_historical_shape() {
    let engine = engine_at(MatchDetailLevel::Off);
    let ev = matching_event();
    let results = engine.evaluate(&JsonEvent::borrow(&ev));
    assert_eq!(results.len(), 1);

    let det = results[0].as_detection().unwrap();
    // Only the two field selections contribute; the keyword selection does
    // not, matching pre-enrichment behavior.
    assert_eq!(det.matched_fields.len(), 2);
    for fm in &det.matched_fields {
        assert!(fm.selection.is_none());
        assert!(fm.matcher.is_none());
        assert!(fm.pattern.is_none());
        assert!(fm.case_sensitive.is_none());
        assert!(!fm.negated);
    }
    let fields: Vec<&str> = det
        .matched_fields
        .iter()
        .map(|f| f.field.as_str())
        .collect();
    assert!(fields.contains(&"Image"));
    assert!(fields.contains(&"CommandLine"));
}

#[test]
fn summary_level_adds_descriptor_and_keyword_entry() {
    let engine = engine_at(MatchDetailLevel::Summary);
    let ev = matching_event();
    let results = engine.evaluate(&JsonEvent::borrow(&ev));
    assert_eq!(results.len(), 1);
    let det = results[0].as_detection().unwrap();

    let cmd = det
        .matched_fields
        .iter()
        .find(|f| f.field == "CommandLine")
        .expect("CommandLine match present");
    assert_eq!(cmd.selection.as_deref(), Some("selection_args"));
    assert_eq!(cmd.matcher, Some(MatcherKind::Contains));
    assert_eq!(cmd.case_sensitive, Some(false));
    // Summary withholds the pattern.
    assert!(cmd.pattern.is_none());

    // The keyword match, dropped entirely at Off, now appears.
    let kw = det
        .matched_fields
        .iter()
        .find(|f| f.matcher == Some(MatcherKind::Keyword))
        .expect("keyword match present");
    assert_eq!(kw.field, "keyword");
    assert_eq!(kw.selection.as_deref(), Some("keywords"));
}

#[test]
fn full_level_records_pattern() {
    let engine = engine_at(MatchDetailLevel::Full);
    let ev = matching_event();
    let results = engine.evaluate(&JsonEvent::borrow(&ev));
    let det = results[0].as_detection().unwrap();

    let cmd = det
        .matched_fields
        .iter()
        .find(|f| f.field == "CommandLine")
        .expect("CommandLine match present");
    assert_eq!(cmd.pattern.as_deref(), Some("-enc"));

    let img = det
        .matched_fields
        .iter()
        .find(|f| f.field == "Image")
        .expect("Image match present");
    assert_eq!(img.matcher, Some(MatcherKind::EndsWith));
    assert_eq!(img.pattern.as_deref(), Some("\\powershell.exe"));
}

const NULL_RULE: &str = r#"
title: Missing Image
id: missing-image
logsource:
    category: process_creation
detection:
    selection:
        Image: null
    condition: selection
level: low
"#;

#[test]
fn null_on_absent_field_is_gated_by_level() {
    let collection = parse_sigma_yaml(NULL_RULE).unwrap();
    let ev = json!({ "CommandLine": "whoami" });

    // Off: the absence match fires the rule but records no field entry.
    let mut off = Engine::new();
    off.add_collection(&collection).unwrap();
    let off_res = off.evaluate(&JsonEvent::borrow(&ev));
    assert_eq!(off_res.len(), 1);
    assert!(off_res[0].as_detection().unwrap().matched_fields.is_empty());

    // Summary: the absence match is reported with a null value.
    let mut summary = Engine::new();
    summary.set_match_detail(MatchDetailLevel::Summary);
    summary.add_collection(&collection).unwrap();
    let sum_res = summary.evaluate(&JsonEvent::borrow(&ev));
    let det = sum_res[0].as_detection().unwrap();
    assert_eq!(det.matched_fields.len(), 1);
    let fm = &det.matched_fields[0];
    assert_eq!(fm.field, "Image");
    assert!(fm.value.is_null());
    assert_eq!(fm.matcher, Some(MatcherKind::Null));
}

#[test]
fn keyword_all_reports_the_value_each_term_matched() {
    let yaml = r#"
title: Reverse Shell
logsource:
    product: linux
detection:
    keywords:
        '|all':
            - 'bash -c'
            - '/dev/tcp/'
    condition: keywords
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = Engine::new();
    engine.set_match_detail(MatchDetailLevel::Summary);
    engine.add_collection(&collection).unwrap();
    let ev = json!({ "Image": "/bin/bash -c", "CommandLine": "cat < /dev/tcp/host/80" });
    let results = engine.evaluate(&JsonEvent::borrow(&ev));
    let det = results[0].as_detection().unwrap();
    let mut values: Vec<&str> = det
        .matched_fields
        .iter()
        .filter(|f| f.matcher == Some(MatcherKind::Keyword))
        .map(|f| f.value.as_str().unwrap())
        .collect();
    values.sort();
    assert_eq!(values, ["/bin/bash -c", "cat < /dev/tcp/host/80"]);
}

fn array_engine(yaml: &str, level: MatchDetailLevel) -> Engine {
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = Engine::new();
    engine.set_match_detail(level);
    engine.add_collection(&collection).unwrap();
    engine
}

const ARRAY_ANY: &str = r#"
title: Array Any
sigma-version: 3
logsource: {category: test}
detection:
    selection:
        connections[any]:
            protocol: 'TCP'
            ip|cidr: '123.1.0.0/16'
    condition: selection
"#;

#[test]
fn array_any_records_only_binding_members_with_indexed_paths() {
    let engine = array_engine(ARRAY_ANY, MatchDetailLevel::Off);
    let ev = json!({"connections": [
        {"protocol": "UDP", "ip": "10.0.0.1"},
        {"protocol": "TCP", "ip": "123.1.9.9"}
    ]});
    let results = engine.evaluate(&JsonEvent::borrow(&ev));
    let det = results[0].as_detection().unwrap();
    let fields: Vec<&str> = det
        .matched_fields
        .iter()
        .map(|f| f.field.as_str())
        .collect();
    assert!(fields.contains(&"connections[1].protocol"));
    assert!(fields.contains(&"connections[1].ip"));
    assert!(!fields.iter().any(|f| f.starts_with("connections[0]")));
    for fm in &det.matched_fields {
        assert!(fm.selection.is_none());
        assert!(fm.matcher.is_none());
        let resolved = JsonEvent::borrow(&ev)
            .get_field(&fm.field)
            .expect("indexed path must resolve")
            .to_json();
        assert_eq!(resolved, fm.value);
    }
}

#[test]
fn array_all_records_every_member_up_to_cap() {
    let yaml = r#"
title: Array All
sigma-version: 3
logsource: {category: test}
detection:
    selection:
        connections[all]:
            protocol: 'TCP'
    condition: selection
"#;
    let engine = array_engine(yaml, MatchDetailLevel::Off);
    let ev = json!({"connections": [{"protocol": "TCP"}, {"protocol": "TCP"}]});
    let results = engine.evaluate(&JsonEvent::borrow(&ev));
    let det = results[0].as_detection().unwrap();
    let fields: Vec<&str> = det
        .matched_fields
        .iter()
        .map(|f| f.field.as_str())
        .collect();
    assert_eq!(
        fields,
        vec!["connections[0].protocol", "connections[1].protocol"]
    );
}

#[test]
fn array_none_and_vacuous_all_or_empty_keep_container() {
    let none = r#"
title: None
sigma-version: 3
logsource: {category: test}
detection:
    selection:
        connections[none]:
            protocol: 'TCP'
    condition: selection
"#;
    let vacuous = r#"
title: Vacuous
sigma-version: 3
logsource: {category: test}
detection:
    selection:
        connections[all_or_empty]:
            protocol: 'TCP'
    condition: selection
"#;
    let none_ev = json!({"connections": [{"protocol": "UDP"}]});
    let empty_ev = json!({"connections": []});

    let none_det = array_engine(none, MatchDetailLevel::Off).evaluate(&JsonEvent::borrow(&none_ev));
    assert_eq!(none_det[0].as_detection().unwrap().matched_fields.len(), 1);
    assert_eq!(
        none_det[0].as_detection().unwrap().matched_fields[0].field,
        "connections"
    );

    let vacuous_det =
        array_engine(vacuous, MatchDetailLevel::Off).evaluate(&JsonEvent::borrow(&empty_ev));
    assert_eq!(
        vacuous_det[0].as_detection().unwrap().matched_fields.len(),
        1
    );
    assert_eq!(
        vacuous_det[0].as_detection().unwrap().matched_fields[0].field,
        "connections"
    );
}

#[test]
fn array_summary_adds_descriptor_on_indexed_paths() {
    let engine = array_engine(ARRAY_ANY, MatchDetailLevel::Summary);
    let ev = json!({"connections": [{"protocol": "TCP", "ip": "123.1.9.9"}]});
    let results = engine.evaluate(&JsonEvent::borrow(&ev));
    let det = results[0].as_detection().unwrap();
    assert!(
        det.matched_fields
            .iter()
            .all(|f| f.selection.as_deref() == Some("selection"))
    );
    assert!(det.matched_fields.iter().any(|f| f.matcher.is_some()));
}

#[test]
fn array_scalar_records_unindexed_path() {
    let engine = array_engine(ARRAY_ANY, MatchDetailLevel::Off);
    let ev = json!({"connections": {"protocol": "TCP", "ip": "123.1.9.9"}});
    let results = engine.evaluate(&JsonEvent::borrow(&ev));
    let det = results[0].as_detection().unwrap();
    let fields: Vec<&str> = det
        .matched_fields
        .iter()
        .map(|f| f.field.as_str())
        .collect();
    assert!(fields.contains(&"connections.protocol"));
    assert!(fields.contains(&"connections.ip"));
    assert!(!fields.iter().any(|f| f.contains('[')));
    for fm in &det.matched_fields {
        let resolved = JsonEvent::borrow(&ev)
            .get_field(&fm.field)
            .expect("scalar path must resolve")
            .to_json();
        assert_eq!(resolved, fm.value);
    }
}

#[test]
fn array_nested_records_inner_indexed_paths() {
    let yaml = r#"
title: Nested
sigma-version: 3
logsource: {category: test}
detection:
    selection:
        rules[any]:
            type: 'allow'
            ip[all]|startswith: '123.1.1'
    condition: selection
"#;
    let engine = array_engine(yaml, MatchDetailLevel::Off);
    let ev = json!({"rules": [{"type": "allow", "ip": ["123.1.1.1", "123.1.1.2"]}]});
    let results = engine.evaluate(&JsonEvent::borrow(&ev));
    let det = results[0].as_detection().unwrap();
    let fields: Vec<&str> = det
        .matched_fields
        .iter()
        .map(|f| f.field.as_str())
        .collect();
    assert!(fields.contains(&"rules[0].type"));
    assert!(fields.contains(&"rules[0].ip[0]"));
    assert!(fields.contains(&"rules[0].ip[1]"));
    for fm in &det.matched_fields {
        let resolved = JsonEvent::borrow(&ev)
            .get_field(&fm.field)
            .expect("nested indexed path must resolve")
            .to_json();
        assert_eq!(resolved, fm.value);
    }
}

#[test]
fn array_all_caps_recorded_members_at_32() {
    let yaml = r#"
title: Cap
sigma-version: 3
logsource: {category: test}
detection:
    selection:
        connections[all]:
            protocol: 'TCP'
    condition: selection
"#;
    let members: Vec<serde_json::Value> = (0..40).map(|_| json!({"protocol": "TCP"})).collect();
    let ev = json!({"connections": members});
    let results = array_engine(yaml, MatchDetailLevel::Off).evaluate(&JsonEvent::borrow(&ev));
    let det = results[0].as_detection().unwrap();
    assert_eq!(det.matched_fields.len(), 32);
    assert_eq!(det.matched_fields[0].field, "connections[0].protocol");
    assert_eq!(det.matched_fields[31].field, "connections[31].protocol");
}

#[test]
fn array_keywords_body_gated_by_detail_level() {
    let yaml = r#"
title: Keyword Body
sigma-version: 3
logsource: {category: test}
detection:
    selection:
        tags[any]:
            - suspicious
    condition: selection
"#;
    let ev = json!({"tags": ["ok", "suspicious"]});
    let off = array_engine(yaml, MatchDetailLevel::Off).evaluate(&JsonEvent::borrow(&ev));
    let off_fields: Vec<&str> = off[0]
        .as_detection()
        .unwrap()
        .matched_fields
        .iter()
        .map(|f| f.field.as_str())
        .collect();
    // A list body is AllOf-of-keyword-items or Keywords; at Off, keyword
    // detections historically emit nothing. Element-self items still emit.
    let summary = array_engine(yaml, MatchDetailLevel::Summary).evaluate(&JsonEvent::borrow(&ev));
    let sum_fields: Vec<&str> = summary[0]
        .as_detection()
        .unwrap()
        .matched_fields
        .iter()
        .map(|f| f.field.as_str())
        .collect();
    // A plain list body compiles to element-self items (a value match on the
    // member itself, not a keyword search), so the binding member is reported
    // at every level, including Off, with its resolvable indexed path.
    assert_eq!(off_fields, vec!["tags[1]"], "off fields: {off_fields:?}");
    assert!(
        sum_fields.contains(&"tags[1]"),
        "summary fields: {sum_fields:?}"
    );
}

#[test]
fn array_member_fallback_respects_off_gating() {
    // The binding member matches only via a Null-on-absent item. Top-level
    // selections suppress those at Off; the member fallback must too.
    let yaml = r#"
title: Null Absent Body
sigma-version: 3
logsource: {category: test}
detection:
    selection:
        connections[any]:
            legacy_flag: null
    condition: selection
"#;
    let ev = json!({"connections": [{"protocol": "TCP"}]});
    let off = array_engine(yaml, MatchDetailLevel::Off).evaluate(&JsonEvent::borrow(&ev));
    let det = off[0].as_detection().unwrap();
    assert!(det.matched_fields.is_empty(), "{:?}", det.matched_fields);

    let summary = array_engine(yaml, MatchDetailLevel::Summary).evaluate(&JsonEvent::borrow(&ev));
    let det = summary[0].as_detection().unwrap();
    let fields: Vec<&str> = det
        .matched_fields
        .iter()
        .map(|f| f.field.as_str())
        .collect();
    assert!(
        fields.contains(&"connections[0].legacy_flag"),
        "summary fields: {fields:?}"
    );
}

#[test]
fn exists_false_on_absent_field_reported_above_off() {
    // Flat-selection analogue of the array-body exists handling: an
    // `|exists: false` match on an absent field is suppressed at Off and
    // reported with a null value above it.
    let yaml = r#"
title: Exists False
sigma-version: 3
logsource: {category: test}
detection:
    selection:
        sandbox|exists: false
        protocol: 'TCP'
    condition: selection
"#;
    let ev = json!({"protocol": "TCP"});
    let off = array_engine(yaml, MatchDetailLevel::Off).evaluate(&JsonEvent::borrow(&ev));
    let det = off[0].as_detection().unwrap();
    let off_fields: Vec<&str> = det
        .matched_fields
        .iter()
        .map(|f| f.field.as_str())
        .collect();
    assert_eq!(off_fields, vec!["protocol"]);

    let summary = array_engine(yaml, MatchDetailLevel::Summary).evaluate(&JsonEvent::borrow(&ev));
    let det = summary[0].as_detection().unwrap();
    let sandbox = det
        .matched_fields
        .iter()
        .find(|f| f.field == "sandbox")
        .expect("exists:false entry");
    assert_eq!(sandbox.value, serde_json::Value::Null);
}
