//! Rules the parser rejects because pySigma rejects them, and the nearby valid
//! forms it must keep accepting.

use rsigma_parser::parse_sigma_yaml;

fn rule_with_detection(detection: &str) -> String {
    format!("title: T\nlogsource:\n    category: test\ndetection:\n{detection}\n")
}

fn rule_with_selection(selection: &str) -> String {
    let body: String = selection
        .lines()
        .map(|line| format!("        {line}\n"))
        .collect();
    rule_with_detection(&format!("    sel:\n{body}    condition: sel"))
}

fn parse_error(yaml: &str) -> String {
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert!(
        collection.rules.is_empty(),
        "expected a parse error for:\n{yaml}"
    );
    collection.errors.join("\n")
}

fn assert_parses(yaml: &str) {
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert!(
        collection.errors.is_empty() && collection.rules.len() == 1,
        "expected a clean parse for:\n{yaml}\nerrors: {:?}",
        collection.errors
    );
}

#[test]
fn rejects_modifiers_on_values_of_the_wrong_type() {
    for (selection, expected) in [
        (
            "F|contains: 5",
            "field 'F': |contains requires a string value, got 5",
        ),
        ("F|cased: 5", "|cased requires a string value"),
        ("F|expand: 5", "|expand requires a string value"),
        ("F|fieldref: 5", "|fieldref requires a string value"),
        ("F|windash: 5", "|windash requires a string value"),
        ("F|re: 5", "|re requires a string value"),
        (
            "F|startswith: true",
            "|startswith requires a string value, got true",
        ),
        (
            "F|endswith: null",
            "|endswith requires a string value, got null",
        ),
        ("F|gt: abc", "|gt requires a numeric value, got 'abc'"),
        ("F|lte: null", "|lte requires a numeric value"),
        ("F|minute: x", "|minute requires a numeric value, got 'x'"),
    ] {
        let err = parse_error(&rule_with_selection(selection));
        assert!(err.contains(expected), "{selection}: {err}");
    }
}

#[test]
fn rejects_invalid_values() {
    for (selection, expected) in [
        ("F|base64: 'a*'", "do not support wildcards"),
        ("F|base64offset|contains: 'a?b'", "do not support wildcards"),
        ("F|cidr: 10.1.2.3/8", "host bits set"),
        ("F|cidr: not-a-network", "expected address/prefix"),
        ("F|re: 'a(b'", "invalid regular expression"),
        ("F|re: '[z-a]'", "invalid regular expression"),
        ("F|fieldref: 'Other*'", "must not contain wildcards"),
        ("F|wide: 'é'", "require an ASCII value"),
        ("F|exists: maybe", "|exists takes a single boolean value"),
        ("F|exists: 'yes'", "|exists takes a single boolean value"),
        ("F|exists: 'true'", "|exists takes a single boolean value"),
        ("F|exists: no", "|exists takes a single boolean value"),
        (
            "F|exists: [true, false]",
            "|exists takes a single boolean value",
        ),
        ("'|exists': true", "|exists must be applied to a field"),
        ("F: {a: b}", "'F' takes a value or a list of values"),
        ("F: [[a, b]]", "'F' takes a value or a list of values"),
    ] {
        let err = parse_error(&rule_with_selection(selection));
        assert!(err.contains(expected), "{selection}: {err}");
    }
}

#[test]
fn rejects_conflicting_modifiers() {
    for (selection, expected) in [
        (
            "F|lt|gt: 5",
            "at most one operator may be set per field; got |gt, |lt",
        ),
        ("F|contains|re: x", "got |contains, |re"),
        ("F|contains|cidr: 10.0.0.0/8", "got |contains, |cidr"),
        ("F|i: x", "have no effect without |re"),
        ("F|contains|m: x", "|m have no effect without |re"),
        ("F|contains|fieldref: G", "|contains must follow |fieldref"),
        (
            "F|base64|base64offset: x",
            "mutually exclusive base64 strategies",
        ),
        ("F|wide|utf16: x", "mutually exclusive UTF-16 encodings"),
        ("F|windash|gt: 5", "value transformations |windash"),
        ("F|contains|all: x", "|all requires more than one value"),
    ] {
        let err = parse_error(&rule_with_selection(selection));
        assert!(
            err.contains("Invalid modifier combination") && err.contains(expected),
            "{selection}: {err}"
        );
    }
}

#[test]
fn rejects_invalid_detections() {
    for (detection, expected) in [
        ("    sel: {}\n    condition: sel", "'sel' is empty"),
        ("    sel: []\n    condition: sel", "'sel' is empty"),
        (
            "    kw:\n        - null\n    condition: kw",
            "'kw' uses null as a keyword",
        ),
        ("    kw:\n    condition: kw", "'kw' uses null as a keyword"),
        (
            "    sel:\n        - - a\n          - b\n    condition: sel",
            "must not contain nested lists",
        ),
        (
            "    sel:\n        F: x\n    condition: sel and other",
            "condition references unknown detection identifier 'other'",
        ),
        (
            "    sel:\n        F: x\n    condition: 1 of filter_*",
            "selector '1 of filter_*' matches no detection identifier",
        ),
        (
            "    _hidden:\n        F: x\n    condition: all of them",
            "selector 'all of them' matches no detection identifier",
        ),
    ] {
        let err = parse_error(&rule_with_detection(detection));
        assert!(err.contains(expected), "{detection}: {err}");
    }
}

#[test]
fn checks_conditions_inside_extended_array_blocks() {
    let yaml = "title: T\nsigma-version: 3\nlogsource:\n    category: test\ndetection:\n    sel:\n        conns[any]:\n            a:\n                port: 80\n            condition: a and b\n    condition: sel\n";
    let err = parse_error(yaml);
    assert!(err.contains("unknown detection identifier 'b'"), "{err}");
}

#[test]
fn accepts_valid_neighbors() {
    for selection in [
        "F|re: '(?<!\\\\)cmd'",
        "F|re: '(a)\\1'",
        "F|re|i: '^cmd$'",
        "F|gt: '5'",
        "F|gte: 1.5",
        "F|hour: '3'",
        "F|cidr: 2001:db8::/32",
        "F|exists: true",
        "F|exists: false",
        "F|contains|all: [a, b]",
        "F|fieldref|contains: G",
        "F|cased: abc",
        "F|base64: 'a\\*b'",
        "F|wide|base64: 'é'",
        "F: 5",
        "F: [a, null]",
        "F: []",
        "F|neq: [1, 2]",
        "F|expand: '%admins%'",
    ] {
        assert_parses(&rule_with_selection(selection));
    }
    for detection in [
        "    kw:\n        - foo\n        - 5\n    condition: kw",
        "    sel:\n        - F: a\n        - G: b\n    condition: sel",
        "    sel_a:\n        F: x\n    _hidden:\n        G: y\n    condition: 1 of sel_* and not 1 of _hid*",
    ] {
        assert_parses(&rule_with_detection(detection));
    }
}

#[test]
fn filter_rules_are_validated() {
    let yaml = "title: F\nlogsource:\n    category: test\nfilter:\n    rules: any\n    sel:\n        F|contains: 5\n    condition: not sel\n";
    let err = parse_error_any(yaml);
    assert!(err.contains("|contains requires a string value"), "{err}");

    let yaml = "title: F\nlogsource:\n    category: test\nfilter:\n    rules: any\n    sel:\n        F: x\n    condition: not other\n";
    let err = parse_error_any(yaml);
    assert!(
        err.contains("unknown detection identifier 'other'"),
        "{err}"
    );
}

fn parse_error_any(yaml: &str) -> String {
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert!(collection.is_empty(), "expected a parse error for:\n{yaml}");
    collection.errors.join("\n")
}
