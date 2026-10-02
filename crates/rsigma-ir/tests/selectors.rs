//! Mandatory selector fixtures.
//!
//! Common Sigma regression points:
//! - a selector over zero matching detection names is a compile error
//! - `them` and patterns not starting with `_` skip `_`-prefixed names
//! - patterns starting with `_` match `_`-prefixed names

mod common;

use common::{compiled_from, engine_from, matches, rule_matches, titles_for, try_compile};
use serde_json::json;

// =============================================================================
// Selectors over zero detection names
// =============================================================================

#[test]
fn all_of_zero_matches_is_rejected() {
    // Pattern `selection_*` matches zero detection names (`filter_main` does not).
    let err = try_compile(
        r#"
title: Vacuous All Of Zero
id: vacuous-all-of-zero
logsource:
    category: test
detection:
    filter_main:
        Image: 'notepad.exe'
    condition: all of selection_*
level: low
"#,
    )
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("selector 'all of selection_*' matches no detection identifier"),
        "{err}"
    );
}

#[test]
fn all_of_zero_matches_under_and_is_rejected() {
    let err = try_compile(
        r#"
title: Vacuous All Of Multiple
id: vacuous-all-of-multi
logsource:
    category: test
detection:
    filter_main:
        Image: 'notepad.exe'
    condition: filter_main and all of selection_b*
level: low
"#,
    )
    .unwrap_err();
    assert!(err.to_string().contains("'all of selection_b*'"), "{err}");
}

#[test]
fn nonvacuous_all_of_requires_matching_detection() {
    // Control: `selection_main` matches `selection_*`, so the condition is not vacuous.
    let engine = engine_from(
        r#"
title: Nonvacuous All Of
id: nonvacuous-all-of
logsource:
    category: test
detection:
    selection_main:
        Image: 'notepad.exe'
    condition: all of selection_*
level: low
"#,
    );
    assert!(matches(&engine, &json!({"Image": "notepad.exe"})));
    assert!(!matches(&engine, &json!({"Image": "evil.exe"})));
}

// =============================================================================
// `them` skips `_`-prefixed detection names
// =============================================================================

#[test]
fn them_skips_underscore_prefixed_detection_names() {
    let yaml = r#"
title: Them Skip Prefix
id: them-skip-prefix
logsource:
    category: test
detection:
    selection:
        Image: 'notepad.exe'
    _internal:
        Image: 'evil.exe'
    condition: 1 of them
level: low
"#;
    let rule = compiled_from(yaml);
    // Direct evaluate_rule: proves them-skipping, not engine index pruning.
    assert!(rule_matches(&rule, &json!({"Image": "notepad.exe"})));
    assert!(
        !rule_matches(&rule, &json!({"Image": "evil.exe"})),
        "`them` must skip `_internal` even when that detection matches the event"
    );
    assert!(!rule_matches(&rule, &json!({})));

    let engine = engine_from(yaml);
    assert_eq!(
        titles_for(&engine, &json!({"Image": "notepad.exe"})),
        vec!["Them Skip Prefix".to_string()]
    );
}

#[test]
fn all_of_them_skips_underscore_prefixed_names() {
    let engine = engine_from(
        r#"
title: Them All Skip
id: them-all-skip
logsource:
    category: test
detection:
    selection:
        Image: 'notepad.exe'
    _internal:
        Image: 'evil.exe'
    condition: all of them
level: low
"#,
    );
    assert!(matches(&engine, &json!({"Image": "notepad.exe"})));
    assert!(!matches(&engine, &json!({"Image": "evil.exe"})));
}

#[test]
fn count_of_them_ignores_underscore_prefixed_names() {
    // Only one non-`_` detection exists, so `2 of them` can never match.
    let engine = engine_from(
        r#"
title: Them Count Skip
id: them-count-skip
logsource:
    category: test
detection:
    selection:
        Image: 'notepad.exe'
    _internal:
        Image: 'evil.exe'
    condition: 2 of them
level: low
"#,
    );
    assert!(!matches(&engine, &json!({"Image": "notepad.exe"})));
    assert!(!matches(&engine, &json!({"Image": "evil.exe"})));
}

// =============================================================================
// Patterns starting with `_` match `_`-prefixed names
// =============================================================================

#[test]
fn glob_pattern_matches_underscore_prefixed_detection_name() {
    // A pattern that itself starts with `_` selects `_`-prefixed names.
    let engine = engine_from(
        r#"
title: Glob Matches Underscore
id: glob-underscore
logsource:
    category: test
detection:
    selection_main:
        Image: 'notepad.exe'
    _internal:
        Image: 'evil.exe'
    condition: 1 of _*
level: low
"#,
    );
    assert!(!matches(&engine, &json!({"Image": "notepad.exe"})));
    assert_eq!(
        titles_for(&engine, &json!({"Image": "evil.exe"})),
        vec!["Glob Matches Underscore".to_string()]
    );
}

#[test]
fn exact_pattern_matches_underscore_prefixed_detection_name() {
    let engine = engine_from(
        r#"
title: Exact Underscore Pattern
id: exact-underscore
logsource:
    category: test
detection:
    selection:
        Image: 'notepad.exe'
    _internal:
        Image: 'evil.exe'
    condition: 1 of _internal
level: low
"#,
    );
    assert!(!matches(&engine, &json!({"Image": "notepad.exe"})));
    assert!(matches(&engine, &json!({"Image": "evil.exe"})));
}

#[test]
fn selection_star_does_not_match_bare_selection_name() {
    // Documents glob semantics: `selection_*` requires the underscore suffix.
    // `selection` alone is not a match (regression guard for fixture authors).
    let rule = compiled_from(
        r#"
title: Selection Star Semantics
id: selection-star-semantics
logsource:
    category: test
detection:
    selection:
        Image: 'notepad.exe'
    selection_other:
        Image: 'evil.exe'
    condition: 1 of selection_*
level: low
"#,
    );
    assert!(
        !rule_matches(&rule, &json!({"Image": "notepad.exe"})),
        "`selection` must not match pattern `selection_*`"
    );
    assert!(rule_matches(&rule, &json!({"Image": "evil.exe"})));
}

#[test]
fn star_pattern_skips_underscore_prefixed_detection_names() {
    let rule = compiled_from(
        r#"
title: Star Skip Prefix
id: star-skip-prefix
logsource:
    category: test
detection:
    selection:
        Image: 'notepad.exe'
    _internal:
        Image: 'evil.exe'
    condition: all of *
level: low
"#,
    );
    assert!(rule_matches(&rule, &json!({"Image": "notepad.exe"})));
    assert!(!rule_matches(&rule, &json!({"Image": "evil.exe"})));
}
