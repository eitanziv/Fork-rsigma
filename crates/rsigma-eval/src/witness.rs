//! Static extraction of *witnesses*: necessary conditions for a rule to match.
//!
//! A witness is a cheap, event-shaped predicate that must hold whenever a
//! rule matches. A rule's analysis is an OR-set of witnesses: at least one of
//! them holds on every event the rule can possibly match. The candidate index
//! inverts that relation, so an event only has to check the witnesses it
//! satisfies to recover every rule worth evaluating.
//!
//! # Soundness
//!
//! The analysis may only ever *weaken*. Returning [`RuleWitness::Open`] (the
//! rule is a candidate for every event) is always allowed; claiming a witness
//! that does not actually follow from the rule's semantics silently loses
//! detections. Every rule here is therefore derived from the evaluator's own
//! behavior in [`crate::compiler`]:
//!
//! - An item with a field name evaluates to `false` on an absent field unless
//!   its matcher holds for absent fields ([`CompiledMatcher::matches_absent`]:
//!   `null`, or a negation such as `|neq`). Field presence is
//!   therefore a sound witness for almost every field-scoped item, which is
//!   what keeps rules built from regexes, CIDR blocks, and numeric
//!   comparisons out of the always-evaluated set.
//! - `exists: false` matches an absent field, so it admits no witness.
//! - Negation inverts polarity, so a negated subtree admits no witness.
//! - A quantified selector that can be satisfied by zero detections (`all of`
//!   over an empty match set, or `0 of`) is vacuously true and admits none.
//!
//! # Case folding
//!
//! Witness literals are stored folded with the same `to_lowercase` the
//! matchers apply, so a folded event value can be compared directly. A
//! case-insensitive matcher already holds its value folded. A `|cased`
//! matcher does not, and folding it here is only a faithful per-character
//! mapping while it stays ASCII, because Rust lowers a Greek capital sigma
//! differently depending on its position in the word. Non-ASCII cased
//! literals are therefore dropped rather than folded.

use rsigma_parser::{ConditionExpr, Quantifier};

use crate::compiler::{CompiledDetection, CompiledDetectionItem, CompiledRule};
use crate::matcher::{CompiledMatcher, GroupMode};

/// A necessary condition on an event, in the form the candidate index can
/// invert.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum Witness {
    /// The folded value of `field`, or of one of its array members, equals
    /// `value`.
    Exact { field: String, value: String },
    /// The folded value of `field`, or of one of its array members, contains
    /// `needle`.
    Substring { field: String, needle: String },
    /// Some folded string value anywhere in the event contains `needle`.
    Keyword { needle: String },
    /// `field` is present on the event.
    Presence { field: String },
}

impl Witness {
    /// Selectivity rank, lower being more selective. Used to choose between
    /// the alternatives an `AND` offers.
    fn rank(&self) -> u8 {
        match self {
            Witness::Exact { .. } => 0,
            Witness::Substring { needle, .. } if needle.len() >= LONG_LITERAL => 1,
            Witness::Substring { .. } => 2,
            Witness::Keyword { needle } if needle.len() >= LONG_LITERAL => 3,
            Witness::Keyword { .. } => 4,
            Witness::Presence { .. } => 5,
        }
    }
}

/// Literal length above which a substring witness is treated as selective
/// enough to prefer over a shorter one.
const LONG_LITERAL: usize = 8;

/// The result of analyzing one rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RuleWitness {
    /// No sound witness could be extracted: the rule must be evaluated
    /// against every event.
    Open,
    /// At least one of these holds whenever the rule matches.
    AnyOf(Vec<Witness>),
}

/// Analyze a compiled rule into the witnesses that gate it.
///
/// A rule matches when *any* of its conditions holds, so the result is the
/// union over conditions, and a single unanalyzable condition opens the whole
/// rule.
pub(crate) fn analyze_rule(rule: &CompiledRule) -> RuleWitness {
    if rule.conditions.is_empty() {
        // No condition can never fire, but the evaluator owns that verdict;
        // staying open keeps this analysis out of the semantics business.
        return RuleWitness::Open;
    }
    let analysis = or_combine(
        rule.conditions
            .iter()
            .map(|c| analyze_condition(c, &rule.detections)),
    );
    match analysis {
        Analysis::Open => RuleWitness::Open,
        Analysis::Witnesses(mut ws) => {
            ws.sort_by(|a, b| sort_key(a).cmp(&sort_key(b)));
            ws.dedup();
            if ws.is_empty() {
                RuleWitness::Open
            } else {
                RuleWitness::AnyOf(ws)
            }
        }
    }
}

/// Total order used to deduplicate a witness set, most selective first.
fn sort_key(w: &Witness) -> (u8, &str, &str) {
    match w {
        Witness::Exact { field, value } => (w.rank(), field, value),
        Witness::Substring { field, needle } => (w.rank(), field, needle),
        Witness::Keyword { needle } => (w.rank(), "", needle),
        Witness::Presence { field } => (w.rank(), field, ""),
    }
}

// ---------------------------------------------------------------------------
// Combinators
// ---------------------------------------------------------------------------

type Detections = std::collections::HashMap<String, CompiledDetection>;

#[derive(Debug, Clone)]
enum Analysis {
    Open,
    Witnesses(Vec<Witness>),
}

/// `OR`: every branch has to contribute, because any branch alone can carry
/// the match. One open branch opens the disjunction.
fn or_combine(parts: impl IntoIterator<Item = Analysis>) -> Analysis {
    let mut union: Vec<Witness> = Vec::new();
    for part in parts {
        match part {
            Analysis::Open => return Analysis::Open,
            Analysis::Witnesses(ws) => union.extend(ws),
        }
    }
    Analysis::Witnesses(union)
}

/// `AND`: every conjunct is individually necessary, so any one of their
/// witness sets is a valid gate. Pick the most selective and discard the
/// rest, which keeps the index small without weakening it.
fn and_combine(parts: impl IntoIterator<Item = Analysis>) -> Analysis {
    let mut best: Option<Vec<Witness>> = None;
    for part in parts {
        let Analysis::Witnesses(ws) = part else {
            continue;
        };
        if ws.is_empty() {
            continue;
        }
        if best.as_ref().is_none_or(|b| set_score(&ws) < set_score(b)) {
            best = Some(ws);
        }
    }
    match best {
        Some(ws) => Analysis::Witnesses(ws),
        None => Analysis::Open,
    }
}

/// Score a witness set: its least selective member first (the set is only as
/// good as its worst alternative), then its size.
fn set_score(ws: &[Witness]) -> (u8, usize) {
    let worst = ws.iter().map(Witness::rank).max().unwrap_or(u8::MAX);
    (worst, ws.len())
}

// ---------------------------------------------------------------------------
// Conditions
// ---------------------------------------------------------------------------

fn analyze_condition(cond: &ConditionExpr, detections: &Detections) -> Analysis {
    match cond {
        ConditionExpr::Identifier(name) => match detections.get(name) {
            Some(det) => analyze_detection(det),
            // A dangling identifier is a rule-authoring error the evaluator
            // resolves its own way; stay open.
            None => Analysis::Open,
        },
        ConditionExpr::And(parts) => {
            and_combine(parts.iter().map(|p| analyze_condition(p, detections)))
        }
        ConditionExpr::Or(parts) => {
            or_combine(parts.iter().map(|p| analyze_condition(p, detections)))
        }
        ConditionExpr::Not(_) => Analysis::Open,
        ConditionExpr::Selector {
            quantifier,
            pattern,
        } => {
            let selected: Vec<&CompiledDetection> = detections
                .iter()
                .filter(|(name, _)| pattern.matches_detection_name(name))
                .map(|(_, det)| det)
                .collect();

            match quantifier {
                // Satisfiable by zero detections, hence vacuously true.
                Quantifier::All if selected.is_empty() => Analysis::Open,
                Quantifier::Count(0) => Analysis::Open,
                // Every selected detection must match, so any one of them
                // gates the selector.
                Quantifier::All => and_combine(selected.into_iter().map(analyze_detection)),
                // At least one must match, but which one is unknown, so all
                // of them have to contribute.
                Quantifier::Any | Quantifier::Count(_) => {
                    or_combine(selected.into_iter().map(analyze_detection))
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Detections
// ---------------------------------------------------------------------------

fn analyze_detection(detection: &CompiledDetection) -> Analysis {
    match detection {
        // An empty `AllOf` is vacuously true.
        CompiledDetection::AllOf(items) if items.is_empty() => Analysis::Open,
        CompiledDetection::AllOf(items) => and_combine(items.iter().map(analyze_item)),
        // An empty `AnyOf` never matches; the witness set is irrelevant, so
        // take the cheap conservative answer.
        CompiledDetection::AnyOf(subs) if subs.is_empty() => Analysis::Open,
        CompiledDetection::AnyOf(subs) => or_combine(subs.iter().map(analyze_detection)),
        CompiledDetection::And(subs) if subs.is_empty() => Analysis::Open,
        CompiledDetection::And(subs) => and_combine(subs.iter().map(analyze_detection)),
        CompiledDetection::Keywords(matcher) => analyze_matcher(matcher, None),
        CompiledDetection::ArrayMatch {
            field,
            quantifier,
            body: _,
        } => {
            use rsigma_parser::ArrayQuantifier;
            match quantifier {
                // Both require at least one member, so the array field must
                // be present. The body's own literals are member-scoped and
                // would have to be re-scoped to keyword witnesses, which
                // relies on the keyword walk reaching the same values
                // `get_field` does; presence of the array is sound without
                // that assumption.
                ArrayQuantifier::Any | ArrayQuantifier::All => {
                    Analysis::Witnesses(vec![Witness::Presence {
                        field: field.clone(),
                    }])
                }
                // Vacuously true on an absent or empty array.
                ArrayQuantifier::AllOrEmpty | ArrayQuantifier::None => Analysis::Open,
            }
        }
        // Element-scoped bodies only appear under `ArrayMatch`, which never
        // descends into them here.
        CompiledDetection::Conditional { .. } => Analysis::Open,
    }
}

fn analyze_item(item: &CompiledDetectionItem) -> Analysis {
    let Some(field) = item.field.as_deref() else {
        // Keyword item: literals are the only handle, and they are unscoped.
        return analyze_matcher(&item.matcher, None);
    };

    match item.exists {
        // Matches precisely when the field is absent.
        Some(false) => return Analysis::Open,
        Some(true) => {
            return Analysis::Witnesses(vec![Witness::Presence {
                field: field.to_string(),
            }]);
        }
        None => {}
    }

    // An item that holds for an absent field (`null`, or a negation such as
    // `|neq`) cannot require the field.
    if item.matcher.matches_absent() {
        return Analysis::Open;
    }

    // The field must exist for this item to hold, so presence is always
    // available as a fallback when the matcher itself yields nothing.
    match analyze_matcher(&item.matcher, Some(field)) {
        Analysis::Witnesses(ws) if !ws.is_empty() => Analysis::Witnesses(ws),
        _ => Analysis::Witnesses(vec![Witness::Presence {
            field: field.to_string(),
        }]),
    }
}

// ---------------------------------------------------------------------------
// Matchers
// ---------------------------------------------------------------------------

/// Analyze a matcher. `field` is `None` for keyword scope, where literals
/// witness "somewhere in the event" rather than a specific field.
fn analyze_matcher(matcher: &CompiledMatcher, field: Option<&str>) -> Analysis {
    match matcher {
        CompiledMatcher::Exact {
            value,
            case_insensitive,
        } => match (fold_literal(value, *case_insensitive), field) {
            (Some(v), Some(f)) => Analysis::Witnesses(vec![Witness::Exact {
                field: f.to_string(),
                value: v,
            }]),
            // Keyword scope cannot use equality: the matcher tests every
            // string in the event, so the literal is a containment witness at
            // best (and in fact an equality one, but containment is what the
            // index can check without knowing field boundaries).
            (Some(v), None) => Analysis::Witnesses(vec![Witness::Keyword { needle: v }]),
            (None, _) => Analysis::Open,
        },

        CompiledMatcher::Contains {
            value,
            case_insensitive,
        }
        | CompiledMatcher::StartsWith {
            value,
            case_insensitive,
        }
        | CompiledMatcher::EndsWith {
            value,
            case_insensitive,
        } => substring_witness(value, *case_insensitive, field),

        CompiledMatcher::AhoCorasickSet {
            needles,
            case_insensitive,
            ..
        } => or_combine(
            needles
                .iter()
                .map(|n| substring_witness(n, *case_insensitive, field)),
        ),

        CompiledMatcher::Regex(re) => regex_witness(re.as_str(), field),

        CompiledMatcher::RegexSetMatch { set, mode } => {
            let parts = set.patterns().iter().map(|p| regex_witness(p, field));
            match mode {
                GroupMode::Any => or_combine(parts),
                GroupMode::All => and_combine(parts),
            }
        }

        CompiledMatcher::AnyOf(children) => {
            or_combine(children.iter().map(|c| analyze_matcher(c, field)))
        }
        CompiledMatcher::AllOf(children) => {
            and_combine(children.iter().map(|c| analyze_matcher(c, field)))
        }
        CompiledMatcher::CaseInsensitiveGroup { children, mode } => {
            let parts = children.iter().map(|c| analyze_matcher(c, field));
            match mode {
                GroupMode::Any => or_combine(parts),
                GroupMode::All => and_combine(parts),
            }
        }

        // A timestamp part reformats the field value before matching, so the
        // inner literals do not appear in the event as written. Presence of
        // the field is all that survives, and `analyze_item` supplies it.
        CompiledMatcher::TimestampPart { .. } => Analysis::Open,

        // An expand template resolves placeholders from the event at match
        // time and compares the whole expansion, so no literal part of it is
        // guaranteed to appear in the value on its own.
        CompiledMatcher::Expand { .. } => Analysis::Open,

        // Numeric and network comparisons hold for values whose textual form
        // the index cannot enumerate: `NumericEq(4688.0)` matches the string
        // `"4688"`, the integer `4688`, and the float `4688.0`. Presence from
        // `analyze_item` is the sound handle.
        CompiledMatcher::NumericEq(_)
        | CompiledMatcher::NumericGt(_)
        | CompiledMatcher::NumericGte(_)
        | CompiledMatcher::NumericLt(_)
        | CompiledMatcher::NumericLte(_)
        | CompiledMatcher::BoolEq(_)
        | CompiledMatcher::Cidr(_) => Analysis::Open,

        // `Exists(true)` is handled as an item-level flag; reaching it here
        // means it is nested, where presence is still all it implies.
        CompiledMatcher::Exists(_) => Analysis::Open,

        CompiledMatcher::FieldRef { .. } => Analysis::Open,
        CompiledMatcher::Null => Analysis::Open,
        CompiledMatcher::Not(_) => Analysis::Open,
    }
}

fn substring_witness(value: &str, case_insensitive: bool, field: Option<&str>) -> Analysis {
    match (fold_literal(value, case_insensitive), field) {
        (Some(needle), Some(f)) => Analysis::Witnesses(vec![Witness::Substring {
            field: f.to_string(),
            needle,
        }]),
        (Some(needle), None) => Analysis::Witnesses(vec![Witness::Keyword { needle }]),
        (None, _) => Analysis::Open,
    }
}

/// Fold a matcher literal into the index's comparison form, or `None` when it
/// cannot be folded faithfully.
fn fold_literal(value: &str, case_insensitive: bool) -> Option<String> {
    if value.is_empty() {
        return None;
    }
    if case_insensitive {
        // Already folded by the compiler, with the same function the haystack
        // goes through.
        Some(value.to_string())
    } else if value.is_ascii() {
        Some(value.to_ascii_lowercase())
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Regex literals
// ---------------------------------------------------------------------------

/// Extract witnesses from a regex: an OR-set of literals such that any match
/// of the pattern contains at least one of them.
fn regex_witness(pattern: &str, field: Option<&str>) -> Analysis {
    let Some(literals) = regex_mandatory_literals(pattern) else {
        return Analysis::Open;
    };
    or_combine(
        literals
            .into_iter()
            // A regex is matched against the raw value, so its literals are
            // case-sensitive unless the pattern carries `(?i)`, which the
            // parser folds into the HIR for us. Treat the extracted literal
            // as cased and fold it, dropping non-ASCII for the same reason
            // `fold_literal` does.
            .map(|lit| substring_witness(&lit, false, field)),
    )
}

/// A set of literals with the property that every string the pattern matches
/// contains at least one of them. `None` when no useful set exists.
fn regex_mandatory_literals(pattern: &str) -> Option<Vec<String>> {
    let hir = regex_syntax::ParserBuilder::new()
        .utf8(false)
        .build()
        .parse(pattern)
        .ok()?;
    let literals = hir_mandatory_literals(&hir)?;
    // Single-byte literals are sound but select nothing useful.
    if literals.iter().any(|l| l.len() < 2) {
        return None;
    }
    Some(literals)
}

fn hir_mandatory_literals(hir: &regex_syntax::hir::Hir) -> Option<Vec<String>> {
    use regex_syntax::hir::HirKind;
    match hir.kind() {
        HirKind::Literal(lit) => {
            let s = std::str::from_utf8(&lit.0).ok()?;
            if s.is_empty() {
                None
            } else {
                Some(vec![s.to_string()])
            }
        }
        // Concatenation is an AND: any child's mandatory set is mandatory for
        // the whole, so take the one whose weakest literal is longest,
        // breaking ties toward the smaller set.
        HirKind::Concat(children) => children
            .iter()
            .filter_map(hir_mandatory_literals)
            .max_by_key(|lits| {
                (
                    lits.iter().map(String::len).min().unwrap_or(0),
                    std::cmp::Reverse(lits.len()),
                )
            }),
        // Alternation is an OR: every branch must contribute, or the set is
        // not mandatory.
        HirKind::Alternation(children) => {
            let mut union = Vec::new();
            for child in children {
                union.extend(hir_mandatory_literals(child)?);
            }
            Some(union)
        }
        HirKind::Repetition(rep) if rep.min >= 1 => hir_mandatory_literals(&rep.sub),
        HirKind::Capture(cap) => hir_mandatory_literals(&cap.sub),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Engine;
    use rsigma_parser::parse_sigma_yaml;

    fn analyze(yaml: &str) -> RuleWitness {
        let collection = parse_sigma_yaml(yaml).unwrap();
        let mut engine = Engine::new();
        engine.add_collection(&collection).unwrap();
        analyze_rule(&engine.rules()[0])
    }

    fn witnesses(yaml: &str) -> Vec<Witness> {
        match analyze(yaml) {
            RuleWitness::AnyOf(ws) => ws,
            RuleWitness::Open => panic!("expected witnesses, got Open"),
        }
    }

    fn rule(detection: &str) -> String {
        format!("title: T\nlogsource:\n    category: test\ndetection:\n{detection}")
    }

    #[test]
    fn exact_item_yields_exact_witness() {
        let ws = witnesses(&rule(
            "    selection:\n        Image: 'C:\\CMD.exe'\n    condition: selection\n",
        ));
        assert_eq!(
            ws,
            vec![Witness::Exact {
                field: "Image".into(),
                value: "c:\\cmd.exe".into(),
            }]
        );
    }

    #[test]
    fn contains_item_yields_substring_witness() {
        let ws = witnesses(&rule(
            "    selection:\n        CommandLine|contains: 'WhoAmI'\n    condition: selection\n",
        ));
        assert_eq!(
            ws,
            vec![Witness::Substring {
                field: "CommandLine".into(),
                needle: "whoami".into(),
            }]
        );
    }

    #[test]
    fn keyword_detection_yields_keyword_witnesses() {
        let ws = witnesses(&rule(
            "    keywords:\n        - 'MimiKatz'\n        - 'vssadmin delete'\n    condition: keywords\n",
        ));
        assert!(ws.contains(&Witness::Keyword {
            needle: "mimikatz".into()
        }));
        assert!(ws.contains(&Witness::Keyword {
            needle: "vssadmin delete".into()
        }));
    }

    /// An `AND` only needs one gate, and it should keep the selective one.
    #[test]
    fn and_keeps_the_most_selective_conjunct() {
        let ws = witnesses(&rule(
            "    selection:\n        EventID|gte: 4000\n        Image: 'cmd.exe'\n    condition: selection\n",
        ));
        assert_eq!(
            ws,
            vec![Witness::Exact {
                field: "Image".into(),
                value: "cmd.exe".into(),
            }]
        );
    }

    /// An `OR` needs every branch, or an event matching only the missing
    /// branch would be dropped.
    #[test]
    fn or_unions_every_branch() {
        let ws = witnesses(&rule(
            "    selection:\n        - Image|endswith: '\\wmic.exe'\n        - CommandLine|contains: 'process call create'\n    condition: selection\n",
        ));
        assert_eq!(ws.len(), 2);
        assert!(ws.contains(&Witness::Substring {
            field: "Image".into(),
            needle: "\\wmic.exe".into(),
        }));
        assert!(ws.contains(&Witness::Substring {
            field: "CommandLine".into(),
            needle: "process call create".into(),
        }));
    }

    /// Regexes, CIDR blocks, and numeric comparisons still require their
    /// field to be present, which keeps them out of the always-evaluated set.
    #[test]
    fn opaque_matchers_degrade_to_presence() {
        for detection in [
            "    selection:\n        CommandLine|re: '^.{200,}$'\n    condition: selection\n",
            "    selection:\n        DestinationIp|cidr: '10.0.0.0/8'\n    condition: selection\n",
            "    selection:\n        EventID|gte: 4000\n    condition: selection\n",
            "    selection:\n        Image|fieldref: 'ParentImage'\n    condition: selection\n",
        ] {
            let ws = witnesses(&rule(detection));
            assert!(
                matches!(ws.as_slice(), [Witness::Presence { .. }]),
                "expected a presence witness for {detection}, got {ws:?}"
            );
        }
    }

    #[test]
    fn regex_mandatory_literal_is_extracted() {
        let ws = witnesses(&rule(
            "    selection:\n        CommandLine|re: 'certutil.*(urlcache|verifyctl)'\n    condition: selection\n",
        ));
        assert!(
            ws.contains(&Witness::Substring {
                field: "CommandLine".into(),
                needle: "certutil".into(),
            }),
            "got {ws:?}"
        );
    }

    #[test]
    fn negation_and_absence_stay_open() {
        for detection in [
            "    selection:\n        Image: 'cmd.exe'\n    filter:\n        User: 'SYSTEM'\n    condition: selection or not filter\n",
            "    selection:\n        TargetFilename|exists: false\n    condition: selection\n",
            "    selection:\n        User: null\n    condition: selection\n",
        ] {
            assert_eq!(
                analyze(&rule(detection)),
                RuleWitness::Open,
                "expected Open for {detection}"
            );
        }
    }

    /// `and not` keeps its positive conjunct as a gate: if the rule fires,
    /// the positive selection matched.
    #[test]
    fn and_not_keeps_the_positive_conjunct() {
        let ws = witnesses(&rule(
            "    selection:\n        Image: 'cmd.exe'\n    filter:\n        User: 'SYSTEM'\n    condition: selection and not filter\n",
        ));
        assert_eq!(
            ws,
            vec![Witness::Exact {
                field: "Image".into(),
                value: "cmd.exe".into(),
            }]
        );
    }

    #[test]
    fn one_of_selector_unions_branches() {
        let ws = witnesses(&rule(
            "    sel_a:\n        Image|endswith: '\\powershell.exe'\n    sel_b:\n        Image|endswith: '\\pwsh.exe'\n    condition: 1 of sel_*\n",
        ));
        assert_eq!(ws.len(), 2);
    }

    #[test]
    fn all_of_selector_picks_one_branch() {
        let ws = witnesses(&rule(
            "    sel_a:\n        Image|endswith: '\\rundll32.exe'\n    sel_b:\n        CommandLine|contains: 'javascript:'\n    condition: all of sel_*\n",
        ));
        assert_eq!(ws.len(), 1);
    }

    /// A non-ASCII `|cased` literal cannot be folded faithfully, so it must
    /// fall back to presence rather than be indexed.
    #[test]
    fn non_ascii_cased_literal_degrades_to_presence() {
        let ws = witnesses(&rule(
            "    selection:\n        User|contains|cased: 'Ärzte'\n    condition: selection\n",
        ));
        assert_eq!(
            ws,
            vec![Witness::Presence {
                field: "User".into()
            }]
        );
    }

    #[test]
    fn case_insensitive_unicode_literal_is_folded_by_the_compiler() {
        let ws = witnesses(&rule(
            "    selection:\n        User|contains: 'Ärzte'\n    condition: selection\n",
        ));
        assert_eq!(
            ws,
            vec![Witness::Substring {
                field: "User".into(),
                needle: "ärzte".into(),
            }]
        );
    }
}
