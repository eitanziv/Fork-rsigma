//! Data-aware "explain" trace for a single rule against a single event.
//!
//! Static tooling (validate, lint, LSP) answers "is this rule well-formed?"
//! It cannot answer "given this event, why did the rule not match?" because it
//! has no event data. [`explain_rule`] fills that gap: it walks the compiled
//! condition tree against one event and records, for every node and field,
//! whether it matched and why not.
//!
//! Unlike the production evaluator in [`crate::compiler`], the recording
//! evaluator never short-circuits (`all`/`any` would hide failing branches)
//! and never consults the bloom pre-filter (an optimization that would mask
//! the real reason). It is a parallel, read-only path: the optimized hot path
//! is untouched.
//!
//! The verdict can never disagree with the production engine: every per-node
//! `matched` boolean is computed from the same eval primitives the engine
//! uses, so `explain_rule(rule, event).matched == evaluate_rule(rule,
//! event).is_some()` holds (pinned by a property test).

use std::collections::HashMap;

use serde::Serialize;
use serde_json::Value;

use rsigma_parser::{ArrayQuantifier, ConditionExpr, Quantifier};

use crate::compiler::{
    CompiledDetection, CompiledDetectionItem, CompiledRule, array_quantifier_from_member_matches,
    decisive_member_verdict, element_field, eval_array_body, eval_array_item,
    eval_detection_item_no_bloom, select_recorded_member_indices,
};
use crate::event::{Event, EventValue};
use crate::matcher::CompiledMatcher;
use crate::result::MatcherKind;

/// A structured explanation of why a rule did or did not match an event.
#[derive(Debug, Clone, Serialize)]
pub struct RuleExplanation {
    /// Title of the explained rule.
    pub rule_title: String,
    /// Rule id, when the rule declares one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    /// The overall verdict: `true` iff the production engine would match.
    pub matched: bool,
    /// One trace per condition expression on the rule (a rule matches if any
    /// condition matches).
    pub conditions: Vec<ConditionTrace>,
}

/// A node in the explained condition tree, mirroring
/// [`ConditionExpr`].
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ConditionTrace {
    /// A named selection reference (`selection`), with its detection trace.
    Selection {
        name: String,
        matched: bool,
        detection: DetectionTrace,
    },
    /// `a and b and ...`.
    And {
        matched: bool,
        children: Vec<ConditionTrace>,
    },
    /// `a or b or ...`.
    Or {
        matched: bool,
        children: Vec<ConditionTrace>,
    },
    /// `not a`.
    Not {
        matched: bool,
        child: Box<ConditionTrace>,
    },
    /// A quantified selector such as `1 of selection_*` or `all of them`.
    Quantified {
        /// The quantifier as written: `any`, `all`, or a count.
        quantifier: String,
        matched: bool,
        /// How many matching selections were required.
        need: u64,
        /// How many matching selections actually matched.
        got: u64,
        /// Per-selection detail for every selection the pattern matched.
        branches: Vec<SelectionBranch>,
    },
}

impl ConditionTrace {
    /// The verdict recorded for this node.
    pub fn matched(&self) -> bool {
        match self {
            ConditionTrace::Selection { matched, .. }
            | ConditionTrace::And { matched, .. }
            | ConditionTrace::Or { matched, .. }
            | ConditionTrace::Not { matched, .. }
            | ConditionTrace::Quantified { matched, .. } => *matched,
        }
    }
}

/// One selection inside a quantified selector trace.
#[derive(Debug, Clone, Serialize)]
pub struct SelectionBranch {
    pub name: String,
    pub matched: bool,
    pub detection: DetectionTrace,
}

/// A node in the explained detection tree, mirroring
/// [`CompiledDetection`].
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DetectionTrace {
    /// Every item must match (a YAML mapping).
    AllOf {
        matched: bool,
        items: Vec<ItemTrace>,
    },
    /// Any sub-detection may match (a YAML list of mappings).
    AnyOf {
        matched: bool,
        branches: Vec<DetectionTrace>,
    },
    /// All sub-detections must match (a mapping mixing plain and array blocks).
    And {
        matched: bool,
        branches: Vec<DetectionTrace>,
    },
    /// Keyword detection: match a value across all event fields.
    Keywords { matched: bool, item: ItemTrace },
    /// Array object-scope match with per-member traces.
    ArrayMatch {
        field: String,
        /// Quantifier as written: `any`, `all`, `all_or_empty`, or `none`.
        quantifier: String,
        matched: bool,
        member_count: usize,
        /// Members whose body matched, counted over the full array (not just
        /// the recorded subset), so truncation cannot understate it.
        matched_count: usize,
        /// True when the field value was a non-array scalar treated as one member.
        #[serde(skip_serializing_if = "std::ops::Not::not")]
        scalar: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        empty_reason: Option<ArrayEmptyReason>,
        #[serde(skip_serializing_if = "std::ops::Not::not")]
        truncated: bool,
        #[serde(skip_serializing_if = "is_zero_usize")]
        omitted: usize,
        members: Vec<ArrayMemberTrace>,
    },
    /// Extended array-body condition, or a top-level `Conditional` detection.
    Conditional {
        matched: bool,
        condition: Box<ConditionTrace>,
    },
    /// Last-resort opaque detection (unknown selection names).
    Other { kind: String, matched: bool },
}

fn is_zero_usize(n: &usize) -> bool {
    *n == 0
}

/// Why an array object-scope node had zero members.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArrayEmptyReason {
    MissingOrNull,
    EmptyArray,
}

/// One recorded member of an [`DetectionTrace::ArrayMatch`].
#[derive(Debug, Clone, Serialize)]
pub struct ArrayMemberTrace {
    pub index: usize,
    pub matched: bool,
    pub detection: DetectionTrace,
}

impl DetectionTrace {
    /// The verdict recorded for this node.
    pub fn matched(&self) -> bool {
        match self {
            DetectionTrace::AllOf { matched, .. }
            | DetectionTrace::AnyOf { matched, .. }
            | DetectionTrace::And { matched, .. }
            | DetectionTrace::Keywords { matched, .. }
            | DetectionTrace::ArrayMatch { matched, .. }
            | DetectionTrace::Conditional { matched, .. }
            | DetectionTrace::Other { matched, .. } => *matched,
        }
    }
}

/// A single field-or-keyword leaf in a detection trace.
#[derive(Debug, Clone, Serialize)]
pub struct ItemTrace {
    /// The field name tested (`None` for keyword items).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    /// The kind of matcher applied.
    pub matcher: MatcherKind,
    /// The pattern the matcher tested against, when meaningful.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    /// The event value at `field`, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual: Option<Value>,
    /// Whether this leaf matched.
    pub matched: bool,
    /// The reason for the verdict.
    pub reason: MatchReason,
}

/// Why a single leaf matched or did not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchReason {
    /// The leaf matched.
    Matched,
    /// The field is not present in the event.
    FieldAbsent,
    /// The field is present but the value does not satisfy the matcher.
    ValueMismatch,
    /// The field is present and matches except for letter case.
    CaseMismatch,
    /// An existence assertion (`|exists`) was not satisfied.
    Existence,
    /// A keyword item found no matching string anywhere in the event.
    NoKeywordMatch,
}

/// Explain why `rule` did or did not match `event`.
///
/// Visits every branch of the condition tree (no short-circuit, no bloom) and
/// returns a [`RuleExplanation`] whose `matched` field equals the production
/// verdict for the same rule and event.
pub fn explain_rule(rule: &CompiledRule, event: &impl Event) -> RuleExplanation {
    let conditions: Vec<ConditionTrace> = rule
        .conditions
        .iter()
        .map(|c| explain_condition(c, &rule.detections, event))
        .collect();
    let matched = conditions.iter().any(ConditionTrace::matched);
    RuleExplanation {
        rule_title: rule.title.clone(),
        rule_id: rule.id.clone(),
        matched,
        conditions,
    }
}

fn explain_condition(
    expr: &ConditionExpr,
    detections: &HashMap<String, CompiledDetection>,
    event: &impl Event,
) -> ConditionTrace {
    match expr {
        ConditionExpr::Identifier(name) => {
            let detection = match detections.get(name) {
                Some(det) => explain_detection(det, event),
                // `compile_rule` validates identifier references, so this arm
                // is unreachable for a compiled rule; recorded as a non-match.
                None => DetectionTrace::Other {
                    kind: "unknown selection".to_string(),
                    matched: false,
                },
            };
            ConditionTrace::Selection {
                name: name.clone(),
                matched: detection.matched(),
                detection,
            }
        }
        ConditionExpr::And(exprs) => {
            let children: Vec<ConditionTrace> = exprs
                .iter()
                .map(|e| explain_condition(e, detections, event))
                .collect();
            let matched = children.iter().all(ConditionTrace::matched);
            ConditionTrace::And { matched, children }
        }
        ConditionExpr::Or(exprs) => {
            let children: Vec<ConditionTrace> = exprs
                .iter()
                .map(|e| explain_condition(e, detections, event))
                .collect();
            let matched = children.iter().any(ConditionTrace::matched);
            ConditionTrace::Or { matched, children }
        }
        ConditionExpr::Not(inner) => {
            let child = explain_condition(inner, detections, event);
            let matched = !child.matched();
            ConditionTrace::Not {
                matched,
                child: Box::new(child),
            }
        }
        ConditionExpr::Selector {
            quantifier,
            pattern,
        } => {
            // Sort for deterministic output (detections is a HashMap).
            let mut names: Vec<&String> = detections
                .keys()
                .filter(|n| pattern.matches_detection_name(n))
                .collect();
            names.sort();

            let branches: Vec<SelectionBranch> = names
                .iter()
                .map(|name| {
                    let detection = detections
                        .get(*name)
                        .map(|det| explain_detection(det, event))
                        .unwrap_or(DetectionTrace::Other {
                            kind: "unknown selection".to_string(),
                            matched: false,
                        });
                    SelectionBranch {
                        name: (*name).clone(),
                        matched: detection.matched(),
                        detection,
                    }
                })
                .collect();

            let got = branches.iter().filter(|b| b.matched).count() as u64;
            let total = branches.len() as u64;
            let (quant_str, need, matched) = match quantifier {
                Quantifier::Any => ("any".to_string(), 1, got >= 1),
                Quantifier::All => ("all".to_string(), total, got == total),
                Quantifier::Count(n) => (n.to_string(), *n, got >= *n),
            };
            ConditionTrace::Quantified {
                quantifier: quant_str,
                matched,
                need,
                got,
                branches,
            }
        }
    }
}

fn explain_detection(detection: &CompiledDetection, event: &impl Event) -> DetectionTrace {
    match detection {
        CompiledDetection::AllOf(items) => {
            let items: Vec<ItemTrace> = items.iter().map(|i| explain_item(i, event)).collect();
            let matched = items.iter().all(|i| i.matched);
            DetectionTrace::AllOf { matched, items }
        }
        CompiledDetection::AnyOf(dets) => {
            let branches: Vec<DetectionTrace> =
                dets.iter().map(|d| explain_detection(d, event)).collect();
            let matched = branches.iter().any(DetectionTrace::matched);
            DetectionTrace::AnyOf { matched, branches }
        }
        CompiledDetection::And(dets) => {
            let branches: Vec<DetectionTrace> =
                dets.iter().map(|d| explain_detection(d, event)).collect();
            let matched = branches.iter().all(DetectionTrace::matched);
            DetectionTrace::And { matched, branches }
        }
        CompiledDetection::Keywords(matcher) => {
            let matched = matcher.matches_keyword(event);
            let desc = matcher.describe();
            let item = ItemTrace {
                field: None,
                matcher: desc.kind,
                pattern: desc.pattern,
                actual: None,
                matched,
                reason: if matched {
                    MatchReason::Matched
                } else {
                    MatchReason::NoKeywordMatch
                },
            };
            DetectionTrace::Keywords { matched, item }
        }
        CompiledDetection::ArrayMatch {
            field,
            quantifier,
            body,
        } => {
            let value = event.get_field(field);
            explain_array_match(field, *quantifier, body, value.as_ref(), event)
        }
        CompiledDetection::Conditional { named, condition } => {
            let condition = explain_condition(condition, named, event);
            DetectionTrace::Conditional {
                matched: condition.matched(),
                condition: Box::new(condition),
            }
        }
    }
}

fn explain_array_match<E: Event>(
    field: &str,
    quantifier: ArrayQuantifier,
    body: &CompiledDetection,
    value: Option<&EventValue>,
    outer: &E,
) -> DetectionTrace {
    let (scalar, empty_reason, members): (bool, Option<ArrayEmptyReason>, Vec<&EventValue>) =
        match value {
            None | Some(EventValue::Null) => {
                (false, Some(ArrayEmptyReason::MissingOrNull), Vec::new())
            }
            Some(EventValue::Array(items)) if items.is_empty() => {
                (false, Some(ArrayEmptyReason::EmptyArray), Vec::new())
            }
            Some(EventValue::Array(items)) => (false, None, items.iter().collect()),
            Some(single) => (true, None, vec![single]),
        };

    let member_matched: Vec<bool> = members
        .iter()
        .map(|m| eval_array_body(body, m, outer))
        .collect();
    let matched = array_quantifier_from_member_matches(quantifier, &member_matched);
    let matched_count = member_matched.iter().filter(|&&m| m).count();
    let recorded: Vec<ArrayMemberTrace> =
        select_recorded_member_indices(&member_matched, decisive_member_verdict(quantifier))
            .into_iter()
            .map(|index| ArrayMemberTrace {
                index,
                matched: member_matched[index],
                detection: explain_array_body(body, members[index], outer),
            })
            .collect();
    let omitted = members.len().saturating_sub(recorded.len());
    DetectionTrace::ArrayMatch {
        field: field.to_string(),
        quantifier: quantifier.to_string(),
        matched,
        member_count: members.len(),
        matched_count,
        scalar,
        empty_reason,
        truncated: omitted > 0,
        omitted,
        members: recorded,
    }
}

fn explain_array_body<E: Event>(
    body: &CompiledDetection,
    member: &EventValue,
    outer: &E,
) -> DetectionTrace {
    match body {
        CompiledDetection::AllOf(items) => {
            let items: Vec<ItemTrace> = items
                .iter()
                .map(|i| explain_array_item(i, member, outer))
                .collect();
            let matched = items.iter().all(|i| i.matched);
            DetectionTrace::AllOf { matched, items }
        }
        CompiledDetection::AnyOf(dets) => {
            let branches: Vec<DetectionTrace> = dets
                .iter()
                .map(|d| explain_array_body(d, member, outer))
                .collect();
            let matched = branches.iter().any(DetectionTrace::matched);
            DetectionTrace::AnyOf { matched, branches }
        }
        CompiledDetection::And(dets) => {
            let branches: Vec<DetectionTrace> = dets
                .iter()
                .map(|d| explain_array_body(d, member, outer))
                .collect();
            let matched = branches.iter().all(DetectionTrace::matched);
            DetectionTrace::And { matched, branches }
        }
        CompiledDetection::ArrayMatch {
            field,
            quantifier,
            body: inner,
        } => explain_array_match(
            field,
            *quantifier,
            inner,
            element_field(member, field),
            outer,
        ),
        CompiledDetection::Keywords(matcher) => {
            let matched = matcher.matches(member, outer);
            let desc = matcher.describe();
            DetectionTrace::Keywords {
                matched,
                item: ItemTrace {
                    field: None,
                    matcher: desc.kind,
                    pattern: desc.pattern,
                    actual: Some(member.to_json()),
                    matched,
                    reason: if matched {
                        MatchReason::Matched
                    } else {
                        MatchReason::ValueMismatch
                    },
                },
            }
        }
        CompiledDetection::Conditional { named, condition } => {
            let condition = explain_array_condition(condition, named, member, outer);
            DetectionTrace::Conditional {
                matched: condition.matched(),
                condition: Box::new(condition),
            }
        }
    }
}

fn explain_array_condition<E: Event>(
    expr: &ConditionExpr,
    named: &HashMap<String, CompiledDetection>,
    member: &EventValue,
    outer: &E,
) -> ConditionTrace {
    match expr {
        ConditionExpr::Identifier(name) => {
            let detection = match named.get(name) {
                Some(det) => explain_array_body(det, member, outer),
                None => DetectionTrace::Other {
                    kind: "unknown selection".to_string(),
                    matched: false,
                },
            };
            ConditionTrace::Selection {
                name: name.clone(),
                matched: detection.matched(),
                detection,
            }
        }
        ConditionExpr::And(exprs) => {
            let children: Vec<ConditionTrace> = exprs
                .iter()
                .map(|e| explain_array_condition(e, named, member, outer))
                .collect();
            let matched = children.iter().all(ConditionTrace::matched);
            ConditionTrace::And { matched, children }
        }
        ConditionExpr::Or(exprs) => {
            let children: Vec<ConditionTrace> = exprs
                .iter()
                .map(|e| explain_array_condition(e, named, member, outer))
                .collect();
            let matched = children.iter().any(ConditionTrace::matched);
            ConditionTrace::Or { matched, children }
        }
        ConditionExpr::Not(inner) => {
            let child = explain_array_condition(inner, named, member, outer);
            let matched = !child.matched();
            ConditionTrace::Not {
                matched,
                child: Box::new(child),
            }
        }
        ConditionExpr::Selector {
            quantifier,
            pattern,
        } => {
            let mut names: Vec<&String> = named
                .keys()
                .filter(|n| pattern.matches_detection_name(n))
                .collect();
            names.sort();

            let branches: Vec<SelectionBranch> = names
                .iter()
                .map(|name| {
                    let detection = named
                        .get(*name)
                        .map(|det| explain_array_body(det, member, outer))
                        .unwrap_or(DetectionTrace::Other {
                            kind: "unknown selection".to_string(),
                            matched: false,
                        });
                    SelectionBranch {
                        name: (*name).clone(),
                        matched: detection.matched(),
                        detection,
                    }
                })
                .collect();

            let got = branches.iter().filter(|b| b.matched).count() as u64;
            let total = branches.len() as u64;
            let (quant_str, need, matched) = match quantifier {
                Quantifier::Any => ("any".to_string(), 1, got >= 1),
                Quantifier::All => ("all".to_string(), total, got == total),
                Quantifier::Count(n) => (n.to_string(), *n, got >= *n),
            };
            ConditionTrace::Quantified {
                quantifier: quant_str,
                matched,
                need,
                got,
                branches,
            }
        }
    }
}

fn explain_array_item<E: Event>(
    item: &CompiledDetectionItem,
    member: &EventValue,
    outer: &E,
) -> ItemTrace {
    let desc = item.matcher.describe();
    let matched = eval_array_item(item, member, outer);

    if item.exists.is_some() {
        let actual = match &item.field {
            Some(name) => element_field(member, name).map(|v| v.to_json()),
            None => Some(member.to_json()),
        };
        return ItemTrace {
            field: item.field.clone(),
            matcher: MatcherKind::Exists,
            pattern: desc.pattern,
            actual,
            matched,
            reason: if matched {
                MatchReason::Matched
            } else {
                MatchReason::Existence
            },
        };
    }

    match &item.field {
        Some(field) => {
            let value = element_field(member, field);
            let reason = if matched {
                MatchReason::Matched
            } else {
                match value {
                    None => MatchReason::FieldAbsent,
                    Some(v) => {
                        if case_only_mismatch(&item.matcher, v) {
                            MatchReason::CaseMismatch
                        } else {
                            MatchReason::ValueMismatch
                        }
                    }
                }
            };
            ItemTrace {
                field: Some(field.clone()),
                matcher: desc.kind,
                pattern: desc.pattern,
                actual: value.map(|v| v.to_json()),
                matched,
                reason,
            }
        }
        None => {
            let reason = if matched {
                MatchReason::Matched
            } else if case_only_mismatch(&item.matcher, member) {
                MatchReason::CaseMismatch
            } else {
                MatchReason::ValueMismatch
            };
            ItemTrace {
                field: None,
                matcher: desc.kind,
                pattern: desc.pattern,
                actual: Some(member.to_json()),
                matched,
                reason,
            }
        }
    }
}

fn explain_item(item: &CompiledDetectionItem, event: &impl Event) -> ItemTrace {
    let desc = item.matcher.describe();
    let matched = eval_detection_item_no_bloom(item, event);

    // Existence assertion (`|exists`): the matcher is structural.
    if item.exists.is_some() {
        let actual = item
            .field
            .as_deref()
            .and_then(|f| event.get_field(f))
            .map(|v| v.to_json());
        return ItemTrace {
            field: item.field.clone(),
            matcher: MatcherKind::Exists,
            pattern: desc.pattern,
            actual,
            matched,
            reason: if matched {
                MatchReason::Matched
            } else {
                MatchReason::Existence
            },
        };
    }

    match &item.field {
        Some(field) => {
            let value = event.get_field(field);
            let reason = if matched {
                MatchReason::Matched
            } else {
                match &value {
                    None => MatchReason::FieldAbsent,
                    Some(v) => {
                        if case_only_mismatch(&item.matcher, v) {
                            MatchReason::CaseMismatch
                        } else {
                            MatchReason::ValueMismatch
                        }
                    }
                }
            };
            ItemTrace {
                field: Some(field.clone()),
                matcher: desc.kind,
                pattern: desc.pattern,
                actual: value.map(|v| v.to_json()),
                matched,
                reason,
            }
        }
        // A keyword item embedded inside an `AllOf` mapping.
        None => ItemTrace {
            field: None,
            matcher: desc.kind,
            pattern: desc.pattern,
            actual: None,
            matched,
            reason: if matched {
                MatchReason::Matched
            } else {
                MatchReason::NoKeywordMatch
            },
        },
    }
}

/// Heuristic: would a case-sensitive string matcher have matched if case were
/// ignored? Used only to label a failed leaf as [`MatchReason::CaseMismatch`]
/// rather than [`MatchReason::ValueMismatch`]; the verdict itself comes from
/// the real matcher, so a mislabel never changes correctness.
fn case_only_mismatch(matcher: &CompiledMatcher, actual: &EventValue) -> bool {
    let Some(actual) = actual.as_str() else {
        return false;
    };
    let actual = actual.to_lowercase();
    let (pattern, kind) = match matcher {
        CompiledMatcher::Exact {
            value,
            case_insensitive: false,
        } => (value, CaseKind::Exact),
        CompiledMatcher::Contains {
            value,
            case_insensitive: false,
        } => (value, CaseKind::Contains),
        CompiledMatcher::StartsWith {
            value,
            case_insensitive: false,
        } => (value, CaseKind::StartsWith),
        CompiledMatcher::EndsWith {
            value,
            case_insensitive: false,
        } => (value, CaseKind::EndsWith),
        _ => return false,
    };
    let pattern = pattern.to_lowercase();
    match kind {
        CaseKind::Exact => actual == pattern,
        CaseKind::Contains => actual.contains(&pattern),
        CaseKind::StartsWith => actual.starts_with(&pattern),
        CaseKind::EndsWith => actual.ends_with(&pattern),
    }
}

enum CaseKind {
    Exact,
    Contains,
    StartsWith,
    EndsWith,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::compile_rule;
    use crate::evaluate_rule;
    use crate::event::JsonEvent;
    use proptest::prelude::*;
    use rsigma_parser::parse_sigma_yaml;
    use serde_json::json;

    fn compile(yaml: &str) -> CompiledRule {
        let coll = parse_sigma_yaml(yaml).expect("parse");
        compile_rule(&coll.rules[0]).expect("compile")
    }

    /// Find the first `ItemTrace` in a single-condition explanation, drilling
    /// through the selection's detection.
    fn first_item(exp: &RuleExplanation) -> &ItemTrace {
        match &exp.conditions[0] {
            ConditionTrace::Selection { detection, .. } => match detection {
                DetectionTrace::AllOf { items, .. } => &items[0],
                other => panic!("unexpected detection: {other:?}"),
            },
            other => panic!("unexpected condition: {other:?}"),
        }
    }

    const RULE_ENDSWITH: &str = r#"
title: Powershell
id: rule-endswith
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|endswith: '\powershell.exe'
    condition: selection
"#;

    #[test]
    fn matched_leaf_reports_matched() {
        let rule = compile(RULE_ENDSWITH);
        let v = json!({"CommandLine": "C:\\Windows\\System32\\powershell.exe"});
        let exp = explain_rule(&rule, &JsonEvent::borrow(&v));
        assert!(exp.matched);
        assert_eq!(exp.rule_id.as_deref(), Some("rule-endswith"));
        let item = first_item(&exp);
        assert!(item.matched);
        assert_eq!(item.reason, MatchReason::Matched);
        assert_eq!(item.matcher, MatcherKind::EndsWith);
    }

    #[test]
    fn absent_field_reports_field_absent() {
        let rule = compile(RULE_ENDSWITH);
        let v = json!({"Image": "x"});
        let exp = explain_rule(&rule, &JsonEvent::borrow(&v));
        assert!(!exp.matched);
        let item = first_item(&exp);
        assert!(!item.matched);
        assert_eq!(item.reason, MatchReason::FieldAbsent);
        assert!(item.actual.is_none());
    }

    #[test]
    fn value_present_but_wrong_reports_value_mismatch() {
        let rule = compile(RULE_ENDSWITH);
        let v = json!({"CommandLine": "C:\\Windows\\System32\\cmd.exe"});
        let exp = explain_rule(&rule, &JsonEvent::borrow(&v));
        assert!(!exp.matched);
        let item = first_item(&exp);
        assert_eq!(item.reason, MatchReason::ValueMismatch);
        assert_eq!(item.actual, Some(json!("C:\\Windows\\System32\\cmd.exe")));
    }

    #[test]
    fn case_only_difference_reports_case_mismatch() {
        let rule = compile(
            r#"
title: Cased
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|endswith|cased: '\powershell.exe'
    condition: selection
"#,
        );
        let v = json!({"CommandLine": "C:\\Windows\\System32\\POWERSHELL.EXE"});
        let exp = explain_rule(&rule, &JsonEvent::borrow(&v));
        assert!(!exp.matched);
        let item = first_item(&exp);
        assert_eq!(item.reason, MatchReason::CaseMismatch);
    }

    #[test]
    fn numeric_mismatch_reports_value_mismatch() {
        let rule = compile(
            r#"
title: Count
logsource:
    category: test
detection:
    selection:
        Count|gt: 5
    condition: selection
"#,
        );
        let v = json!({"Count": 3});
        let exp = explain_rule(&rule, &JsonEvent::borrow(&v));
        assert!(!exp.matched);
        let item = first_item(&exp);
        assert_eq!(item.matcher, MatcherKind::Numeric);
        assert_eq!(item.reason, MatchReason::ValueMismatch);
    }

    #[test]
    fn negation_inverts_verdict() {
        let rule = compile(
            r#"
title: Not Filter
logsource:
    category: test
detection:
    selection:
        EventID: 1
    filter:
        User: SYSTEM
    condition: selection and not filter
"#,
        );
        // selection matches, filter matches -> `not filter` is false -> no match.
        let v = json!({"EventID": 1, "User": "SYSTEM"});
        let exp = explain_rule(&rule, &JsonEvent::borrow(&v));
        assert!(!exp.matched);
        // selection matches, filter does not -> `not filter` true -> match.
        let v2 = json!({"EventID": 1, "User": "alice"});
        let exp2 = explain_rule(&rule, &JsonEvent::borrow(&v2));
        assert!(exp2.matched);
        match &exp2.conditions[0] {
            ConditionTrace::And { children, .. } => {
                assert!(matches!(
                    children[1],
                    ConditionTrace::Not { matched: true, .. }
                ));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn quantified_selector_records_need_and_got() {
        // `1 of selection_*` is preserved as a native selector, so explain
        // reports it as a quantified node with need/got counts.
        let rule = compile(
            r#"
title: One Of
logsource:
    category: test
detection:
    selection_a:
        CommandLine|contains: powershell
    selection_b:
        CommandLine|contains: whoami
    condition: 1 of selection_*
"#,
        );
        let v = json!({"CommandLine": "run powershell now"});
        let exp = explain_rule(&rule, &JsonEvent::borrow(&v));
        assert!(exp.matched);
        match &exp.conditions[0] {
            ConditionTrace::Quantified {
                need,
                got,
                branches,
                ..
            } => {
                assert_eq!(*need, 1);
                assert_eq!(*got, 1);
                assert_eq!(branches.len(), 2);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn keyword_detection_traces_keyword_leaf() {
        let rule = compile(
            r#"
title: Keywords
logsource:
    category: test
detection:
    keywords:
        - whoami
        - mimikatz
    condition: keywords
"#,
        );
        let hit = json!({"msg": "user ran whoami"});
        let exp = explain_rule(&rule, &JsonEvent::borrow(&hit));
        assert!(exp.matched);
        let miss = json!({"msg": "nothing here"});
        let exp_miss = explain_rule(&rule, &JsonEvent::borrow(&miss));
        assert!(!exp_miss.matched);
        match &exp_miss.conditions[0] {
            ConditionTrace::Selection { detection, .. } => match detection {
                DetectionTrace::Keywords { item, .. } => {
                    assert_eq!(item.reason, MatchReason::NoKeywordMatch);
                    assert_eq!(item.matcher, MatcherKind::OneOf);
                }
                other => panic!("unexpected: {other:?}"),
            },
            other => panic!("unexpected: {other:?}"),
        }
    }

    fn selection_detection(exp: &RuleExplanation) -> &DetectionTrace {
        match &exp.conditions[0] {
            ConditionTrace::Selection { detection, .. } => detection,
            other => panic!("unexpected condition: {other:?}"),
        }
    }

    const RULE_ARRAY_ANY: &str = r#"
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
    fn array_any_match_records_binding_member() {
        let rule = compile(RULE_ARRAY_ANY);
        let v = json!({"connections": [
            {"protocol": "UDP", "ip": "10.0.0.1"},
            {"protocol": "TCP", "ip": "123.1.9.9"}
        ]});
        let exp = explain_rule(&rule, &JsonEvent::borrow(&v));
        assert!(exp.matched);
        match selection_detection(&exp) {
            DetectionTrace::ArrayMatch {
                field,
                quantifier,
                matched,
                member_count,
                scalar,
                truncated,
                members,
                ..
            } => {
                assert_eq!(field, "connections");
                assert_eq!(quantifier, "any");
                assert!(matched);
                assert_eq!(*member_count, 2);
                assert!(!*scalar);
                assert!(!*truncated);
                assert_eq!(members.len(), 2);
                assert!(!members[0].matched);
                assert!(members[1].matched);
                assert_eq!(members[0].index, 0);
                assert_eq!(members[1].index, 1);
                match &members[1].detection {
                    DetectionTrace::AllOf { items, matched } => {
                        assert!(matched);
                        assert_eq!(items.len(), 2);
                        assert!(items.iter().all(|i| i.matched));
                        assert_eq!(items[0].field.as_deref(), Some("protocol"));
                    }
                    other => panic!("unexpected member body: {other:?}"),
                }
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn array_any_split_member_is_a_miss_with_per_predicate_fails() {
        let rule = compile(RULE_ARRAY_ANY);
        let v = json!({"connections": [
            {"protocol": "TCP", "ip": "10.0.0.1"},
            {"protocol": "UDP", "ip": "123.1.9.9"}
        ]});
        let exp = explain_rule(&rule, &JsonEvent::borrow(&v));
        assert!(!exp.matched);
        match selection_detection(&exp) {
            DetectionTrace::ArrayMatch {
                members, matched, ..
            } => {
                assert!(!*matched);
                assert_eq!(members.len(), 2);
                assert!(members.iter().all(|m| !m.matched));
                match &members[0].detection {
                    DetectionTrace::AllOf { items, .. } => {
                        assert!(items[0].matched);
                        assert!(!items[1].matched);
                        assert_eq!(items[1].reason, MatchReason::ValueMismatch);
                    }
                    other => panic!("unexpected: {other:?}"),
                }
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn array_all_none_all_or_empty_empty_and_missing() {
        let all = compile(
            r#"
title: All
sigma-version: 3
logsource: {category: test}
detection:
    selection:
        connections[all]:
            protocol: 'TCP'
    condition: selection
"#,
        );
        let none = compile(
            r#"
title: None
sigma-version: 3
logsource: {category: test}
detection:
    selection:
        connections[none]:
            protocol: 'TCP'
    condition: selection
"#,
        );
        let all_or_empty = compile(
            r#"
title: AllOrEmpty
sigma-version: 3
logsource: {category: test}
detection:
    selection:
        connections[all_or_empty]:
            protocol: 'TCP'
    condition: selection
"#,
        );
        let missing = json!({"other": 1});
        let empty = json!({"connections": []});
        let null = json!({"connections": null});

        for event in [&missing, &empty, &null] {
            let je = JsonEvent::borrow(event);
            assert!(!explain_rule(&all, &je).matched);
            assert!(explain_rule(&none, &je).matched);
            assert!(explain_rule(&all_or_empty, &je).matched);
        }

        let missing_exp = explain_rule(&none, &JsonEvent::borrow(&missing));
        match selection_detection(&missing_exp) {
            DetectionTrace::ArrayMatch {
                empty_reason,
                member_count,
                members,
                ..
            } => {
                assert_eq!(*empty_reason, Some(ArrayEmptyReason::MissingOrNull));
                assert_eq!(*member_count, 0);
                assert!(members.is_empty());
            }
            other => panic!("unexpected: {other:?}"),
        }
        let empty_exp = explain_rule(&none, &JsonEvent::borrow(&empty));
        match selection_detection(&empty_exp) {
            DetectionTrace::ArrayMatch { empty_reason, .. } => {
                assert_eq!(*empty_reason, Some(ArrayEmptyReason::EmptyArray));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn array_scalar_as_one_member() {
        let rule = compile(
            r#"
title: Scalar
sigma-version: 3
logsource: {category: test}
detection:
    selection:
        connections[any]:
            protocol: 'TCP'
    condition: selection
"#,
        );
        let v = json!({"connections": {"protocol": "TCP"}});
        let exp = explain_rule(&rule, &JsonEvent::borrow(&v));
        assert!(exp.matched);
        match selection_detection(&exp) {
            DetectionTrace::ArrayMatch {
                scalar,
                member_count,
                members,
                ..
            } => {
                assert!(*scalar);
                assert_eq!(*member_count, 1);
                assert_eq!(members[0].index, 0);
                assert!(members[0].matched);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn array_extended_condition_body() {
        let rule = compile(
            r#"
title: Extended
sigma-version: 3
logsource: {category: test}
detection:
    selection:
        connections[any]:
            condition: in_cidr and not is_tcp
            in_cidr:
                ip|cidr: '123.1.0.0/16'
            is_tcp:
                protocol: 'TCP'
    condition: selection
"#,
        );
        let v = json!({"connections": [
            {"protocol": "UDP", "ip": "123.1.9.9"},
            {"protocol": "TCP", "ip": "123.1.9.9"}
        ]});
        let exp = explain_rule(&rule, &JsonEvent::borrow(&v));
        assert!(exp.matched);
        match selection_detection(&exp) {
            DetectionTrace::ArrayMatch { members, .. } => {
                let by_index = |i: usize| members.iter().find(|m| m.index == i).unwrap();
                assert!(by_index(0).matched);
                assert!(!by_index(1).matched);
                match &by_index(0).detection {
                    DetectionTrace::Conditional { matched, condition } => {
                        assert!(matched);
                        assert!(matches!(
                            condition.as_ref(),
                            ConditionTrace::And { matched: true, .. }
                        ));
                    }
                    other => panic!("unexpected: {other:?}"),
                }
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn array_nested_quantifier() {
        let rule = compile(
            r#"
title: Nested
sigma-version: 3
logsource: {category: test}
detection:
    selection:
        rules[any]:
            type: 'allow'
            ip[all]|startswith: '123.1.1'
    condition: selection
"#,
        );
        let v = json!({"rules": [
            {"type": "allow", "ip": ["123.1.1.1", "123.1.1.2"]}
        ]});
        let exp = explain_rule(&rule, &JsonEvent::borrow(&v));
        assert!(exp.matched);
        match selection_detection(&exp) {
            DetectionTrace::ArrayMatch { members, .. } => {
                assert!(members[0].matched);
                match &members[0].detection {
                    DetectionTrace::And { branches, .. } => {
                        let inner = branches
                            .iter()
                            .find(|b| matches!(b, DetectionTrace::ArrayMatch { field, .. } if field == "ip"))
                            .expect("inner array");
                        match inner {
                            DetectionTrace::ArrayMatch {
                                quantifier,
                                member_count,
                                members: inner_members,
                                matched,
                                ..
                            } => {
                                assert_eq!(quantifier, "all");
                                assert!(matched);
                                assert_eq!(*member_count, 2);
                                assert_eq!(inner_members.len(), 2);
                                assert!(inner_members.iter().all(|m| m.matched));
                            }
                            other => panic!("unexpected inner: {other:?}"),
                        }
                    }
                    other => panic!("unexpected outer body: {other:?}"),
                }
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn array_fieldref_resolves_against_outer_event() {
        let rule = compile(
            r#"
title: Fieldref
sigma-version: 3
logsource: {category: test}
detection:
    selection:
        connections[any]:
            protocol|fieldref: expected_proto
    condition: selection
"#,
        );
        let hit = json!({
            "expected_proto": "TCP",
            "connections": [{"protocol": "TCP"}, {"protocol": "UDP"}]
        });
        let miss = json!({
            "expected_proto": "TCP",
            "connections": [{"protocol": "UDP"}]
        });
        assert!(explain_rule(&rule, &JsonEvent::borrow(&hit)).matched);
        assert!(!explain_rule(&rule, &JsonEvent::borrow(&miss)).matched);
        // A member-as-Event adapter would look up expected_proto on the member and miss.
        let adapter_trap = json!({
            "expected_proto": "UDP",
            "connections": [{"protocol": "TCP", "expected_proto": "TCP"}]
        });
        assert!(!explain_rule(&rule, &JsonEvent::borrow(&adapter_trap)).matched);
    }

    #[test]
    fn array_exists_absent_vs_explicit_null() {
        let rule = compile(
            r#"
title: Exists
sigma-version: 3
logsource: {category: test}
detection:
    selection:
        connections[any]:
            dest|exists: true
    condition: selection
"#,
        );
        let present = json!({"connections": [{"dest": "a"}]});
        let absent = json!({"connections": [{}]});
        let explicit_null = json!({"connections": [{"dest": null}]});
        assert!(explain_rule(&rule, &JsonEvent::borrow(&present)).matched);
        assert!(!explain_rule(&rule, &JsonEvent::borrow(&absent)).matched);
        assert!(explain_rule(&rule, &JsonEvent::borrow(&explicit_null)).matched);

        let exp = explain_rule(&rule, &JsonEvent::borrow(&absent));
        match selection_detection(&exp) {
            DetectionTrace::ArrayMatch { members, .. } => match &members[0].detection {
                DetectionTrace::AllOf { items, .. } => {
                    assert_eq!(items[0].reason, MatchReason::Existence);
                    assert!(!items[0].matched);
                }
                other => panic!("unexpected: {other:?}"),
            },
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn array_truncation_keeps_verdict_and_records_binding_member() {
        // [any] over 40 members where only the last one binds: the binding
        // member is decisive and must survive truncation.
        let rule = compile(
            r#"
title: Trunc
sigma-version: 3
logsource: {category: test}
detection:
    selection:
        connections[any]:
            protocol: 'TCP'
    condition: selection
"#,
        );
        let mut members = Vec::new();
        for i in 0..40 {
            members.push(json!({"protocol": if i == 39 { "TCP" } else { "UDP" }}));
        }
        let v = json!({"connections": members});
        let exp = explain_rule(&rule, &JsonEvent::borrow(&v));
        assert!(exp.matched);
        assert_eq!(
            evaluate_rule(&rule, &JsonEvent::borrow(&v)).is_some(),
            exp.matched
        );
        match selection_detection(&exp) {
            DetectionTrace::ArrayMatch {
                truncated,
                omitted,
                member_count,
                matched_count,
                members,
                matched,
                ..
            } => {
                assert!(matched);
                assert!(*truncated);
                assert_eq!(*member_count, 40);
                assert_eq!(*matched_count, 1);
                assert_eq!(*omitted, 8);
                assert_eq!(members.len(), 32);
                let binding = members.iter().find(|m| m.matched).expect("binding member");
                assert_eq!(binding.index, 39);
                assert!(members.windows(2).all(|w| w[0].index < w[1].index));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn array_truncation_keeps_all_culprits_for_all_quantifier() {
        // [all] over 40 members where the last 5 fail: the culprits are
        // decisive and must all survive truncation.
        let rule = compile(
            r#"
title: TruncAll
sigma-version: 3
logsource: {category: test}
detection:
    selection:
        connections[all]:
            protocol: 'TCP'
    condition: selection
"#,
        );
        let mut members = Vec::new();
        for i in 0..40 {
            members.push(json!({"protocol": if i < 35 { "TCP" } else { "UDP" }}));
        }
        let v = json!({"connections": members});
        let exp = explain_rule(&rule, &JsonEvent::borrow(&v));
        assert!(!exp.matched);
        match selection_detection(&exp) {
            DetectionTrace::ArrayMatch {
                matched,
                matched_count,
                members,
                ..
            } => {
                assert!(!*matched);
                assert_eq!(*matched_count, 35);
                let fails: Vec<usize> = members
                    .iter()
                    .filter(|m| !m.matched)
                    .map(|m| m.index)
                    .collect();
                assert_eq!(fails, vec![35, 36, 37, 38, 39]);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    // -------------------------------------------------------------------------
    // Verdict equivalence: the explain trace can never disagree with the engine.
    // -------------------------------------------------------------------------

    fn sample_rules() -> Vec<CompiledRule> {
        [
            RULE_ENDSWITH,
            r#"
title: And Not
logsource: {category: test}
detection:
    selection:
        EventID: 1
    filter:
        User: SYSTEM
    condition: selection and not filter
"#,
            r#"
title: One Of
logsource: {category: test}
detection:
    selection_a:
        CommandLine|contains: powershell
    selection_b:
        CommandLine|contains: whoami
    condition: 1 of selection_*
"#,
            r#"
title: All Of
logsource: {category: test}
detection:
    selection_a:
        CommandLine|contains: powershell
    selection_b:
        User: SYSTEM
    condition: all of selection_*
"#,
            r#"
title: Numeric
logsource: {category: test}
detection:
    selection:
        Count|gt: 5
    condition: selection
"#,
            r#"
title: Exists
logsource: {category: test}
detection:
    selection:
        User|exists: true
    condition: selection
"#,
            r#"
title: Keywords
logsource: {category: test}
detection:
    keywords:
        - whoami
        - powershell
    condition: keywords
"#,
            RULE_ARRAY_ANY,
            r#"
title: Array Nested
sigma-version: 3
logsource: {category: test}
detection:
    selection:
        rules[any]:
            type: 'allow'
            ip[all]|startswith: '123.1.1'
    condition: selection
"#,
        ]
        .iter()
        .map(|y| compile(y))
        .collect()
    }

    fn arb_event() -> impl Strategy<Value = serde_json::Value> {
        let cmd = prop::option::of(prop::sample::select(vec![
            "C:\\Windows\\System32\\powershell.exe",
            "powershell.exe -enc AAAA",
            "cmd.exe /c whoami",
            "PowerShell.EXE",
            "explorer.exe",
        ]));
        let user = prop::option::of(prop::sample::select(vec!["SYSTEM", "alice", "root"]));
        let eid = prop::option::of(prop::sample::select(vec![1i64, 2, 4688]));
        let count = prop::option::of(0i64..10);
        let proto = prop::option::of(prop::sample::select(vec!["TCP", "UDP"]));
        let ip = prop::option::of(prop::sample::select(vec!["123.1.9.9", "10.0.0.1"]));
        (cmd, user, eid, count, proto, ip).prop_map(|(cmd, user, eid, count, proto, ip)| {
            let mut m = serde_json::Map::new();
            if let Some(c) = cmd {
                m.insert("CommandLine".into(), json!(c));
            }
            if let Some(u) = user {
                m.insert("User".into(), json!(u));
            }
            if let Some(e) = eid {
                m.insert("EventID".into(), json!(e));
            }
            if let Some(c) = count {
                m.insert("Count".into(), json!(c));
            }
            if let Some(p) = proto {
                let addr = ip.unwrap_or("10.0.0.1");
                m.insert("connections".into(), json!([{"protocol": p, "ip": addr}]));
                m.insert(
                    "rules".into(),
                    json!([{"type": "allow", "ip": [addr, addr]}]),
                );
            }
            serde_json::Value::Object(m)
        })
    }

    proptest! {
        #[test]
        fn explain_verdict_equals_engine_verdict(event in arb_event()) {
            let rules = sample_rules();
            let je = JsonEvent::borrow(&event);
            for rule in &rules {
                let explained = explain_rule(rule, &je).matched;
                let engine = evaluate_rule(rule, &je).is_some();
                prop_assert_eq!(
                    explained, engine,
                    "explain/engine disagree on rule {:?} for event {}",
                    rule.title, event
                );
            }
        }
    }
}
