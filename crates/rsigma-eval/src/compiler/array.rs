//! Array object-scope evaluation shared by the production compiler and explain.
//!
//! Field lookup inside a member is relative (`element_field`); `|fieldref` and
//! keyword matchers still receive the outer event. Callers must thread `member`
//! and `outer` separately: wrapping a member as an `Event` would silently flip
//! those verdicts.

use std::borrow::Cow;
use std::collections::HashMap;

use rsigma_parser::fieldpath::{first_unescaped, unescape_brackets};
use rsigma_parser::{ArrayQuantifier, ConditionExpr, Quantifier};

use super::{CompiledDetection, CompiledDetectionItem};
use crate::event::{Event, EventValue};

/// Cap on recorded array members in explain traces and `matched_fields`.
///
/// Explain records a diagnosis subset (decisive members first); match-detail
/// records binding members in index order. Both stop at this cap so recorded
/// member entries stay bounded. Note the cap only bounds per-member entries:
/// a `[none]` or vacuous `[all_or_empty]` match still records the container
/// with its full array value, as it always has.
pub(crate) const ARRAY_MEMBER_CAP: usize = 32;

/// Evaluate an array object-scope match against a resolved field value.
///
/// A scalar (non-array, non-null) value is treated as a single-member array,
/// so `any`/`all` both reduce to "the value satisfies the body". `all`
/// requires a non-empty array; a missing/null value never matches.
pub(crate) fn eval_array_quantified<E: Event>(
    value: &EventValue,
    quantifier: ArrayQuantifier,
    body: &CompiledDetection,
    outer: &E,
) -> bool {
    match value {
        EventValue::Array(members) => match quantifier {
            ArrayQuantifier::Any => members.iter().any(|m| eval_array_body(body, m, outer)),
            ArrayQuantifier::All => {
                !members.is_empty() && members.iter().all(|m| eval_array_body(body, m, outer))
            }
            ArrayQuantifier::AllOrEmpty => members.iter().all(|m| eval_array_body(body, m, outer)),
            ArrayQuantifier::None => !members.iter().any(|m| eval_array_body(body, m, outer)),
        },
        // A null or missing array is empty: `none` holds vacuously, the others
        // do not.
        EventValue::Null => array_quantifier_matches_empty(quantifier),
        // A scalar (non-array, non-null) value is a single-member array.
        single => match quantifier {
            ArrayQuantifier::None => !eval_array_body(body, single, outer),
            _ => eval_array_body(body, single, outer),
        },
    }
}

/// Whether a quantifier matches an empty or missing array (zero members).
pub(crate) fn array_quantifier_matches_empty(quantifier: ArrayQuantifier) -> bool {
    matches!(
        quantifier,
        ArrayQuantifier::None | ArrayQuantifier::AllOrEmpty
    )
}

/// Quantifier verdict from a complete per-member match list.
///
/// Empty input is the missing/empty-array case. Used by explain so truncation
/// of recorded traces cannot change `matched`.
pub(crate) fn array_quantifier_from_member_matches(
    quantifier: ArrayQuantifier,
    member_matched: &[bool],
) -> bool {
    if member_matched.is_empty() {
        return array_quantifier_matches_empty(quantifier);
    }
    match quantifier {
        ArrayQuantifier::Any => member_matched.iter().any(|&m| m),
        ArrayQuantifier::All | ArrayQuantifier::AllOrEmpty => member_matched.iter().all(|&m| m),
        ArrayQuantifier::None => member_matched.iter().all(|&m| !m),
    }
}

/// The member body-verdict that decides a quantifier's node verdict.
///
/// For the existential quantifiers (`any`, `none`) the decisive members are
/// the body-matching ones: they bind an `any` and violate a `none`. For the
/// universal quantifiers (`all`, `all_or_empty`) the decisive members are the
/// failing ones. Recording that class first keeps the diagnostic member (the
/// binding member of a passing `any`, the culprit of a failing `all`) inside
/// the cap even for large arrays.
pub(crate) fn decisive_member_verdict(quantifier: ArrayQuantifier) -> bool {
    matches!(quantifier, ArrayQuantifier::Any | ArrayQuantifier::None)
}

/// Select up to [`ARRAY_MEMBER_CAP`] member indices to record in an explain
/// trace. Members whose body verdict equals `decisive` are selected first,
/// the rest fill any remaining room, and the result is returned in ascending
/// index order.
pub(crate) fn select_recorded_member_indices(
    member_matched: &[bool],
    decisive: bool,
) -> Vec<usize> {
    let cap = ARRAY_MEMBER_CAP.min(member_matched.len());
    let mut selected = Vec::with_capacity(cap);
    for (i, &matched) in member_matched.iter().enumerate() {
        if matched == decisive {
            selected.push(i);
            if selected.len() == cap {
                break;
            }
        }
    }
    if selected.len() < cap {
        for (i, &matched) in member_matched.iter().enumerate() {
            if matched != decisive {
                selected.push(i);
                if selected.len() == cap {
                    break;
                }
            }
        }
    }
    selected.sort_unstable();
    selected
}

/// Path for one array member. Indexed (`field[i]`) for real arrays; the bare
/// field name for a scalar treated as a one-member array, so the path still
/// resolves through [`Event::get_field`].
pub(crate) fn array_member_path(field: &str, index: usize, scalar: bool) -> String {
    if scalar {
        field.to_string()
    } else {
        format!("{field}[{index}]")
    }
}

/// Join a member path with a relative field. `None` is the member itself.
pub(crate) fn join_member_field(member_path: &str, relative: Option<&str>) -> String {
    match relative {
        None | Some("") | Some(".") => member_path.to_string(),
        Some(rel) if member_path.is_empty() => rel.to_string(),
        Some(rel) => format!("{member_path}.{rel}"),
    }
}

/// Evaluate a compiled detection `body` against a single array member.
///
/// Field references inside `body` resolve relative to the member; a body item
/// with no field name matches the member value itself.
pub(crate) fn eval_array_body<E: Event>(
    body: &CompiledDetection,
    member: &EventValue,
    outer: &E,
) -> bool {
    match body {
        CompiledDetection::AllOf(items) => items
            .iter()
            .all(|item| eval_array_item(item, member, outer)),
        CompiledDetection::AnyOf(dets) => dets.iter().any(|d| eval_array_body(d, member, outer)),
        CompiledDetection::And(dets) => dets.iter().all(|d| eval_array_body(d, member, outer)),
        CompiledDetection::ArrayMatch {
            field,
            quantifier,
            body: inner,
        } => match element_field(member, field) {
            Some(value) => eval_array_quantified(value, *quantifier, inner, outer),
            None => array_quantifier_matches_empty(*quantifier),
        },
        // Keywords inside an element scope match the member value directly.
        CompiledDetection::Keywords(matcher) => matcher.matches(member, outer),
        // Extended block body: evaluate the condition over named sub-selections
        // against this member (same-element binding under and/or/not).
        CompiledDetection::Conditional { named, condition } => {
            eval_array_condition(condition, named, member, outer)
        }
    }
}

/// Evaluate an extended block-body `condition` against a single array member.
///
/// Each named sub-selection is evaluated against the member (via
/// [`eval_array_body`]), and the boolean structure (`and`/`or`/`not` and
/// selector quantifiers like `1 of x_*`) is applied. This is the element-scoped
/// analogue of the top-level condition evaluator; it carries no bloom because
/// array members are not bloom-indexed.
pub(crate) fn eval_array_condition<E: Event>(
    expr: &ConditionExpr,
    named: &HashMap<String, CompiledDetection>,
    member: &EventValue,
    outer: &E,
) -> bool {
    match expr {
        ConditionExpr::Identifier(name) => named
            .get(name)
            .is_some_and(|d| eval_array_body(d, member, outer)),
        ConditionExpr::And(exprs) => exprs
            .iter()
            .all(|e| eval_array_condition(e, named, member, outer)),
        ConditionExpr::Or(exprs) => exprs
            .iter()
            .any(|e| eval_array_condition(e, named, member, outer)),
        ConditionExpr::Not(inner) => !eval_array_condition(inner, named, member, outer),
        ConditionExpr::Selector {
            quantifier,
            pattern,
        } => {
            let names: Vec<&String> = named
                .keys()
                .filter(|n| pattern.matches_detection_name(n))
                .collect();
            let count = names
                .iter()
                .filter(|n| {
                    named
                        .get(**n)
                        .is_some_and(|d| eval_array_body(d, member, outer))
                })
                .count() as u64;
            match quantifier {
                Quantifier::Any => count >= 1,
                Quantifier::All => count == names.len() as u64,
                Quantifier::Count(n) => count >= *n,
            }
        }
    }
}

/// Evaluate one body item against an array member.
pub(crate) fn eval_array_item<E: Event>(
    item: &CompiledDetectionItem,
    member: &EventValue,
    outer: &E,
) -> bool {
    if let Some(expect_exists) = item.exists {
        let exists = match &item.field {
            Some(name) => element_field(member, name).is_some(),
            None => true,
        };
        return exists == expect_exists;
    }

    match &item.field {
        Some(name) => match element_field(member, name) {
            Some(value) => item.matcher.matches(value, outer),
            None => item.matcher.matches_absent(),
        },
        // No field name: match the array member value itself.
        None => item.matcher.matches(member, outer),
    }
}

/// Resolve a field path within an array member (an [`EventValue`]).
///
/// Mirrors `JsonEvent::get_field`: a flat key first, then dot-separated
/// traversal that distributes over arrays for object keys and selects a single
/// element for positional `[N]` indices.
pub(crate) fn element_field<'a>(
    member: &'a EventValue<'a>,
    path: &str,
) -> Option<&'a EventValue<'a>> {
    if let EventValue::Map(entries) = member
        && let Some((_, v)) = entries.iter().find(|(k, _)| k.as_ref() == path)
    {
        return Some(v);
    }
    let ops = parse_event_ops(path);
    nav_event_value(member, &ops)
}

enum EventOp<'a> {
    Key(Cow<'a, str>),
    Index(i64),
}

/// Parse a dot path into navigation ops, recognizing positional `name[N]`.
/// Only an unescaped `[...]` is an index; `\[` / `\]` are literal and unescaped
/// into the key.
fn parse_event_ops(path: &str) -> Vec<EventOp<'_>> {
    let mut ops = Vec::new();
    for part in path.split('.') {
        match first_unescaped(part, b'[') {
            Some(bpos) if index_groups(&part[bpos..]).is_some() => {
                let name = &part[..bpos];
                if !name.is_empty() {
                    ops.push(EventOp::Key(unescape_brackets(name)));
                }
                for idx in index_groups(&part[bpos..]).expect("checked") {
                    ops.push(EventOp::Index(idx));
                }
            }
            _ => ops.push(EventOp::Key(unescape_brackets(part))),
        }
    }
    ops
}

/// Parse `[N]` or `[N][M]...` into indices (negative allowed), or `None` if
/// malformed/non-numeric.
fn index_groups(s: &str) -> Option<Vec<i64>> {
    let mut out = Vec::new();
    let mut rem = s;
    while !rem.is_empty() {
        let rest = rem.strip_prefix('[')?;
        let close = rest.find(']')?;
        out.push(rest[..close].parse().ok()?);
        rem = &rest[close + 1..];
    }
    Some(out)
}

fn nav_event_value<'a>(
    current: &'a EventValue<'a>,
    ops: &[EventOp<'_>],
) -> Option<&'a EventValue<'a>> {
    let Some((op, rest)) = ops.split_first() else {
        return Some(current);
    };
    match op {
        EventOp::Key(key) => match current {
            EventValue::Map(entries) => {
                let next = entries
                    .iter()
                    .find(|(k, _)| k.as_ref() == key.as_ref())
                    .map(|(_, v)| v)?;
                nav_event_value(next, rest)
            }
            EventValue::Array(members) => members.iter().find_map(|m| nav_event_value(m, ops)),
            _ => None,
        },
        EventOp::Index(i) => match current {
            EventValue::Array(members) => {
                let idx = crate::event::resolve_array_index(*i, members.len())?;
                nav_event_value(members.get(idx)?, rest)
            }
            _ => None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recorded_indices_under_cap_keep_all_members_in_index_order() {
        let matched = [true, false, true, false, true];
        assert_eq!(
            select_recorded_member_indices(&matched, false),
            vec![0, 1, 2, 3, 4]
        );
        assert_eq!(
            select_recorded_member_indices(&matched, true),
            vec![0, 1, 2, 3, 4]
        );
    }

    #[test]
    fn recorded_indices_keep_decisive_fails_under_truncation() {
        // 30 matches then 10 fails: with fails decisive (all/all_or_empty),
        // every culprit survives the cap even though they sit at the end.
        let matched: Vec<bool> = (0..40).map(|i| i < 30).collect();
        let selected = select_recorded_member_indices(&matched, false);
        assert_eq!(selected.len(), ARRAY_MEMBER_CAP);
        for i in 30..40 {
            assert!(selected.contains(&i), "culprit {i} dropped: {selected:?}");
        }
        assert!(selected.windows(2).all(|w| w[0] < w[1]), "not sorted");
    }

    #[test]
    fn recorded_indices_keep_decisive_match_under_truncation() {
        // One binding member at the very end of a large [any] array: with
        // matches decisive it must survive the cap.
        let matched: Vec<bool> = (0..40).map(|i| i == 39).collect();
        let selected = select_recorded_member_indices(&matched, true);
        assert_eq!(selected.len(), ARRAY_MEMBER_CAP);
        assert!(selected.contains(&39), "binding member dropped");
    }

    #[test]
    fn decisive_verdict_is_true_for_existential_quantifiers() {
        assert!(decisive_member_verdict(ArrayQuantifier::Any));
        assert!(decisive_member_verdict(ArrayQuantifier::None));
        assert!(!decisive_member_verdict(ArrayQuantifier::All));
        assert!(!decisive_member_verdict(ArrayQuantifier::AllOrEmpty));
    }

    #[test]
    fn member_path_indexes_arrays_and_leaves_scalars_bare() {
        assert_eq!(array_member_path("connections", 0, false), "connections[0]");
        assert_eq!(array_member_path("connections", 0, true), "connections");
        assert_eq!(
            join_member_field("connections[0]", Some("protocol")),
            "connections[0].protocol"
        );
        assert_eq!(join_member_field("connections[0]", None), "connections[0]");
        assert_eq!(join_member_field("rules[0]", Some("ip")), "rules[0].ip");
    }

    #[test]
    fn quantifier_from_member_matches_empty_and_all() {
        assert!(array_quantifier_from_member_matches(
            ArrayQuantifier::None,
            &[]
        ));
        assert!(!array_quantifier_from_member_matches(
            ArrayQuantifier::All,
            &[]
        ));
        assert!(array_quantifier_from_member_matches(
            ArrayQuantifier::All,
            &[true, true]
        ));
        assert!(!array_quantifier_from_member_matches(
            ArrayQuantifier::All,
            &[true, false]
        ));
    }
}
