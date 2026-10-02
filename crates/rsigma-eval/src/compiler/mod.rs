//! Compile parsed Sigma rules into optimized in-memory representations.
//!
//! The primary entry point, [`compile_rule`], lowers a `SigmaRule` to HIR via
//! `rsigma_ir::lower_rule` and then materializes the physical forms
//! (`CompiledRule`, `CompiledDetection`, `CompiledDetectionItem`) with
//! [`compile_to_compiled`], which builds the concrete `CompiledMatcher`
//! variants (regex, Aho-Corasick, `IpNet`, lowercased patterns) that evaluate
//! efficiently against events. Modifier interpretation happens during lowering;
//! this module turns the resolved matchers into executable artifacts.

mod array;
mod from_ir;
mod helpers;
#[doc(hidden)]
pub mod optimizer;
#[cfg(test)]
mod tests;
mod value;

pub(crate) use array::{
    array_quantifier_from_member_matches, array_quantifier_matches_empty, decisive_member_verdict,
    element_field, eval_array_body, eval_array_item, eval_array_quantified,
    select_recorded_member_indices,
};

pub use from_ir::compile_to_compiled;

// Re-export so equivalence proptests in other modules and the fuzz target
// can drive the optimizer directly.
#[cfg(test)]
pub(crate) use optimizer::optimize_any_of as optimize_any_of_for_test;

use std::collections::HashMap;
use std::sync::Arc;

#[cfg(test)]
use rsigma_parser::DetectionItem;
use rsigma_parser::{
    ArrayQuantifier, ConditionExpr, Detection, Level, LogSource, Quantifier, SigmaRule,
};

use crate::error::Result;
use crate::event::{Event, EventValue};
use crate::matcher::CompiledMatcher;
use crate::result::{
    DetectionBody, EvaluationResult, FieldMatch, MatchDetailLevel, MatcherKind, ResultBody,
    RuleHeader,
};

pub(crate) use helpers::{yaml_to_json, yaml_to_json_map};

// =============================================================================
// Compiled types
// =============================================================================

/// A compiled Sigma rule, ready for evaluation.
#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub title: String,
    pub id: Option<String>,
    pub level: Option<Level>,
    pub tags: Vec<String>,
    /// The rule's `description`. Retained because it carries the ADS goal
    /// section, which downstream consumers surface alongside a match.
    pub description: Option<String>,
    /// The rule's `falsepositives`, retained as the ADS false-positives
    /// section carrier.
    pub falsepositives: Vec<String>,
    pub logsource: LogSource,
    /// Compiled named detections, keyed by detection name.
    pub detections: HashMap<String, CompiledDetection>,
    /// Condition expression trees (usually one, but can be multiple).
    pub conditions: Vec<ConditionExpr>,
    /// Whether to include the full event JSON in the match result.
    /// Controlled by the `rsigma.include_event` custom attribute.
    pub include_event: bool,
    /// Custom attributes from the original Sigma rule (merged view of
    /// arbitrary top-level keys, the explicit `custom_attributes:` block,
    /// and pipeline `SetCustomAttribute` additions). Propagated to match
    /// results. Wrapped in `Arc` so per-match cloning is a pointer bump.
    pub custom_attributes: Arc<HashMap<String, serde_json::Value>>,
}

/// A compiled detection definition.
#[derive(Debug, Clone)]
pub enum CompiledDetection {
    /// AND-linked detection items (from a YAML mapping).
    AllOf(Vec<CompiledDetectionItem>),
    /// OR-linked sub-detections (from a YAML list of mappings).
    AnyOf(Vec<CompiledDetection>),
    /// Keyword detection: match values across all event fields.
    Keywords(CompiledMatcher),
    /// Array object-scope match: evaluate `body` against the members of the
    /// array at `field`, with `any`/`all` quantification. Within `body`, a
    /// detection item with `field == None` matches the array member itself.
    ArrayMatch {
        field: String,
        quantifier: ArrayQuantifier,
        body: Box<CompiledDetection>,
    },
    /// AND of heterogeneous sub-detections (a mapping mixing plain items with
    /// array object-scope blocks).
    And(Vec<CompiledDetection>),
    /// Extended array object-scope body: named element-scoped sub-selections
    /// combined by `condition` (and/or/not), evaluated against a single array
    /// member. Appears only as an [`ArrayMatch`](CompiledDetection::ArrayMatch)
    /// body.
    Conditional {
        named: HashMap<String, CompiledDetection>,
        condition: ConditionExpr,
    },
}

/// A compiled detection item: a field + matcher.
#[derive(Debug, Clone)]
pub struct CompiledDetectionItem {
    /// The field name to check (`None` for keyword items).
    pub field: Option<String>,
    /// The compiled matcher combining all values with appropriate logic.
    pub matcher: CompiledMatcher,
    /// If `Some(true)`, field must exist; `Some(false)`, must not exist.
    pub exists: Option<bool>,
    /// Pre-computed flag set when the matcher is a positive substring
    /// assertion eligible for bloom-filter pre-filtering. Recomputing the
    /// recursive `is_positive_substring_matcher` walk for every event would
    /// dominate the eval cost on rule sets where most items don't qualify.
    pub bloom_eligible: bool,
}

// =============================================================================
// Public API
// =============================================================================

/// Compile a parsed `SigmaRule` into a `CompiledRule`.
///
/// Routes through the IR layer: `lower_rule` → [`compile_to_compiled`].
pub fn compile_rule(rule: &SigmaRule) -> Result<CompiledRule> {
    let ir = rsigma_ir::lower_rule(rule, &rsigma_ir::LowerOptions::default())?;
    compile_to_compiled(&ir)
}

/// Evaluate a compiled rule against an event, returning an
/// [`EvaluationResult`] if it matches.
///
/// This is the public entry point for one-shot rule evaluation. It does no
/// bloom pre-filtering; every detection item is evaluated directly. Engines
/// that maintain a per-field bloom index should call the crate-private
/// `evaluate_rule_with_bloom` variant via the `Engine` API instead.
pub fn evaluate_rule(rule: &CompiledRule, event: &impl Event) -> Option<EvaluationResult> {
    evaluate_rule_with_bloom(
        rule,
        event,
        &crate::engine::bloom_index::NoBloom,
        MatchDetailLevel::Off,
    )
}

/// Evaluate a compiled rule against an event with bloom pre-filtering.
///
/// `bloom` provides per-field verdicts for positive substring matchers.
/// When `bloom.verdict_for_field(field)` returns `DefinitelyNoMatch`, any
/// positive substring item targeting that field is short-circuited to
/// `false` without invoking its matcher. The pre-filter is purely an
/// optimization: it never changes the eval result vs `evaluate_rule`.
pub(crate) fn evaluate_rule_with_bloom<E, B>(
    rule: &CompiledRule,
    event: &E,
    bloom: &B,
    level: MatchDetailLevel,
) -> Option<EvaluationResult>
where
    E: Event,
    B: crate::engine::bloom_index::BloomLookup,
{
    for condition in &rule.conditions {
        if eval_condition_matches_with_bloom(condition, &rule.detections, event, bloom) {
            let mut matched_selections = Vec::new();
            let matched = eval_condition_with_bloom(
                condition,
                &rule.detections,
                event,
                &mut matched_selections,
                bloom,
            );
            debug_assert!(matched, "detail pass must agree with boolean pass");
            let matched_fields =
                collect_field_matches(&matched_selections, &rule.detections, event, level);

            let event_data = if rule.include_event {
                Some(event.to_json())
            } else {
                None
            };

            return Some(EvaluationResult {
                header: RuleHeader {
                    rule_title: rule.title.clone(),
                    rule_id: rule.id.clone(),
                    level: rule.level,
                    tags: rule.tags.clone(),
                    custom_attributes: rule.custom_attributes.clone(),
                    enrichments: None,
                },
                body: ResultBody::Detection(DetectionBody {
                    matched_selections,
                    matched_fields,
                    event: event_data,
                }),
            });
        }
    }
    None
}

// =============================================================================
// Detection compilation
// =============================================================================

/// Compile a parsed detection tree into a [`CompiledDetection`].
///
/// Routes through the IR layer like [`compile_rule`]: `lower_detection` →
/// the HIR compiler. Returns an error if the detection tree is empty or
/// contains invalid items.
pub fn compile_detection(detection: &Detection) -> Result<CompiledDetection> {
    let opts = rsigma_ir::LowerOptions {
        permissive_placeholders: true,
    };
    from_ir::compile_ir_detection(&rsigma_ir::lower::lower_detection(detection, &opts)?)
}

#[cfg(test)]
fn compile_detection_item(item: &DetectionItem) -> Result<CompiledDetectionItem> {
    let ir = rsigma_ir::lower::lower_detection_item(item, &rsigma_ir::LowerOptions::default())?;
    from_ir::compile_ir_detection_item(&ir)
}

// =============================================================================
// Condition evaluation
// =============================================================================

/// Evaluate a condition expression against the event using compiled detections.
///
/// Returns `true` if the condition is satisfied. Populates `matched_selections`
/// with the names of detections that were evaluated and returned true.
pub fn eval_condition(
    expr: &ConditionExpr,
    detections: &HashMap<String, CompiledDetection>,
    event: &impl Event,
    matched_selections: &mut Vec<String>,
) -> bool {
    eval_condition_with_bloom(
        expr,
        detections,
        event,
        matched_selections,
        &crate::engine::bloom_index::NoBloom,
    )
}

/// Evaluate a condition without collecting match details.
///
/// This is the production fast path for the common nonmatch case. Selectors
/// can stop as soon as their quantifier is decided; matching rules run the
/// detail-collecting evaluator once afterward.
fn eval_condition_matches_with_bloom<E, B>(
    expr: &ConditionExpr,
    detections: &HashMap<String, CompiledDetection>,
    event: &E,
    bloom: &B,
) -> bool
where
    E: Event,
    B: crate::engine::bloom_index::BloomLookup,
{
    match expr {
        ConditionExpr::Identifier(name) => detections
            .get(name)
            .is_some_and(|det| eval_detection_with_bloom(det, event, bloom)),
        ConditionExpr::And(exprs) => exprs
            .iter()
            .all(|e| eval_condition_matches_with_bloom(e, detections, event, bloom)),
        ConditionExpr::Or(exprs) => exprs
            .iter()
            .any(|e| eval_condition_matches_with_bloom(e, detections, event, bloom)),
        ConditionExpr::Not(inner) => {
            !eval_condition_matches_with_bloom(inner, detections, event, bloom)
        }
        ConditionExpr::Selector {
            quantifier,
            pattern,
        } => {
            let mut matching = detections
                .iter()
                .filter(|(name, _)| pattern.matches_detection_name(name));
            match quantifier {
                Quantifier::Any => {
                    matching.any(|(_, det)| eval_detection_with_bloom(det, event, bloom))
                }
                Quantifier::All => {
                    matching.all(|(_, det)| eval_detection_with_bloom(det, event, bloom))
                }
                Quantifier::Count(required) => {
                    if *required == 0 {
                        return true;
                    }
                    let mut matched = 0u64;
                    matching.any(|(_, det)| {
                        if eval_detection_with_bloom(det, event, bloom) {
                            matched += 1;
                        }
                        matched >= *required
                    })
                }
            }
        }
    }
}

/// Bloom-aware version of [`eval_condition`].
///
/// Identical to `eval_condition` except that positive substring leaves are
/// short-circuited to `false` when the bloom proves no pattern can match
/// the event's field value.
pub(crate) fn eval_condition_with_bloom<E, B>(
    expr: &ConditionExpr,
    detections: &HashMap<String, CompiledDetection>,
    event: &E,
    matched_selections: &mut Vec<String>,
    bloom: &B,
) -> bool
where
    E: Event,
    B: crate::engine::bloom_index::BloomLookup,
{
    match expr {
        ConditionExpr::Identifier(name) => {
            if let Some(det) = detections.get(name) {
                let result = eval_detection_with_bloom(det, event, bloom);
                if result {
                    matched_selections.push(name.clone());
                }
                result
            } else {
                false
            }
        }

        ConditionExpr::And(exprs) => exprs
            .iter()
            .all(|e| eval_condition_with_bloom(e, detections, event, matched_selections, bloom)),

        ConditionExpr::Or(exprs) => exprs
            .iter()
            .any(|e| eval_condition_with_bloom(e, detections, event, matched_selections, bloom)),

        ConditionExpr::Not(inner) => {
            !eval_condition_with_bloom(inner, detections, event, matched_selections, bloom)
        }

        ConditionExpr::Selector {
            quantifier,
            pattern,
        } => {
            let matching_names: Vec<&String> = detections
                .keys()
                .filter(|name| pattern.matches_detection_name(name))
                .collect();

            let mut match_count = 0u64;
            for name in &matching_names {
                if let Some(det) = detections.get(*name)
                    && eval_detection_with_bloom(det, event, bloom)
                {
                    match_count += 1;
                    matched_selections.push((*name).clone());
                }
            }

            match quantifier {
                Quantifier::Any => match_count >= 1,
                Quantifier::All => match_count == matching_names.len() as u64,
                Quantifier::Count(n) => match_count >= *n,
            }
        }
    }
}

/// Evaluate a compiled detection item against an event without bloom
/// pre-filtering. Used only by the in-crate compiler tests; the production
/// paths run through `eval_detection_item_with_bloom` from
/// `evaluate_rule_with_bloom`.
#[cfg(test)]
fn eval_detection_item(item: &CompiledDetectionItem, event: &impl Event) -> bool {
    eval_detection_item_with_bloom(item, event, &crate::engine::bloom_index::NoBloom)
}

/// Evaluate a single compiled detection item against an event without bloom
/// pre-filtering. Used by the [`crate::explain`] recording evaluator so each
/// per-item verdict matches the production engine exactly.
pub(crate) fn eval_detection_item_no_bloom(
    item: &CompiledDetectionItem,
    event: &impl Event,
) -> bool {
    eval_detection_item_with_bloom(item, event, &crate::engine::bloom_index::NoBloom)
}

/// Evaluate a compiled detection against an event with a bloom lookup.
fn eval_detection_with_bloom<E, B>(detection: &CompiledDetection, event: &E, bloom: &B) -> bool
where
    E: Event,
    B: crate::engine::bloom_index::BloomLookup,
{
    match detection {
        CompiledDetection::AllOf(items) => items
            .iter()
            .all(|item| eval_detection_item_with_bloom(item, event, bloom)),
        CompiledDetection::AnyOf(dets) => dets
            .iter()
            .any(|d| eval_detection_with_bloom(d, event, bloom)),
        CompiledDetection::Keywords(matcher) => matcher.matches_keyword(event),
        CompiledDetection::ArrayMatch {
            field,
            quantifier,
            body,
        } => match event.get_field(field) {
            Some(value) => eval_array_quantified(&value, *quantifier, body, event),
            None => array_quantifier_matches_empty(*quantifier),
        },
        CompiledDetection::And(dets) => dets
            .iter()
            .all(|d| eval_detection_with_bloom(d, event, bloom)),
        // Only produced as an `ArrayMatch` body (evaluated via
        // `eval_array_condition`). At the top level it degenerates to a
        // sub-rule over the event, which reuses the condition evaluator.
        CompiledDetection::Conditional { named, condition } => {
            eval_condition_with_bloom(condition, named, event, &mut Vec::new(), bloom)
        }
    }
}

/// Evaluate a single detection item with bloom pre-filtering.
///
/// When the matcher targets a single field and is a positive substring
/// matcher (not under negation), the bloom verdict is consulted first. A
/// `DefinitelyNoMatch` verdict guarantees the matcher would return `false`,
/// so we return early without invoking it.
fn eval_detection_item_with_bloom<E, B>(item: &CompiledDetectionItem, event: &E, bloom: &B) -> bool
where
    E: Event,
    B: crate::engine::bloom_index::BloomLookup,
{
    if let Some(expect_exists) = item.exists {
        if let Some(field) = &item.field {
            return event.get_field(field).is_some() == expect_exists;
        }
        return !expect_exists;
    }

    match &item.field {
        Some(field_name) => {
            if let Some(value) = event.get_field(field_name) {
                if item.bloom_eligible
                    && bloom.verdict_for_field(field_name)
                        == crate::engine::bloom_index::BloomVerdict::DefinitelyNoMatch
                {
                    return false;
                }
                item.matcher.matches(&value, event)
            } else {
                matches!(item.matcher, CompiledMatcher::Null)
            }
        }
        None => item.matcher.matches_keyword(event),
    }
}

/// Cap on the number of keyword-match entries recorded per keyword detection
/// at `Summary` / `Full`. A single high-cardinality event (many string
/// leaves) cannot blow up the output line.
const MAX_KEYWORD_MATCHES: usize = 16;

/// Collect field matches from matched selections for the detection result.
///
/// At [`MatchDetailLevel::Off`] this reproduces the historical behavior
/// exactly: one `{ field, value }` entry per field-present `AllOf` item that
/// matched, with keyword and absence matches omitted. At `Summary` / `Full`
/// it attaches the matcher descriptor and reports the previously dropped
/// keyword and `Null`-on-absent matches.
fn collect_field_matches(
    selection_names: &[String],
    detections: &HashMap<String, CompiledDetection>,
    event: &impl Event,
    level: MatchDetailLevel,
) -> Vec<FieldMatch> {
    let mut matches = Vec::new();
    for name in selection_names {
        if let Some(det) = detections.get(name) {
            collect_detection_fields(name, det, event, level, &mut matches);
        }
    }
    matches
}

fn collect_detection_fields(
    selection: &str,
    detection: &CompiledDetection,
    event: &impl Event,
    level: MatchDetailLevel,
    out: &mut Vec<FieldMatch>,
) {
    match detection {
        CompiledDetection::AllOf(items) => {
            for item in items {
                match &item.field {
                    Some(field_name) => {
                        if let Some(value) = event.get_field(field_name) {
                            if item.matcher.matches(&value, event) {
                                out.push(make_field_match(
                                    selection,
                                    field_name,
                                    value.to_json(),
                                    &item.matcher,
                                    level,
                                ));
                            }
                        } else if level != MatchDetailLevel::Off
                            && matches!(
                                item.matcher,
                                CompiledMatcher::Null | CompiledMatcher::Exists(false)
                            )
                        {
                            // Field absent and matched by the `Null` matcher or
                            // an `|exists: false` assertion. Never reported at
                            // `Off` (preserves wire shape).
                            out.push(make_field_match(
                                selection,
                                field_name,
                                serde_json::Value::Null,
                                &item.matcher,
                                level,
                            ));
                        }
                    }
                    None => {
                        // Keyword item inside an `AllOf`. Only reported above `Off`.
                        if level != MatchDetailLevel::Off {
                            collect_keyword_matches(selection, &item.matcher, event, level, out);
                        }
                    }
                }
            }
        }
        CompiledDetection::AnyOf(dets) => {
            for d in dets {
                if eval_detection_with_bloom(d, event, &crate::engine::bloom_index::NoBloom) {
                    collect_detection_fields(selection, d, event, level, out);
                }
            }
        }
        CompiledDetection::ArrayMatch { field, body, .. } => {
            let value = event.get_field(field);
            collect_array_match_fields(
                selection,
                field,
                body,
                value.as_ref(),
                event,
                level,
                "",
                out,
            );
        }
        CompiledDetection::And(dets) => {
            for d in dets {
                if eval_detection_with_bloom(d, event, &crate::engine::bloom_index::NoBloom) {
                    collect_detection_fields(selection, d, event, level, out);
                }
            }
        }
        // Top-level Conditional is only produced as an array body; member
        // recording happens in `collect_array_body_fields`.
        CompiledDetection::Conditional { .. } => {}
        CompiledDetection::Keywords(matcher) => {
            // Keyword detections produced no entries historically; only
            // reported above `Off`.
            if level != MatchDetailLevel::Off {
                collect_keyword_matches(selection, matcher, event, level, out);
            }
        }
    }
}

/// Record binding members of a matched `ArrayMatch`.
///
/// Matching members are emitted with indexed paths (`field[i].leaf`) up to
/// [`array::ARRAY_MEMBER_CAP`]. A scalar treated as one member uses the
/// un-indexed path so it still resolves through [`Event::get_field`]. `[none]`
/// and vacuous `[all_or_empty]` have no binding member and keep the container.
#[allow(clippy::too_many_arguments)]
fn collect_array_match_fields<E: Event>(
    selection: &str,
    field: &str,
    body: &CompiledDetection,
    value: Option<&EventValue>,
    outer: &E,
    level: MatchDetailLevel,
    path_prefix: &str,
    out: &mut Vec<FieldMatch>,
) {
    let container_path = if path_prefix.is_empty() {
        field.to_string()
    } else {
        array::join_member_field(path_prefix, Some(field))
    };

    let (scalar, members): (bool, Vec<&EventValue>) = match value {
        None => return,
        Some(EventValue::Null) => {
            out.push(FieldMatch::new(container_path, serde_json::Value::Null));
            return;
        }
        Some(EventValue::Array(items)) if items.is_empty() => {
            out.push(FieldMatch::new(
                container_path,
                serde_json::Value::Array(Vec::new()),
            ));
            return;
        }
        Some(EventValue::Array(items)) => (false, items.iter().collect()),
        Some(single) => (true, vec![single]),
    };

    let matching: Vec<usize> = members
        .iter()
        .enumerate()
        .filter(|(_, m)| array::eval_array_body(body, m, outer))
        .map(|(i, _)| i)
        .take(array::ARRAY_MEMBER_CAP)
        .collect();

    if matching.is_empty() {
        if let Some(v) = value {
            out.push(FieldMatch::new(container_path, v.to_json()));
        }
        return;
    }

    for i in matching {
        let member_path = array::array_member_path(&container_path, i, scalar);
        let before = out.len();
        collect_array_body_fields(selection, body, members[i], outer, level, &member_path, out);
        // A binding member whose body produced no leaf entries (e.g. only
        // `not` branches matched) is still recorded as a whole. At `Off` the
        // only leafless cases are level-gated ones (keywords, absent-field
        // matches), which top-level selections also suppress, so the fallback
        // must not resurrect them.
        if out.len() == before && level != MatchDetailLevel::Off {
            out.push(FieldMatch::new(member_path, members[i].to_json()));
        }
    }
}

fn collect_array_body_fields<E: Event>(
    selection: &str,
    body: &CompiledDetection,
    member: &EventValue,
    outer: &E,
    level: MatchDetailLevel,
    member_path: &str,
    out: &mut Vec<FieldMatch>,
) {
    match body {
        CompiledDetection::AllOf(items) => {
            for item in items {
                if !array::eval_array_item(item, member, outer) {
                    continue;
                }
                let relative = item.field.as_deref();
                let absent =
                    relative.is_some_and(|name| array::element_field(member, name).is_none());
                if absent && level == MatchDetailLevel::Off {
                    continue;
                }
                let path = array::join_member_field(member_path, relative);
                let value = match relative {
                    Some(name) => array::element_field(member, name)
                        .map(|v| v.to_json())
                        .unwrap_or(serde_json::Value::Null),
                    None => member.to_json(),
                };
                out.push(make_field_match(
                    selection,
                    &path,
                    value,
                    &item.matcher,
                    level,
                ));
            }
        }
        CompiledDetection::AnyOf(dets) | CompiledDetection::And(dets) => {
            for d in dets {
                if array::eval_array_body(d, member, outer) {
                    collect_array_body_fields(selection, d, member, outer, level, member_path, out);
                }
            }
        }
        CompiledDetection::ArrayMatch {
            field, body: inner, ..
        } => {
            collect_array_match_fields(
                selection,
                field,
                inner,
                array::element_field(member, field),
                outer,
                level,
                member_path,
                out,
            );
        }
        CompiledDetection::Keywords(matcher) => {
            if level != MatchDetailLevel::Off && matcher.matches(member, outer) {
                let d = matcher.describe();
                out.push(FieldMatch {
                    field: member_path.to_string(),
                    value: member.to_json(),
                    selection: Some(selection.to_string()),
                    matcher: Some(MatcherKind::Keyword),
                    pattern: if level == MatchDetailLevel::Full {
                        d.pattern
                    } else {
                        None
                    },
                    case_sensitive: d.case_sensitive,
                    negated: d.negated,
                });
            }
        }
        CompiledDetection::Conditional { named, condition } => {
            collect_array_condition_fields(
                selection,
                condition,
                named,
                member,
                outer,
                level,
                member_path,
                out,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn collect_array_condition_fields<E: Event>(
    selection: &str,
    expr: &ConditionExpr,
    named: &HashMap<String, CompiledDetection>,
    member: &EventValue,
    outer: &E,
    level: MatchDetailLevel,
    member_path: &str,
    out: &mut Vec<FieldMatch>,
) {
    match expr {
        ConditionExpr::Identifier(name) => {
            if let Some(det) = named.get(name)
                && array::eval_array_body(det, member, outer)
            {
                collect_array_body_fields(selection, det, member, outer, level, member_path, out);
            }
        }
        ConditionExpr::And(exprs) | ConditionExpr::Or(exprs) => {
            for e in exprs {
                collect_array_condition_fields(
                    selection,
                    e,
                    named,
                    member,
                    outer,
                    level,
                    member_path,
                    out,
                );
            }
        }
        ConditionExpr::Not(_) => {}
        ConditionExpr::Selector { pattern, .. } => {
            let mut names: Vec<&String> = named
                .keys()
                .filter(|n| pattern.matches_detection_name(n))
                .collect();
            names.sort();
            for name in names {
                if let Some(det) = named.get(name)
                    && array::eval_array_body(det, member, outer)
                {
                    collect_array_body_fields(
                        selection,
                        det,
                        member,
                        outer,
                        level,
                        member_path,
                        out,
                    );
                }
            }
        }
    }
}

/// Build a [`FieldMatch`] at the requested detail level. `Off` yields the
/// bare `{ field, value }` shape; `Summary` adds the matcher descriptor;
/// `Full` additionally records the pattern.
fn make_field_match(
    selection: &str,
    field: &str,
    value: serde_json::Value,
    matcher: &CompiledMatcher,
    level: MatchDetailLevel,
) -> FieldMatch {
    match level {
        MatchDetailLevel::Off => FieldMatch::new(field, value),
        MatchDetailLevel::Summary | MatchDetailLevel::Full => {
            let d = matcher.describe();
            FieldMatch {
                field: field.to_string(),
                value,
                selection: Some(selection.to_string()),
                matcher: Some(d.kind),
                pattern: if level == MatchDetailLevel::Full {
                    d.pattern
                } else {
                    None
                },
                case_sensitive: d.case_sensitive,
                negated: d.negated,
            }
        }
    }
}

/// Record the individual event string values that satisfied a keyword
/// matcher, capped at [`MAX_KEYWORD_MATCHES`]. Each entry uses the sentinel
/// field name `"keyword"`.
fn collect_keyword_matches(
    selection: &str,
    matcher: &CompiledMatcher,
    event: &impl Event,
    level: MatchDetailLevel,
    out: &mut Vec<FieldMatch>,
) {
    let descriptor = matcher.describe();
    let mut count = 0;
    for s in event.all_string_values() {
        if count >= MAX_KEYWORD_MATCHES {
            break;
        }
        if matcher.matches_str(&s) {
            count += 1;
            out.push(FieldMatch {
                field: "keyword".to_string(),
                value: serde_json::Value::String(s.into_owned()),
                selection: Some(selection.to_string()),
                matcher: Some(MatcherKind::Keyword),
                pattern: if level == MatchDetailLevel::Full {
                    descriptor.pattern.clone()
                } else {
                    None
                },
                case_sensitive: descriptor.case_sensitive,
                negated: descriptor.negated,
            });
        }
    }
}
