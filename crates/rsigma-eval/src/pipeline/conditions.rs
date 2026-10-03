//! Pipeline conditions that gate when transformations are applied.
//!
//! Three levels of conditions:
//! - **Rule conditions**: evaluated against the whole `SigmaRule`
//! - **Detection item conditions**: evaluated against individual `DetectionItem` values
//! - **Field name conditions**: evaluated against field names in detection items

use std::collections::{HashMap, HashSet};

use regex::Regex;

use rsigma_parser::{
    ConditionExpr, CorrelationRule, Detection, DetectionItem, LogSource, Modifier, SigmaRule,
    SigmaString, SigmaValue, SpecialChar, StringPart, parse_condition,
};

use super::state::PipelineState;
use crate::error::{EvalError, Result};

// =============================================================================
// Condition linking
// =============================================================================

/// Logical operator used to link a condition list.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ConditionOp {
    /// Every condition must match.
    #[default]
    And,
    /// At least one condition must match.
    Or,
}

/// A condition paired with the identifier used by condition expressions.
#[derive(Debug, Clone)]
pub struct NamedCondition<T> {
    /// Identifier used in a `*_cond_expr` expression.
    pub id: String,
    /// Parsed condition.
    pub condition: T,
}

/// Conditions and their pySigma-compatible linking behavior.
#[derive(Debug, Clone)]
pub struct ConditionSet<T> {
    /// Parsed conditions in source order.
    pub conditions: Vec<NamedCondition<T>>,
    /// Default list-linking operator when no expression is present.
    pub op: ConditionOp,
    /// Whether to negate the linked result.
    pub negated: bool,
    /// Optional logical expression over condition identifiers.
    pub expression: Option<String>,
}

impl<T> Default for ConditionSet<T> {
    fn default() -> Self {
        Self {
            conditions: Vec::new(),
            op: ConditionOp::And,
            negated: false,
            expression: None,
        }
    }
}

impl<T> ConditionSet<T> {
    /// Evaluate this set with the supplied condition matcher.
    pub fn matches(&self, mut matcher: impl FnMut(&T) -> bool) -> bool {
        let matched = if let Some(expression) = &self.expression {
            let results = self
                .conditions
                .iter()
                .map(|named| (named.id.clone(), matcher(&named.condition)))
                .collect();
            eval_condition_expr(expression, &results)
        } else {
            match self.op {
                ConditionOp::And => self
                    .conditions
                    .iter()
                    .all(|named| matcher(&named.condition)),
                ConditionOp::Or => self
                    .conditions
                    .iter()
                    .any(|named| matcher(&named.condition)),
            }
        };

        if self.negated { !matched } else { matched }
    }
}

/// A rule-level condition paired with an optional expression identifier.
///
/// Retained for source compatibility with the pre-`ConditionSet` API.
#[derive(Debug, Clone)]
pub struct NamedRuleCondition {
    /// Optional condition expression identifier.
    pub id: Option<String>,
    /// Parsed rule condition.
    pub condition: RuleCondition,
}
/// A detection-item condition with its expression identifier.
pub type NamedDetectionItemCondition = NamedCondition<DetectionItemCondition>;
/// A field-name condition with its expression identifier.
pub type NamedFieldNameCondition = NamedCondition<FieldNameCondition>;

/// Check whether every named rule condition matches.
///
/// This compatibility helper retains the pre-`ConditionSet` API. New code
/// should call [`ConditionSet::matches`] to honor configured linking,
/// negation, and expressions.
pub fn all_rule_conditions_match(
    conditions: &[NamedRuleCondition],
    rule: &SigmaRule,
    state: &PipelineState,
) -> bool {
    conditions
        .iter()
        .all(|named| named.condition.matches_rule(rule, state))
}

/// Comparison operator for `processing_state` conditions.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum StateOperator {
    #[default]
    Eq,
    Ne,
    Gte,
    Gt,
    Lte,
    Lt,
}

impl StateOperator {
    fn matches(self, actual: &serde_json::Value, expected: &serde_json::Value) -> bool {
        match self {
            StateOperator::Eq => state_values_equal(actual, expected),
            StateOperator::Ne => !state_values_equal(actual, expected),
            StateOperator::Gte => compare_state_values(actual, expected).is_some_and(|o| o.is_ge()),
            StateOperator::Gt => compare_state_values(actual, expected).is_some_and(|o| o.is_gt()),
            StateOperator::Lte => compare_state_values(actual, expected).is_some_and(|o| o.is_le()),
            StateOperator::Lt => compare_state_values(actual, expected).is_some_and(|o| o.is_lt()),
        }
    }
}

fn state_values_equal(actual: &serde_json::Value, expected: &serde_json::Value) -> bool {
    match (actual, expected) {
        (serde_json::Value::Number(_), serde_json::Value::Number(_)) => {
            compare_state_values(actual, expected).is_some_and(|o| o.is_eq())
        }
        _ => actual == expected,
    }
}

fn compare_state_values(
    actual: &serde_json::Value,
    expected: &serde_json::Value,
) -> Option<std::cmp::Ordering> {
    match (actual, expected) {
        (serde_json::Value::Number(a), serde_json::Value::Number(b)) => {
            if a.is_f64() || b.is_f64() {
                return a.as_f64()?.partial_cmp(&b.as_f64()?);
            }
            if let (Some(a), Some(b)) = (a.as_i64(), b.as_i64()) {
                return Some(a.cmp(&b));
            }
            if let (Some(a), Some(b)) = (a.as_u64(), b.as_u64()) {
                return Some(a.cmp(&b));
            }
            if let (Some(a), Some(b)) = (a.as_i64(), b.as_u64()) {
                return Some(if a < 0 {
                    std::cmp::Ordering::Less
                } else {
                    (a as u64).cmp(&b)
                });
            }
            if let (Some(a), Some(b)) = (a.as_u64(), b.as_i64()) {
                return Some(if b < 0 {
                    std::cmp::Ordering::Greater
                } else {
                    a.cmp(&(b as u64))
                });
            }
            None
        }
        (serde_json::Value::String(a), serde_json::Value::String(b)) => Some(a.cmp(b)),
        (serde_json::Value::Bool(a), serde_json::Value::Bool(b)) => Some(a.cmp(b)),
        _ => None,
    }
}

// =============================================================================
// Rule Conditions
// =============================================================================

/// A condition evaluated against a `SigmaRule` (or `CorrelationRule`).
#[derive(Debug, Clone)]
pub enum RuleCondition {
    /// Match logsource fields (category, product, service). `None` = any.
    Logsource {
        category: Option<String>,
        product: Option<String>,
        service: Option<String>,
    },

    /// Rule contains a detection item matching the given field and value.
    ContainsDetectionItem {
        field: String,
        value: Option<String>,
    },

    /// A specific processing item was applied earlier.
    ProcessingItemApplied { processing_item_id: String },

    /// Check pipeline state key-value.
    ProcessingState {
        key: String,
        val: serde_json::Value,
        op: StateOperator,
    },

    /// Always true for detection rules.
    IsSigmaRule,

    /// Always true for correlation rules.
    IsSigmaCorrelationRule,

    /// Match a rule attribute (level, status, etc.) against a value.
    RuleAttribute { attribute: String, value: String },

    /// Rule has a specific tag.
    Tag { tag: String },
}

impl RuleCondition {
    /// Check if this condition matches a detection rule.
    pub fn matches_rule(&self, rule: &SigmaRule, state: &PipelineState) -> bool {
        match self {
            RuleCondition::Logsource {
                category,
                product,
                service,
            } => logsource_matches(&rule.logsource, category, product, service),

            RuleCondition::ContainsDetectionItem { field, value } => {
                rule_contains_detection_item(&rule.detection.named, field, value.as_deref())
            }

            RuleCondition::ProcessingItemApplied { processing_item_id } => {
                state.was_applied(processing_item_id)
            }

            RuleCondition::ProcessingState { key, val, op } => state
                .get_state(key)
                .is_some_and(|actual| op.matches(actual, val)),

            RuleCondition::IsSigmaRule => true,
            RuleCondition::IsSigmaCorrelationRule => false,

            RuleCondition::RuleAttribute { attribute, value } => {
                rule_attribute_matches(rule, attribute, value)
            }

            RuleCondition::Tag { tag } => rule.tags.iter().any(|t| t == tag),
        }
    }

    /// Check if this condition matches a correlation rule.
    pub fn matches_correlation(&self, _corr: &CorrelationRule, state: &PipelineState) -> bool {
        match self {
            RuleCondition::IsSigmaRule => false,
            RuleCondition::IsSigmaCorrelationRule => true,
            RuleCondition::ProcessingItemApplied { processing_item_id } => {
                state.was_applied(processing_item_id)
            }
            RuleCondition::ProcessingState { key, val, op } => state
                .get_state(key)
                .is_some_and(|actual| op.matches(actual, val)),
            _ => false,
        }
    }
}

// =============================================================================
// Detection Item Conditions
// =============================================================================

/// How a value condition combines its per-value results.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ValueMatch {
    /// At least one value must match.
    #[default]
    Any,
    /// Every value must match.
    All,
}

impl ValueMatch {
    fn combine(self, mut results: impl Iterator<Item = bool>) -> bool {
        match self {
            ValueMatch::Any => results.any(|matched| matched),
            ValueMatch::All => results.all(|matched| matched),
        }
    }
}

/// A condition evaluated against individual detection item values.
#[derive(Debug, Clone)]
pub enum DetectionItemCondition {
    /// String values match a pre-compiled regex anchored at the start of the
    /// value. `negate` inverts each value's result before `cond` combines
    /// them; values that are not strings never match.
    MatchString {
        regex: Regex,
        negate: bool,
        cond: ValueMatch,
    },

    /// Detection item values are null. `negate` inverts the combined result.
    IsNull { negate: bool, cond: ValueMatch },

    /// A specific processing item was applied.
    ProcessingItemApplied { processing_item_id: String },

    /// Check pipeline state.
    ProcessingState {
        key: String,
        val: serde_json::Value,
        op: StateOperator,
    },
}

impl DetectionItemCondition {
    /// Check if this condition matches a detection item's values.
    pub fn matches_item(&self, item: &DetectionItem, state: &PipelineState) -> bool {
        match self {
            DetectionItemCondition::MatchString {
                regex,
                negate,
                cond,
            } => cond.combine(item.values.iter().map(|value| {
                let matched = match value {
                    SigmaValue::String(s) => string_value_text(item, s)
                        .is_some_and(|text| matches_at_start(regex, &text)),
                    _ => false,
                };
                matched != *negate
            })),

            DetectionItemCondition::IsNull { negate, cond } => {
                let matched = cond.combine(
                    item.values
                        .iter()
                        .map(|value| matches!(value, SigmaValue::Null)),
                );
                matched != *negate
            }

            DetectionItemCondition::ProcessingItemApplied { processing_item_id } => {
                state.detection_item_was_processed_by(item, processing_item_id)
            }

            DetectionItemCondition::ProcessingState { key, val, op } => state
                .get_state(key)
                .is_some_and(|actual| op.matches(actual, val)),
        }
    }
}

// =============================================================================
// Field Name Conditions
// =============================================================================

/// Pre-compiled field match list — either plain strings or compiled regexes.
#[derive(Debug, Clone)]
pub enum FieldMatcher {
    /// Exact string comparison.
    Plain(Vec<String>),
    /// Pre-compiled regex patterns.
    Regex(Vec<regex::Regex>),
}

/// Legacy enum kept for pipeline parsing compatibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldMatchType {
    /// Exact string comparison.
    Plain,
    /// Regex pattern matching.
    Regex,
}

/// A condition evaluated against field names in detection items.
#[derive(Debug, Clone)]
pub enum FieldNameCondition {
    /// Field name must be in the include list.
    IncludeFields { matcher: FieldMatcher },

    /// Field name must NOT be in the exclude list.
    ExcludeFields { matcher: FieldMatcher },

    /// A specific processing item was applied.
    ProcessingItemApplied { processing_item_id: String },

    /// Check pipeline state.
    ProcessingState {
        key: String,
        val: serde_json::Value,
        op: StateOperator,
    },
}

impl FieldNameCondition {
    /// Check if this condition matches a field name.
    pub fn matches_field_name(&self, field_name: &str, state: &PipelineState) -> bool {
        self.matches_field(Some(field_name), state)
    }

    /// Check if this condition matches an optional field name. Keyword
    /// detection items have no field name: include conditions reject them
    /// and exclude conditions accept them.
    pub fn matches_field(&self, field_name: Option<&str>, state: &PipelineState) -> bool {
        match self {
            FieldNameCondition::IncludeFields { matcher } => {
                field_name.is_some_and(|name| field_matches(name, matcher))
            }

            FieldNameCondition::ExcludeFields { matcher } => {
                !field_name.is_some_and(|name| field_matches(name, matcher))
            }

            FieldNameCondition::ProcessingItemApplied { processing_item_id } => field_name
                .is_some_and(|name| state.field_was_processed_by(name, processing_item_id)),

            FieldNameCondition::ProcessingState { key, val, op } => state
                .get_state(key)
                .is_some_and(|actual| op.matches(actual, val)),
        }
    }

    /// Check if this condition matches a detection item: its field name, or
    /// the target of any of its field references.
    pub fn matches_detection_item(&self, item: &DetectionItem, state: &PipelineState) -> bool {
        self.matches_field(item.field.name.as_deref(), state)
            || (item.field.modifiers.contains(&Modifier::FieldRef)
                && item.values.iter().any(|value| match value {
                    SigmaValue::String(target) => target
                        .as_plain()
                        .is_some_and(|name| self.matches_field(Some(&name), state)),
                    _ => false,
                }))
    }
}

// =============================================================================
// Condition expression evaluation
// =============================================================================

/// Evaluate a logical expression string over a map of condition results.
///
/// The expression can use `and`, `or`, `not`, parentheses, and condition IDs.
pub fn eval_condition_expr(expr: &str, results: &HashMap<String, bool>) -> bool {
    parse_condition(expr)
        .map(|parsed| eval_parsed_condition(&parsed, results))
        .unwrap_or(false)
}

fn eval_parsed_condition(expr: &ConditionExpr, results: &HashMap<String, bool>) -> bool {
    match expr {
        ConditionExpr::Identifier(id) => results.get(id).copied().unwrap_or(false),
        ConditionExpr::And(children) => children
            .iter()
            .all(|child| eval_parsed_condition(child, results)),
        ConditionExpr::Or(children) => children
            .iter()
            .any(|child| eval_parsed_condition(child, results)),
        ConditionExpr::Not(child) => !eval_parsed_condition(child, results),
        ConditionExpr::Selector { .. } => false,
    }
}

/// Validate a condition expression and its references.
pub(crate) fn validate_condition_expr(expr: &str, ids: &[String], label: &str) -> Result<()> {
    let parsed = parse_condition(expr).map_err(|error| {
        EvalError::InvalidModifiers(format!("invalid {label} expression '{expr}': {error}"))
    })?;
    let mut referenced = HashSet::new();
    collect_condition_ids(&parsed, &mut referenced).map_err(|()| {
        EvalError::InvalidModifiers(format!(
            "{label} expression must contain only condition identifiers and boolean operators"
        ))
    })?;

    let defined: HashSet<&str> = ids.iter().map(String::as_str).collect();
    let unknown: Vec<&str> = referenced
        .iter()
        .map(String::as_str)
        .filter(|id| !defined.contains(id))
        .collect();
    if !unknown.is_empty() {
        return Err(EvalError::InvalidModifiers(format!(
            "{label} expression references unknown condition identifier(s): {}",
            unknown.join(", ")
        )));
    }

    let unreferenced: Vec<&str> = ids
        .iter()
        .map(String::as_str)
        .filter(|id| !referenced.contains(*id))
        .collect();
    if !unreferenced.is_empty() {
        return Err(EvalError::InvalidModifiers(format!(
            "{label} expression leaves condition identifier(s) unreferenced: {}",
            unreferenced.join(", ")
        )));
    }

    Ok(())
}

fn collect_condition_ids(
    expr: &ConditionExpr,
    ids: &mut HashSet<String>,
) -> std::result::Result<(), ()> {
    match expr {
        ConditionExpr::Identifier(id) => {
            ids.insert(id.clone());
            Ok(())
        }
        ConditionExpr::And(children) | ConditionExpr::Or(children) => {
            for child in children {
                collect_condition_ids(child, ids)?;
            }
            Ok(())
        }
        ConditionExpr::Not(child) => collect_condition_ids(child, ids),
        ConditionExpr::Selector { .. } => Err(()),
    }
}

// =============================================================================
// Helper functions
// =============================================================================

fn logsource_matches(
    ls: &LogSource,
    category: &Option<String>,
    product: &Option<String>,
    service: &Option<String>,
) -> bool {
    if let Some(cat) = category {
        match &ls.category {
            Some(lc) if lc.eq_ignore_ascii_case(cat) => {}
            _ => return false,
        }
    }
    if let Some(prod) = product {
        match &ls.product {
            Some(lp) if lp.eq_ignore_ascii_case(prod) => {}
            _ => return false,
        }
    }
    if let Some(svc) = service {
        match &ls.service {
            Some(ls_svc) if ls_svc.eq_ignore_ascii_case(svc) => {}
            _ => return false,
        }
    }
    true
}

fn rule_contains_detection_item(
    named: &std::collections::HashMap<String, Detection>,
    field: &str,
    value: Option<&str>,
) -> bool {
    for detection in named.values() {
        if detection_contains_item(detection, field, value) {
            return true;
        }
    }
    false
}

fn detection_contains_item(detection: &Detection, field: &str, value: Option<&str>) -> bool {
    match detection {
        Detection::AllOf(items) => items.iter().any(|item| item_matches(item, field, value)),
        Detection::AnyOf(subs) => subs
            .iter()
            .any(|sub| detection_contains_item(sub, field, value)),
        Detection::ArrayMatch { body, .. } => detection_contains_item(body, field, value),
        Detection::And(subs) => subs
            .iter()
            .any(|sub| detection_contains_item(sub, field, value)),
        Detection::Conditional { named, .. } => named
            .values()
            .any(|sub| detection_contains_item(sub, field, value)),
        Detection::Keywords(_) => false,
    }
}

fn item_matches(item: &DetectionItem, field: &str, value: Option<&str>) -> bool {
    let field_match = item
        .field
        .name
        .as_ref()
        .is_some_and(|n| n.eq_ignore_ascii_case(field));

    if !field_match {
        return false;
    }

    if let Some(val) = value {
        item.values.iter().any(|v| match v {
            SigmaValue::String(s) => s
                .as_plain()
                .unwrap_or_else(|| s.original.clone())
                .eq_ignore_ascii_case(val),
            SigmaValue::Integer(i) => i.to_string() == val,
            SigmaValue::Float(f) => f.to_string() == val,
            SigmaValue::Bool(b) => b.to_string() == val,
            SigmaValue::Null => val == "null",
        })
    } else {
        true // Just checking field existence, no value constraint
    }
}

fn rule_attribute_matches(rule: &SigmaRule, attribute: &str, value: &str) -> bool {
    match attribute {
        "level" => rule
            .level
            .as_ref()
            .is_some_and(|l| format!("{l:?}").eq_ignore_ascii_case(value)),
        "status" => rule
            .status
            .as_ref()
            .is_some_and(|s| format!("{s:?}").eq_ignore_ascii_case(value)),
        "author" => rule
            .author
            .as_deref()
            .is_some_and(|a| a.eq_ignore_ascii_case(value)),
        "title" => rule.title.eq_ignore_ascii_case(value),
        "id" => rule.id.as_deref().is_some_and(|id| id == value),
        "date" => rule.date.as_deref().is_some_and(|d| d == value),
        "description" => rule
            .description
            .as_deref()
            .is_some_and(|d| d.contains(value)),
        _ => false,
    }
}

fn field_matches(field_name: &str, matcher: &FieldMatcher) -> bool {
    match matcher {
        FieldMatcher::Plain(fields) => fields.iter().any(|f| f == field_name),
        FieldMatcher::Regex(regexes) => regexes.iter().any(|re| matches_at_start(re, field_name)),
    }
}

/// Python `re.match` semantics: the leftmost match must begin at offset 0.
fn matches_at_start(regex: &Regex, text: &str) -> bool {
    regex.find(text).is_some_and(|m| m.start() == 0)
}

/// The text pySigma matches for a string value once the item's modifiers are
/// applied: literal `*` and `?` escaped, wildcards bare, and `contains`,
/// `startswith`, and `endswith` adding their wildcards. `None` when pySigma
/// holds the value as a non-string type (field references, regular
/// expressions, CIDR, comparisons, timestamp parts) or as an encoded string.
fn string_value_text(item: &DetectionItem, s: &SigmaString) -> Option<String> {
    let modifiers = &item.field.modifiers;
    let non_string = modifiers.iter().any(|modifier| {
        matches!(
            modifier,
            Modifier::FieldRef
                | Modifier::Re
                | Modifier::Cidr
                | Modifier::Exists
                | Modifier::Gt
                | Modifier::Gte
                | Modifier::Lt
                | Modifier::Lte
                | Modifier::Base64
                | Modifier::Base64Offset
                | Modifier::Wide
                | Modifier::Utf16be
                | Modifier::Utf16
                | Modifier::WindAsh
                | Modifier::Minute
                | Modifier::Hour
                | Modifier::Day
                | Modifier::Week
                | Modifier::Month
                | Modifier::Year
        )
    });
    if non_string {
        return None;
    }
    let mut text: String = s
        .parts
        .iter()
        .map(|part| match part {
            StringPart::Plain(plain) => plain.replace('*', "\\*").replace('?', "\\?"),
            StringPart::Special(SpecialChar::WildcardMulti) => "*".to_string(),
            StringPart::Special(SpecialChar::WildcardSingle) => "?".to_string(),
        })
        .collect();
    let starts_wild = matches!(
        s.parts.first(),
        Some(StringPart::Special(SpecialChar::WildcardMulti))
    );
    let ends_wild = matches!(
        s.parts.last(),
        Some(StringPart::Special(SpecialChar::WildcardMulti))
    );
    let contains = modifiers.contains(&Modifier::Contains);
    let mut prefixed = false;
    if (contains || modifiers.contains(&Modifier::EndsWith)) && !starts_wild {
        text.insert(0, '*');
        prefixed = true;
    }
    let ends_wild = ends_wild || (prefixed && s.parts.is_empty());
    if (contains || modifiers.contains(&Modifier::StartsWith)) && !ends_wild {
        text.push('*');
    }
    Some(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_eval_condition_expr_simple() {
        let mut results = HashMap::new();
        results.insert("cond1".to_string(), true);
        results.insert("cond2".to_string(), false);

        assert!(eval_condition_expr("cond1", &results));
        assert!(!eval_condition_expr("cond2", &results));
        assert!(eval_condition_expr("cond1 and not cond2", &results));
        assert!(eval_condition_expr("cond1 or cond2", &results));
        assert!(!eval_condition_expr("cond1 and cond2", &results));
    }

    #[test]
    fn state_operators_at_boundaries() {
        use serde_json::json;
        let cases = [
            (StateOperator::Eq, [false, true, false]),
            (StateOperator::Ne, [true, false, true]),
            (StateOperator::Gt, [false, false, true]),
            (StateOperator::Gte, [false, true, true]),
            (StateOperator::Lt, [true, false, false]),
            (StateOperator::Lte, [true, true, false]),
        ];
        for (op, expected) in cases {
            let actual =
                [json!(4), json!(5.0), json!(6)].map(|value| op.matches(&value, &json!(5)));
            assert_eq!(actual, expected, "{op:?}");
        }
        assert!(StateOperator::Eq.matches(&json!("a"), &json!("a")));
        assert!(!StateOperator::Eq.matches(&json!("5"), &json!(5)));
        assert!(StateOperator::Ne.matches(&json!("5"), &json!(5)));
        assert!(!StateOperator::Gt.matches(&json!("6"), &json!(5)));
    }

    #[test]
    fn state_number_comparison_preserves_integer_precision() {
        let lower = serde_json::json!(9_007_199_254_740_992u64);
        let higher = serde_json::json!(9_007_199_254_740_993u64);
        assert_eq!(
            compare_state_values(&lower, &higher),
            Some(std::cmp::Ordering::Less)
        );
        assert_eq!(
            compare_state_values(&higher, &lower),
            Some(std::cmp::Ordering::Greater)
        );

        let negative = serde_json::json!(-1);
        let unsigned = serde_json::json!(u64::MAX);
        assert_eq!(
            compare_state_values(&negative, &unsigned),
            Some(std::cmp::Ordering::Less)
        );
    }

    #[test]
    fn test_logsource_condition() {
        let rule = SigmaRule {
            sigma_version: None,
            title: "Test".to_string(),
            logsource: LogSource {
                category: Some("process_creation".to_string()),
                product: Some("windows".to_string()),
                service: None,
                definition: None,
                custom: HashMap::new(),
            },
            detection: rsigma_parser::Detections {
                named: HashMap::new(),
                conditions: vec![],
                condition_strings: vec![],
                timeframe: None,
            },
            id: None,
            name: None,
            related: vec![],
            taxonomy: None,
            status: None,
            description: None,
            license: None,
            author: None,
            references: vec![],
            date: None,
            modified: None,
            fields: vec![],
            falsepositives: vec![],
            level: None,
            tags: vec![],
            scope: vec![],
            custom_attributes: HashMap::new(),
        };
        let state = PipelineState::default();

        let cond = RuleCondition::Logsource {
            category: Some("process_creation".to_string()),
            product: Some("windows".to_string()),
            service: None,
        };
        assert!(cond.matches_rule(&rule, &state));

        let cond2 = RuleCondition::Logsource {
            category: Some("network".to_string()),
            product: None,
            service: None,
        };
        assert!(!cond2.matches_rule(&rule, &state));
    }

    #[test]
    fn test_is_sigma_rule_condition() {
        let state = PipelineState::default();
        let rule = SigmaRule {
            sigma_version: None,
            title: "Test".to_string(),
            logsource: LogSource::default(),
            detection: rsigma_parser::Detections {
                named: HashMap::new(),
                conditions: vec![],
                condition_strings: vec![],
                timeframe: None,
            },
            id: None,
            name: None,
            related: vec![],
            taxonomy: None,
            status: None,
            description: None,
            license: None,
            author: None,
            references: vec![],
            date: None,
            modified: None,
            fields: vec![],
            falsepositives: vec![],
            level: None,
            tags: vec![],
            scope: vec![],
            custom_attributes: HashMap::new(),
        };

        assert!(RuleCondition::IsSigmaRule.matches_rule(&rule, &state));
        assert!(!RuleCondition::IsSigmaCorrelationRule.matches_rule(&rule, &state));
    }

    #[test]
    fn test_tag_condition() {
        let state = PipelineState::default();
        let rule = SigmaRule {
            sigma_version: None,
            title: "Test".to_string(),
            logsource: LogSource::default(),
            detection: rsigma_parser::Detections {
                named: HashMap::new(),
                conditions: vec![],
                condition_strings: vec![],
                timeframe: None,
            },
            id: None,
            name: None,
            related: vec![],
            taxonomy: None,
            status: None,
            description: None,
            license: None,
            author: None,
            references: vec![],
            date: None,
            modified: None,
            fields: vec![],
            falsepositives: vec![],
            level: None,
            tags: vec!["attack.execution".to_string(), "attack.t1059".to_string()],
            scope: vec![],
            custom_attributes: HashMap::new(),
        };

        assert!(
            RuleCondition::Tag {
                tag: "attack.execution".to_string()
            }
            .matches_rule(&rule, &state)
        );
        assert!(
            !RuleCondition::Tag {
                tag: "attack.persistence".to_string()
            }
            .matches_rule(&rule, &state)
        );
    }

    #[test]
    fn test_field_name_include() {
        let state = PipelineState::default();
        let cond = FieldNameCondition::IncludeFields {
            matcher: FieldMatcher::Plain(vec![
                "CommandLine".to_string(),
                "ParentImage".to_string(),
            ]),
        };
        assert!(cond.matches_field_name("CommandLine", &state));
        assert!(!cond.matches_field_name("User", &state));
    }

    #[test]
    fn test_field_name_exclude() {
        let state = PipelineState::default();
        let cond = FieldNameCondition::ExcludeFields {
            matcher: FieldMatcher::Plain(vec!["Hostname".to_string()]),
        };
        assert!(cond.matches_field_name("CommandLine", &state));
        assert!(!cond.matches_field_name("Hostname", &state));
    }

    #[test]
    fn test_field_name_regex() {
        let state = PipelineState::default();
        let cond = FieldNameCondition::IncludeFields {
            matcher: FieldMatcher::Regex(vec![Regex::new("Event.*").unwrap()]),
        };
        assert!(cond.matches_field_name("EventType", &state));
        assert!(cond.matches_field_name("EventID", &state));
        assert!(!cond.matches_field_name("CommandLine", &state));
    }

    #[test]
    fn test_processing_item_applied() {
        let mut state = PipelineState::default();
        let cond = RuleCondition::ProcessingItemApplied {
            processing_item_id: "my_transform".to_string(),
        };
        let rule = SigmaRule {
            sigma_version: None,
            title: "Test".to_string(),
            logsource: LogSource::default(),
            detection: rsigma_parser::Detections {
                named: HashMap::new(),
                conditions: vec![],
                condition_strings: vec![],
                timeframe: None,
            },
            id: None,
            name: None,
            related: vec![],
            taxonomy: None,
            status: None,
            description: None,
            license: None,
            author: None,
            references: vec![],
            date: None,
            modified: None,
            fields: vec![],
            falsepositives: vec![],
            level: None,
            tags: vec![],
            scope: vec![],
            custom_attributes: HashMap::new(),
        };

        assert!(!cond.matches_rule(&rule, &state));
        state.mark_applied("my_transform");
        assert!(cond.matches_rule(&rule, &state));
    }
}
