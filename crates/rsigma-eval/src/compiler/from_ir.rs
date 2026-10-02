//! Compile HIR (`IrRule`) into physical [`CompiledRule`] form.
//!
//! This is the second half of the IR-backed compile path:
//! `lower_rule` (rsigma-ir) → [`compile_to_compiled`] → matcher optimizer.

use std::collections::HashMap;
use std::sync::Arc;

use rsigma_ir::{
    IrCondition, IrDetection, IrDetectionItem, IrExpandPart, IrMatcher, IrNumber, IrPattern,
    IrPatternPart, IrRule, IrStrOp, IrTimePart,
};
use rsigma_parser::ConditionExpr;

use crate::error::{EvalError, Result};
use crate::matcher::{CompiledMatcher, ExpandPart, TimePart};

use super::helpers::build_regex;
use super::optimizer;
use super::value::{compile_encoded, compile_str};
use super::{CompiledDetection, CompiledDetectionItem, CompiledRule};

/// Compile an [`IrRule`] into a physical [`CompiledRule`] ready for evaluation.
pub fn compile_to_compiled(ir: &IrRule) -> Result<CompiledRule> {
    let mut detections = HashMap::new();
    for (name, detection) in &ir.detections {
        detections.insert(name.clone(), compile_ir_detection(detection)?);
    }

    let conditions: Vec<ConditionExpr> = ir.conditions.iter().map(ir_condition_to_expr).collect();

    let include_event = ir
        .metadata
        .custom_attributes
        .get("rsigma.include_event")
        .and_then(|v| v.as_str())
        == Some("true");

    Ok(CompiledRule {
        title: ir.metadata.title.clone(),
        id: ir.metadata.id.clone(),
        name: ir.metadata.name.clone(),
        level: ir.metadata.level,
        tags: ir.metadata.tags.clone(),
        description: ir.metadata.description.clone(),
        falsepositives: ir.metadata.falsepositives.clone(),
        logsource: ir.logsource.clone(),
        detections,
        conditions,
        include_event,
        custom_attributes: Arc::new(ir.metadata.custom_attributes.clone()),
    })
}

/// Where a detection is evaluated: against the whole event, or against one
/// member of an array (`field[any]` and friends).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Scope {
    Event,
    Element,
}

pub(super) fn compile_ir_detection(detection: &IrDetection) -> Result<CompiledDetection> {
    compile_ir_detection_in(detection, Scope::Event)
}

fn compile_ir_detection_in(detection: &IrDetection, scope: Scope) -> Result<CompiledDetection> {
    match detection {
        IrDetection::AllOf(items) => {
            if items.is_empty() {
                return Err(EvalError::InvalidModifiers(
                    "AllOf detection must not be empty (vacuous truth)".into(),
                ));
            }
            let compiled: Result<Vec<_>> = items
                .iter()
                .map(|item| compile_ir_detection_item_in(item, scope))
                .collect();
            Ok(CompiledDetection::AllOf(compiled?))
        }
        IrDetection::AnyOf(dets) => {
            if dets.is_empty() {
                return Err(EvalError::InvalidModifiers(
                    "AnyOf detection must not be empty (would never match)".into(),
                ));
            }
            let compiled: Result<Vec<_>> = dets
                .iter()
                .map(|d| compile_ir_detection_in(d, scope))
                .collect();
            Ok(CompiledDetection::AnyOf(compiled?))
        }
        IrDetection::ArrayMatch {
            field,
            quantifier,
            body,
        } => Ok(CompiledDetection::ArrayMatch {
            field: field.clone(),
            quantifier: *quantifier,
            body: Box::new(compile_ir_detection_in(body, Scope::Element)?),
        }),
        IrDetection::And(dets) => {
            if dets.is_empty() {
                return Err(EvalError::InvalidModifiers(
                    "And detection must not be empty".into(),
                ));
            }
            let compiled: Result<Vec<_>> = dets
                .iter()
                .map(|d| compile_ir_detection_in(d, scope))
                .collect();
            Ok(CompiledDetection::And(compiled?))
        }
        IrDetection::Conditional { named, condition } => {
            if named.is_empty() {
                return Err(EvalError::InvalidModifiers(
                    "Conditional detection must have at least one named sub-selection".into(),
                ));
            }
            let compiled: Result<HashMap<String, CompiledDetection>> = named
                .iter()
                .map(|(k, d)| Ok((k.clone(), compile_ir_detection_in(d, scope)?)))
                .collect();
            Ok(CompiledDetection::Conditional {
                named: compiled?,
                condition: ir_condition_to_expr(condition),
            })
        }
        IrDetection::Keywords(matcher) => {
            let compiled = match scope {
                Scope::Event => compile_keyword_matcher(matcher)?,
                Scope::Element => compile_ir_matcher(matcher)?,
            };
            // Keywords are OR-semantics; apply AnyOf optimizer when present.
            let matcher = match compiled {
                CompiledMatcher::AnyOf(ms) => optimizer::optimize_any_of(ms),
                other => other,
            };
            Ok(CompiledDetection::Keywords(matcher))
        }
    }
}

#[cfg(test)]
pub(super) fn compile_ir_detection_item(item: &IrDetectionItem) -> Result<CompiledDetectionItem> {
    compile_ir_detection_item_in(item, Scope::Event)
}

/// A field-less item matches like a keyword at event scope and matches the
/// member itself at array element scope.
fn compile_ir_detection_item_in(
    item: &IrDetectionItem,
    scope: Scope,
) -> Result<CompiledDetectionItem> {
    let matcher = if item.field.is_none() && scope == Scope::Event {
        compile_keyword_matcher(&item.matcher)?
    } else {
        compile_ir_matcher(&item.matcher)?
    };
    let bloom_eligible =
        item.field.is_some() && crate::engine::bloom_index::is_positive_substring_matcher(&matcher);

    Ok(CompiledDetectionItem {
        field: item.field.clone(),
        matcher,
        exists: item.exists,
        bloom_eligible,
    })
}

fn compile_ir_matcher(matcher: &IrMatcher) -> Result<CompiledMatcher> {
    match matcher {
        IrMatcher::Str {
            op,
            pattern,
            case_insensitive,
        } => compile_str(*op, pattern, *case_insensitive),
        IrMatcher::Encoded {
            encodings,
            op,
            pattern,
            case_insensitive,
        } => compile_encoded(encodings, *op, pattern, *case_insensitive),
        IrMatcher::Regex {
            pattern,
            case_insensitive,
            multiline,
            dotall,
            // `cased` only informs convert's operator choice; eval regex case
            // sensitivity is the `|i` flag (`case_insensitive`).
            cased: _,
        } => Ok(CompiledMatcher::Regex(build_regex(
            pattern,
            *case_insensitive,
            *multiline,
            *dotall,
        )?)),
        IrMatcher::Cidr { network } => {
            let net: ipnet::IpNet = network.parse().map_err(EvalError::InvalidCidr)?;
            Ok(CompiledMatcher::Cidr(net))
        }
        IrMatcher::NumericEq(n) => Ok(CompiledMatcher::NumericEq(ir_number_literal(n)?)),
        IrMatcher::NumericGt(n) => Ok(CompiledMatcher::NumericGt(ir_number_literal(n)?)),
        IrMatcher::NumericGte(n) => Ok(CompiledMatcher::NumericGte(ir_number_literal(n)?)),
        IrMatcher::NumericLt(n) => Ok(CompiledMatcher::NumericLt(ir_number_literal(n)?)),
        IrMatcher::NumericLte(n) => Ok(CompiledMatcher::NumericLte(ir_number_literal(n)?)),
        IrMatcher::Exists(b) => Ok(CompiledMatcher::Exists(*b)),
        IrMatcher::FieldRef {
            field,
            op,
            case_insensitive,
        } => Ok(CompiledMatcher::FieldRef {
            field: field.clone(),
            op: *op,
            case_insensitive: *case_insensitive,
        }),
        IrMatcher::Null => Ok(CompiledMatcher::Null),
        IrMatcher::BoolEq(b) => Ok(CompiledMatcher::BoolEq(*b)),
        IrMatcher::Expand {
            template,
            op,
            case_insensitive,
        } => Ok(CompiledMatcher::Expand {
            template: template.iter().map(ir_expand_part).collect(),
            op: *op,
            case_insensitive: *case_insensitive,
        }),
        IrMatcher::TimestampPart { part, inner } => Ok(CompiledMatcher::TimestampPart {
            part: ir_time_part(*part),
            inner: Box::new(compile_ir_matcher(inner)?),
        }),
        IrMatcher::Not(inner) => Ok(CompiledMatcher::Not(Box::new(compile_ir_matcher(inner)?))),
        IrMatcher::AnyOf(ms) => {
            let compiled: Result<Vec<_>> = ms.iter().map(compile_ir_matcher).collect();
            Ok(optimizer::optimize_any_of(compiled?))
        }
        IrMatcher::AllOf(ms) => {
            let compiled: Result<Vec<_>> = ms.iter().map(compile_ir_matcher).collect();
            Ok(CompiledMatcher::AllOf(compiled?))
        }
    }
}

/// Compile a matcher that is tested against every value in the event.
///
/// Keywords match anywhere in a value, so a value without an explicit string
/// operator matches as a substring. Keyword values are strings in the Sigma
/// specification, so a number matches as a case-insensitive substring of its
/// decimal text.
fn compile_keyword_matcher(matcher: &IrMatcher) -> Result<CompiledMatcher> {
    match matcher {
        IrMatcher::Str {
            op: IrStrOp::Exact,
            pattern,
            case_insensitive,
        } => compile_str(IrStrOp::Contains, pattern, *case_insensitive),
        IrMatcher::Encoded {
            encodings,
            op: IrStrOp::Exact,
            pattern,
            case_insensitive,
        } => compile_encoded(encodings, IrStrOp::Contains, pattern, *case_insensitive),
        IrMatcher::NumericEq(n) => {
            let pattern = IrPattern {
                parts: vec![IrPatternPart::Literal(decimal_text(ir_number_literal(n)?))],
            };
            compile_str(IrStrOp::Contains, &pattern, true)
        }
        IrMatcher::Not(inner) => Ok(CompiledMatcher::Not(Box::new(compile_keyword_matcher(
            inner,
        )?))),
        IrMatcher::AnyOf(ms) => {
            let compiled: Result<Vec<_>> = ms.iter().map(compile_keyword_matcher).collect();
            Ok(optimizer::optimize_any_of(compiled?))
        }
        IrMatcher::AllOf(ms) => {
            let compiled: Result<Vec<_>> = ms.iter().map(compile_keyword_matcher).collect();
            Ok(CompiledMatcher::AllOf(compiled?))
        }
        other => compile_ir_matcher(other),
    }
}

/// Decimal text of a number, without a fractional part for whole numbers.
fn decimal_text(n: f64) -> String {
    if n.fract() == 0.0 && (i64::MIN as f64..=i64::MAX as f64).contains(&n) {
        (n as i64).to_string()
    } else {
        n.to_string()
    }
}

fn ir_condition_to_expr(cond: &IrCondition) -> ConditionExpr {
    match cond {
        IrCondition::Detection(name) => ConditionExpr::Identifier(name.clone()),
        IrCondition::And(exprs) => {
            ConditionExpr::And(exprs.iter().map(ir_condition_to_expr).collect())
        }
        IrCondition::Or(exprs) => {
            ConditionExpr::Or(exprs.iter().map(ir_condition_to_expr).collect())
        }
        IrCondition::Not(inner) => ConditionExpr::Not(Box::new(ir_condition_to_expr(inner))),
        IrCondition::Selector {
            quantifier,
            pattern,
        } => ConditionExpr::Selector {
            quantifier: quantifier.clone(),
            pattern: pattern.clone(),
        },
    }
}

fn ir_number_literal(n: &IrNumber) -> Result<f64> {
    match n {
        IrNumber::Literal(v) => Ok(*v),
        IrNumber::DynamicSourceRef { source_id, .. } => Err(EvalError::IncompatibleValue(format!(
            "unresolved dynamic source reference '{source_id}' cannot be compiled; \
             specialize the IR first"
        ))),
    }
}

fn ir_expand_part(part: &IrExpandPart) -> ExpandPart {
    match part {
        IrExpandPart::Literal(s) => ExpandPart::Literal(s.clone()),
        IrExpandPart::Placeholder(s) => ExpandPart::Placeholder(s.clone()),
    }
}

fn ir_time_part(part: IrTimePart) -> TimePart {
    match part {
        IrTimePart::Minute => TimePart::Minute,
        IrTimePart::Hour => TimePart::Hour,
        IrTimePart::Day => TimePart::Day,
        IrTimePart::Week => TimePart::Week,
        IrTimePart::Month => TimePart::Month,
        IrTimePart::Year => TimePart::Year,
    }
}
