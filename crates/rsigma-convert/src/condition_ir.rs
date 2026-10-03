//! Convert [`IrCondition`] trees against a rule's [`IrDetection`] map.
//!
//! The whole rule is lowered to HIR once (`convert_rule_via_ir`); both the
//! detection bodies and the conditions are then walked from the IR. Quantified
//! selectors are resolved here against the IR detections, mirroring eval:
//! an empty match set is rejected, `any` / `1 of` become OR, `all of` becomes
//! AND, and `N of` (N > 1) is unsupported.

use std::collections::HashMap;

use rsigma_eval::pipeline::PipelineState;
use rsigma_ir::{IrCondition, IrDetection};
use rsigma_parser::{Quantifier, SigmaRule};

use crate::backend::Backend;
use crate::error::{ConvertError, Result};
use crate::ir_convert::{Operand, condition_op, detection_op, join, negate, selected_detections};
use crate::state::ConversionState;

/// Walk an [`IrCondition`] and convert each node into a query fragment.
///
/// Selectors are resolved here against the rule's detections, mirroring the
/// parser condition walker: an empty match set is rejected, `any` / `1 of`
/// become OR, `all of` becomes AND, and `N of` (N > 1) is unsupported.
/// Compound operands are grouped through [`Backend::convert_condition_group`].
pub fn convert_ir_condition(
    backend: &dyn Backend,
    expr: &IrCondition,
    detections: &HashMap<String, IrDetection>,
    state: &mut ConversionState,
) -> Result<String> {
    match expr {
        IrCondition::Detection(name) => {
            let det = detections.get(name).ok_or_else(|| {
                ConvertError::RuleConversion(format!("detection '{name}' not found"))
            })?;
            backend.convert_ir_detection(det, state)
        }
        IrCondition::And(exprs) | IrCondition::Or(exprs) => {
            let parts = exprs
                .iter()
                .map(|e| {
                    let part = convert_ir_condition(backend, e, detections, state)?;
                    Ok(Operand::new(part, condition_op(e, detections)))
                })
                .collect::<Result<Vec<_>>>()?;
            join(backend, matches!(expr, IrCondition::And(_)), parts)
        }
        IrCondition::Not(inner) => {
            let part = convert_ir_condition(backend, inner, detections, state)?;
            negate(backend, Operand::new(part, condition_op(inner, detections)))
        }
        IrCondition::Selector {
            quantifier,
            pattern,
        } => {
            let names = selected_detections(detections, pattern);
            if names.is_empty() {
                return Err(ConvertError::RuleConversion(
                    "selector matched no detections".into(),
                ));
            }
            let all = match quantifier {
                Quantifier::Any | Quantifier::Count(1) => false,
                Quantifier::All => true,
                Quantifier::Count(n) => {
                    return Err(ConvertError::RuleConversion(format!(
                        "'{n} of' quantifier not supported in conversion"
                    )));
                }
            };

            let parts = names
                .into_iter()
                .map(|name| {
                    let det = &detections[name];
                    let part = backend.convert_ir_detection(det, state)?;
                    Ok(Operand::new(part, detection_op(det)))
                })
                .collect::<Result<Vec<_>>>()?;
            join(backend, all, parts)
        }
    }
}

/// Map an IR lowering error to the closest `ConvertError`, preserving the
/// error kinds convert historically surfaced (invalid/unsupported modifiers,
/// incompatible values).
pub(crate) fn ir_err(e: rsigma_ir::IrError) -> ConvertError {
    use rsigma_ir::IrError;
    match e {
        IrError::InvalidModifiers(m) => ConvertError::UnsupportedModifier(m),
        IrError::IncompatibleValue(m) | IrError::ExpectedNumeric(m) => {
            ConvertError::UnsupportedValue(m)
        }
        other => ConvertError::RuleConversion(other.to_string()),
    }
}

/// Shared `Backend::convert_rule` implementation: lower the whole rule to HIR
/// and convert detections and conditions from the faithful IR.
pub fn convert_rule_via_ir(
    backend: &dyn Backend,
    rule: &SigmaRule,
    output_format: &str,
    pipeline_state: &PipelineState,
) -> Result<Vec<String>> {
    let mut ir =
        rsigma_ir::lower_rule(rule, &rsigma_ir::LowerOptions::default()).map_err(ir_err)?;
    rsigma_ir::encoding::expand_encoded_detections(&mut ir.detections).map_err(ir_err)?;

    let mut queries = Vec::with_capacity(ir.conditions.len());
    for (idx, cond) in ir.conditions.iter().enumerate() {
        let mut state = ConversionState::new(pipeline_state.state.clone());
        state
            .processing_state
            .insert("_output_format".to_string(), output_format.into());
        let query = convert_ir_condition(backend, cond, &ir.detections, &mut state)?;
        let finished = backend.finish_query(rule, query, &state)?;
        let finalized = backend.finalize_query(rule, finished, idx, &state, output_format)?;
        queries.push(finalized);
    }
    Ok(queries)
}
