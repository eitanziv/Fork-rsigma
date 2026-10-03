//! Compile resolved IR string matchers into concrete [`CompiledMatcher`]s.

use regex::Regex;

use rsigma_ir::encoding::expand_encoded;
use rsigma_ir::{IrEncoding, IrPattern, IrPatternPart, IrStrOp};

use crate::error::{EvalError, Result};
use crate::matcher::CompiledMatcher;

/// Compile a string match over a wildcard-aware pattern.
pub(super) fn compile_str(op: IrStrOp, pattern: &IrPattern, ci: bool) -> Result<CompiledMatcher> {
    match pattern.as_plain() {
        Some(plain) => Ok(compile_plain(op, &plain, ci)),
        None => compile_wildcard(op, pattern, ci),
    }
}

/// Compile a string match over a plain value (no wildcards).
pub(super) fn compile_plain(op: IrStrOp, plain: &str, ci: bool) -> CompiledMatcher {
    let value = if ci {
        plain.to_lowercase()
    } else {
        plain.to_string()
    };
    match op {
        IrStrOp::Contains => CompiledMatcher::Contains {
            value,
            case_insensitive: ci,
        },
        IrStrOp::StartsWith => CompiledMatcher::StartsWith {
            value,
            case_insensitive: ci,
        },
        IrStrOp::EndsWith => CompiledMatcher::EndsWith {
            value,
            case_insensitive: ci,
        },
        IrStrOp::Exact => CompiledMatcher::Exact {
            value,
            case_insensitive: ci,
        },
    }
}

/// Compile a pattern with wildcards into a regex, anchored as `op` requires.
fn compile_wildcard(op: IrStrOp, pattern: &IrPattern, ci: bool) -> Result<CompiledMatcher> {
    let mut re = String::from(if ci { "(?is)" } else { "(?s)" });
    if !matches!(op, IrStrOp::Contains | IrStrOp::EndsWith) {
        re.push('^');
    }
    for part in &pattern.parts {
        match part {
            IrPatternPart::Literal(text) => re.push_str(&regex::escape(text)),
            IrPatternPart::WildcardMulti => re.push_str(".*"),
            IrPatternPart::WildcardSingle => re.push('.'),
        }
    }
    if !matches!(op, IrStrOp::Contains | IrStrOp::StartsWith) {
        re.push('$');
    }
    let regex = Regex::new(&re).map_err(EvalError::InvalidRegex)?;
    Ok(CompiledMatcher::Regex(regex))
}

/// Compile an encoding-transformed string match into one matcher per
/// encoded variant.
pub(super) fn compile_encoded(
    encodings: &[IrEncoding],
    op: IrStrOp,
    pattern: &IrPattern,
    ci: bool,
) -> Result<CompiledMatcher> {
    let mut matchers = expand_encoded(encodings, op, pattern)?
        .iter()
        .map(|(op, pattern)| compile_str(*op, pattern, ci))
        .collect::<Result<Vec<_>>>()?;
    Ok(match matchers.len() {
        1 => matchers.remove(0),
        _ => CompiledMatcher::AnyOf(matchers),
    })
}
