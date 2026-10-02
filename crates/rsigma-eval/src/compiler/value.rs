//! Compile resolved IR string matchers into concrete [`CompiledMatcher`]s.

use base64::Engine as Base64Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use regex::Regex;

use rsigma_ir::{IrEncoding, IrPattern, IrPatternPart, IrStrOp};

use crate::error::{EvalError, Result};
use crate::matcher::CompiledMatcher;

use super::helpers::{
    base64_offset_patterns, expand_windash, to_utf16_bom_bytes, to_utf16be_bytes, to_utf16le_bytes,
};

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

/// Compile an encoding-transformed string match by applying `encodings` in
/// order: UTF-16, then base64 or base64offset, or windash.
pub(super) fn compile_encoded(
    encodings: &[IrEncoding],
    op: IrStrOp,
    value: &str,
    ci: bool,
) -> Result<CompiledMatcher> {
    let mut bytes = value.as_bytes().to_vec();
    for encoding in encodings {
        match encoding {
            IrEncoding::Wide => bytes = to_utf16le_bytes(&bytes),
            IrEncoding::Utf16Be => bytes = to_utf16be_bytes(&bytes),
            IrEncoding::Utf16 => bytes = to_utf16_bom_bytes(&bytes),
            IrEncoding::Base64 => {
                return Ok(compile_plain(op, &BASE64_STANDARD.encode(&bytes), ci));
            }
            IrEncoding::Base64Offset => {
                let matchers = base64_offset_patterns(&bytes)
                    .into_iter()
                    .map(|p| compile_plain(IrStrOp::Contains, &p, ci))
                    .collect();
                return Ok(CompiledMatcher::AnyOf(matchers));
            }
            IrEncoding::Windash => {
                let matchers = expand_windash(value)?
                    .into_iter()
                    .map(|v| compile_plain(op, &v, ci))
                    .collect();
                return Ok(CompiledMatcher::AnyOf(matchers));
            }
        }
    }
    Ok(compile_plain(op, value, ci))
}
