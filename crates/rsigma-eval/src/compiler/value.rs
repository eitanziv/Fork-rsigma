//! Compile resolved IR string matchers into concrete [`CompiledMatcher`]s.

use base64::Engine as Base64Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use regex::Regex;

use rsigma_ir::{IrEncoding, IrPattern, IrPatternPart, IrStrOp};

use crate::error::{EvalError, Result};
use crate::matcher::CompiledMatcher;

use super::helpers::{
    base64_offset_patterns, to_utf16_bom_bytes, to_utf16be_bytes, to_utf16le_bytes, utf16_pattern,
    windash_variants,
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

/// Compile an encoding-transformed string match. Windash variants are
/// expanded first, then each variant is encoded as UTF-16 and base64 or
/// base64offset when those apply.
pub(super) fn compile_encoded(
    encodings: &[IrEncoding],
    op: IrStrOp,
    pattern: &IrPattern,
    ci: bool,
) -> Result<CompiledMatcher> {
    let variants = if encodings.contains(&IrEncoding::Windash) {
        windash_variants(pattern)?
    } else {
        vec![pattern.clone()]
    };
    let utf16 = encodings.iter().copied().find(|e| {
        matches!(
            e,
            IrEncoding::Wide | IrEncoding::Utf16 | IrEncoding::Utf16Be
        )
    });
    let base64 = encodings
        .iter()
        .copied()
        .find(|e| matches!(e, IrEncoding::Base64 | IrEncoding::Base64Offset));

    let mut matchers = Vec::with_capacity(variants.len());
    for variant in &variants {
        let Some(base64) = base64 else {
            let encoded = match utf16 {
                Some(encoding) => utf16_pattern(encoding, variant),
                None => variant.clone(),
            };
            matchers.push(compile_str(op, &encoded, ci)?);
            continue;
        };
        let plain = variant.as_plain().ok_or_else(|| {
            EvalError::InvalidModifiers("|base64 and |base64offset do not support wildcards".into())
        })?;
        let bytes = match utf16 {
            Some(IrEncoding::Wide) => to_utf16le_bytes(plain.as_bytes()),
            Some(IrEncoding::Utf16Be) => to_utf16be_bytes(plain.as_bytes()),
            Some(IrEncoding::Utf16) => to_utf16_bom_bytes(plain.as_bytes()),
            _ => plain.into_bytes(),
        };
        if base64 == IrEncoding::Base64 {
            matchers.push(compile_plain(op, &BASE64_STANDARD.encode(&bytes), ci));
        } else {
            matchers.extend(
                base64_offset_patterns(&bytes)
                    .into_iter()
                    .map(|p| compile_plain(IrStrOp::Contains, &p, ci)),
            );
        }
    }
    Ok(match matchers.len() {
        1 => matchers.remove(0),
        _ => CompiledMatcher::AnyOf(matchers),
    })
}
