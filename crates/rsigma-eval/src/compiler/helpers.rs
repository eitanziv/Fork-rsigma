use base64::Engine as Base64Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use regex::Regex;

use crate::error::{EvalError, Result};

/// Convert a `yaml_serde::Value` to a `serde_json::Value`.
pub(crate) fn yaml_to_json(value: &yaml_serde::Value) -> serde_json::Value {
    match value {
        yaml_serde::Value::Null => serde_json::Value::Null,
        yaml_serde::Value::Bool(b) => serde_json::Value::Bool(*b),
        yaml_serde::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                serde_json::Value::Number(i.into())
            } else if let Some(u) = n.as_u64() {
                serde_json::Value::Number(u.into())
            } else if let Some(f) = n.as_f64() {
                // NaN and Inf are not representable in JSON; fall back to null.
                serde_json::Number::from_f64(f)
                    .map(serde_json::Value::Number)
                    .unwrap_or(serde_json::Value::Null)
            } else {
                serde_json::Value::Null
            }
        }
        yaml_serde::Value::String(s) => serde_json::Value::String(s.clone()),
        yaml_serde::Value::Sequence(seq) => {
            serde_json::Value::Array(seq.iter().map(yaml_to_json).collect())
        }
        yaml_serde::Value::Mapping(map) => {
            let obj: serde_json::Map<String, serde_json::Value> = map
                .iter()
                .filter_map(|(k, v)| Some((k.as_str()?.to_string(), yaml_to_json(v))))
                .collect();
            serde_json::Value::Object(obj)
        }
        yaml_serde::Value::Tagged(tagged) => yaml_to_json(&tagged.value),
    }
}

/// Convert a map of YAML values to a map of JSON values.
pub(crate) fn yaml_to_json_map(
    map: &std::collections::HashMap<String, yaml_serde::Value>,
) -> std::collections::HashMap<String, serde_json::Value> {
    map.iter()
        .map(|(k, v)| (k.clone(), yaml_to_json(v)))
        .collect()
}

/// Convert bytes to UTF-16LE representation (wide string / utf16le).
pub(super) fn to_utf16le_bytes(bytes: &[u8]) -> Vec<u8> {
    let s = String::from_utf8_lossy(bytes);
    let mut wide = Vec::with_capacity(s.len() * 2);
    for c in s.chars() {
        let mut buf = [0u16; 2];
        let encoded = c.encode_utf16(&mut buf);
        for u in encoded {
            wide.extend_from_slice(&u.to_le_bytes());
        }
    }
    wide
}

/// Convert bytes to UTF-16BE representation.
pub(super) fn to_utf16be_bytes(bytes: &[u8]) -> Vec<u8> {
    let s = String::from_utf8_lossy(bytes);
    let mut wide = Vec::with_capacity(s.len() * 2);
    for c in s.chars() {
        let mut buf = [0u16; 2];
        let encoded = c.encode_utf16(&mut buf);
        for u in encoded {
            wide.extend_from_slice(&u.to_be_bytes());
        }
    }
    wide
}

/// Convert bytes to UTF-16 with BOM (little-endian, BOM = FF FE).
pub(super) fn to_utf16_bom_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut result = vec![0xFF, 0xFE]; // UTF-16LE BOM
    result.extend_from_slice(&to_utf16le_bytes(bytes));
    result
}

/// Generate base64 offset patterns for a byte sequence.
///
/// Produces up to 3 patterns for byte offsets 0, 1, and 2 within a
/// base64 3-byte alignment group. Each pattern is the stable middle
/// portion of the encoding: characters that depend on the bytes before or
/// after the value are dropped at both ends.
pub(super) fn base64_offset_patterns(value: &[u8]) -> Vec<String> {
    const START: [usize; 3] = [0, 2, 3];
    const END_TRIM: [usize; 3] = [0, 3, 2];

    let mut patterns = Vec::with_capacity(3);
    for offset in 0..3usize {
        let mut padded = vec![0u8; offset];
        padded.extend_from_slice(value);
        let encoded = BASE64_STANDARD.encode(&padded);
        let end = encoded.len() - END_TRIM[(value.len() + offset) % 3];
        if START[offset] < end {
            patterns.push(encoded[START[offset]..end].to_string());
        }
    }
    patterns
}

/// Build a regex with optional flags.
pub(super) fn build_regex(
    pattern: &str,
    case_insensitive: bool,
    multiline: bool,
    dotall: bool,
) -> Result<Regex> {
    let mut flags = String::new();
    if case_insensitive {
        flags.push('i');
    }
    if multiline {
        flags.push('m');
    }
    if dotall {
        flags.push('s');
    }

    let full_pattern = if flags.is_empty() {
        pattern.to_string()
    } else {
        format!("(?{flags}){pattern}")
    };

    Regex::new(&full_pattern).map_err(EvalError::InvalidRegex)
}

/// Replacement characters for the `windash` modifier per Sigma spec:
/// `-`, `/`, `–` (en dash U+2013), `—` (em dash U+2014), `―` (horizontal bar U+2015).
const WINDASH_CHARS: [char; 5] = ['-', '/', '\u{2013}', '\u{2014}', '\u{2015}'];

/// Maximum number of dashes allowed in windash expansion.
/// 5^8 = 390,625 variants — beyond this the expansion is too large.
const MAX_WINDASH_DASHES: usize = 8;

/// Expand windash variants: for each `-` in the string, generate all
/// permutations by substituting with `-`, `/`, `–`, `—`, and `―`.
pub(super) fn expand_windash(input: &str) -> Result<Vec<String>> {
    // Find byte positions of '-' characters
    let dash_positions: Vec<usize> = input
        .char_indices()
        .filter(|(_, c)| *c == '-')
        .map(|(i, _)| i)
        .collect();

    if dash_positions.is_empty() {
        return Ok(vec![input.to_string()]);
    }

    let n = dash_positions.len();
    if n > MAX_WINDASH_DASHES {
        return Err(EvalError::InvalidModifiers(format!(
            "windash modifier: value contains {n} dashes, max is {MAX_WINDASH_DASHES} \
             (would generate {} variants)",
            5u64.saturating_pow(n as u32)
        )));
    }

    // Generate all 5^n combinations
    let total = WINDASH_CHARS.len().pow(n as u32);
    let mut variants = Vec::with_capacity(total);

    for combo in 0..total {
        let mut variant = input.to_string();
        let mut idx = combo;
        // Replace from back to front to preserve byte positions
        for &pos in dash_positions.iter().rev() {
            let replacement = WINDASH_CHARS[idx % WINDASH_CHARS.len()];
            variant.replace_range(pos..pos + 1, &replacement.to_string());
            idx /= WINDASH_CHARS.len();
        }
        variants.push(variant);
    }

    Ok(variants)
}
