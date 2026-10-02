//! Value-extraction helpers for lowering.
//!
//! Encoding, regex, and wildcard rendering deliberately live in the consumers
//! (eval's compile step and convert), not here: lowering stays purely
//! structural so the HIR round-trips faithfully.

use rsigma_parser::SigmaValue;
use rsigma_parser::value::SpecialChar;

use crate::error::IrError;

pub(super) type Result<T> = std::result::Result<T, IrError>;

/// Convert a `yaml_serde::Value` to a `serde_json::Value`.
pub(super) fn yaml_to_json(value: &yaml_serde::Value) -> serde_json::Value {
    match value {
        yaml_serde::Value::Null => serde_json::Value::Null,
        yaml_serde::Value::Bool(b) => serde_json::Value::Bool(*b),
        yaml_serde::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                serde_json::Value::Number(i.into())
            } else if let Some(u) = n.as_u64() {
                serde_json::Value::Number(u.into())
            } else if let Some(f) = n.as_f64() {
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
pub(super) fn yaml_to_json_map(
    map: &std::collections::HashMap<String, yaml_serde::Value>,
) -> std::collections::HashMap<String, serde_json::Value> {
    map.iter()
        .map(|(k, v)| (k.clone(), yaml_to_json(v)))
        .collect()
}

pub(super) fn value_to_plain_string(value: &SigmaValue) -> Result<String> {
    match value {
        SigmaValue::String(s) => Ok(s.as_plain().unwrap_or_else(|| s.original.clone())),
        SigmaValue::Integer(n) => Ok(n.to_string()),
        SigmaValue::Float(n) => Ok(n.to_string()),
        SigmaValue::Bool(b) => Ok(b.to_string()),
        SigmaValue::Null => Err(IrError::IncompatibleValue(
            "null value for string modifier".into(),
        )),
    }
}

pub(super) fn value_to_f64(value: &SigmaValue) -> Result<f64> {
    match value {
        SigmaValue::Integer(n) => Ok(*n as f64),
        SigmaValue::Float(n) => Ok(*n),
        SigmaValue::String(s) => {
            let plain = s.as_plain().unwrap_or_else(|| s.original.clone());
            plain
                .parse::<f64>()
                .map_err(|_| IrError::ExpectedNumeric(plain))
        }
        _ => Err(IrError::ExpectedNumeric(format!("{value:?}"))),
    }
}

/// A segment of a raw `expand` value.
pub(super) enum ExpandSegment {
    Literal(String),
    Wildcard(SpecialChar),
    Placeholder(String),
}

/// Split the raw source text of an `expand` value into literals, wildcards,
/// and `%name%` placeholders. A backslash escapes `*`, `?`, `%`, and itself,
/// so `\%` is a plain percent and `\\%name%` is a backslash followed by
/// a placeholder. A placeholder name is non-empty and has no `*`, `?`, or
/// backslash.
pub(super) fn scan_expand(raw: &str) -> Vec<ExpandSegment> {
    let mut segments = Vec::new();
    let mut literal = String::new();
    let mut chars = raw.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        match c {
            '\\' => match chars.peek() {
                Some(&(_, next @ ('*' | '?' | '%' | '\\'))) => {
                    literal.push(next);
                    chars.next();
                }
                _ => literal.push('\\'),
            },
            '*' | '?' => {
                if !literal.is_empty() {
                    segments.push(ExpandSegment::Literal(std::mem::take(&mut literal)));
                }
                segments.push(ExpandSegment::Wildcard(if c == '*' {
                    SpecialChar::WildcardMulti
                } else {
                    SpecialChar::WildcardSingle
                }));
            }
            '%' => {
                let rest = &raw[i + 1..];
                match rest.find(['%', '*', '?', '\\']) {
                    Some(len) if len > 0 && rest[len..].starts_with('%') => {
                        if !literal.is_empty() {
                            segments.push(ExpandSegment::Literal(std::mem::take(&mut literal)));
                        }
                        segments.push(ExpandSegment::Placeholder(rest[..len].to_string()));
                        for _ in rest[..=len].chars() {
                            chars.next();
                        }
                    }
                    _ => literal.push('%'),
                }
            }
            _ => literal.push(c),
        }
    }
    if !literal.is_empty() {
        segments.push(ExpandSegment::Literal(literal));
    }
    segments
}
