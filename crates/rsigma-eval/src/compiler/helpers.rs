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
