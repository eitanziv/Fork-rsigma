use std::collections::HashMap;

use regex::Regex;

use rsigma_parser::{
    ConditionExpr, Detection, DetectionItem, FieldSpec, Modifier, SigmaRule, SigmaString,
    SigmaValue, SpecialChar, StringPart,
};

use super::super::conditions::{ConditionSet, DetectionItemCondition, FieldNameCondition};
use super::super::state::PipelineState;
use crate::error::{EvalError, Result};

// =============================================================================
// Field name transformation helper
// =============================================================================

/// Max branches a single one-to-many field-name expansion can produce inside
/// one `AllOf`.
///
/// The Cartesian product of per-item alternative lists grows fast
/// (e.g. 10 items * 5 alternatives each = ~9.7M branches). pySigma
/// materializes expanded rules once for query generation, but rsigma
/// evaluates rules against live events, so a blown-up detection tree stays
/// in the hot path permanently. We reject expansions above this threshold at
/// load time instead of silently ballooning memory and CPU.
const MAX_FIELD_MAPPING_COMBINATIONS: usize = 4096;

/// Apply a field-name-rewriting closure to every detection in `rule`.
///
/// The closure returns `None` to leave a name untouched, `Some(vec)` to
/// rewrite it. A single-element `Some` renames the item in place. Multiple
/// alternatives expand the matched item into an OR over the alternatives;
/// the surrounding `AllOf` becomes an `AnyOf` of `AllOf`s via Cartesian
/// expansion (see `transform_detection_fields`).
pub(super) fn apply_field_name_transform<F>(
    rule: &mut SigmaRule,
    state: &PipelineState,
    detection_conditions: &[&ConditionSet<DetectionItemCondition>],
    field_name_conditions: &[&ConditionSet<FieldNameCondition>],
    transform_fn: F,
) -> Result<()>
where
    F: Fn(&str) -> Option<Vec<String>>,
{
    let rule_title = rule.title.clone();
    for detection in rule.detection.named.values_mut() {
        transform_detection_fields(
            detection,
            state,
            detection_conditions,
            field_name_conditions,
            &transform_fn,
            &rule_title,
        )?;
    }
    Ok(())
}

fn transform_detection_fields<F>(
    detection: &mut Detection,
    state: &PipelineState,
    detection_conditions: &[&ConditionSet<DetectionItemCondition>],
    field_name_conditions: &[&ConditionSet<FieldNameCondition>],
    transform_fn: &F,
    rule_title: &str,
) -> Result<()>
where
    F: Fn(&str) -> Option<Vec<String>>,
{
    match detection {
        Detection::AllOf(items) => {
            let detection_matches: Vec<bool> = items
                .iter()
                .map(|item| detection_conditions_match(item, state, detection_conditions))
                .collect();
            for (item, matches) in items.iter_mut().zip(&detection_matches) {
                if *matches {
                    transform_field_reference_values(
                        item,
                        state,
                        field_name_conditions,
                        transform_fn,
                        rule_title,
                    )?;
                }
            }

            // First pass (read-only): resolve each item's mapping result.
            // Store either a single rename or a multi-alternative expansion.
            enum Resolved {
                Unchanged,
                Renamed(String),
                Expanded(Vec<String>),
            }
            let resolved: Vec<Resolved> = items
                .iter()
                .zip(detection_matches)
                .map(
                    |(item, detection_matches)| match item.field.name.as_deref() {
                        Some(name)
                            if detection_matches
                                && field_conditions_match(name, state, field_name_conditions) =>
                        {
                            match transform_fn(name) {
                                Some(new_names) if new_names.len() > 1 => {
                                    Resolved::Expanded(new_names)
                                }
                                Some(mut new_names) if new_names.len() == 1 => {
                                    Resolved::Renamed(new_names.pop().unwrap())
                                }
                                _ => Resolved::Unchanged,
                            }
                        }
                        _ => Resolved::Unchanged,
                    },
                )
                .collect();

            let needs_expansion = resolved.iter().any(|r| matches!(r, Resolved::Expanded(_)));

            if !needs_expansion {
                // Fast path: apply 1:1 renames in-place, no cloning.
                for (item, res) in items.iter_mut().zip(resolved) {
                    if let Resolved::Renamed(new_name) = res {
                        item.field.name = Some(new_name);
                    }
                }
            } else {
                // Build per-item alternative lists for the Cartesian product.
                let alternatives: Vec<Vec<DetectionItem>> = items
                    .iter()
                    .zip(resolved)
                    .map(|(item, res)| match res {
                        Resolved::Expanded(names) => names
                            .into_iter()
                            .map(|new_name| {
                                let mut clone = item.clone();
                                clone.field.name = Some(new_name);
                                clone
                            })
                            .collect(),
                        Resolved::Renamed(name) => {
                            let mut clone = item.clone();
                            clone.field.name = Some(name);
                            vec![clone]
                        }
                        Resolved::Unchanged => vec![item.clone()],
                    })
                    .collect();

                let total = alternatives
                    .iter()
                    .map(Vec::len)
                    .fold(1usize, |acc, n| acc.saturating_mul(n));
                if total > MAX_FIELD_MAPPING_COMBINATIONS {
                    let sizes: Vec<usize> = alternatives.iter().map(Vec::len).collect();
                    return Err(EvalError::InvalidModifiers(format!(
                        "field name mapping cartesian expansion would produce {total} \
                         branches, exceeding the limit of {MAX_FIELD_MAPPING_COMBINATIONS} \
                         (rule: {rule_title}, per-item alternative counts: {sizes:?}); \
                         reduce the number of one-to-many alternatives or split the AllOf"
                    )));
                }
                let combinations = cartesian_product(alternatives);
                *detection =
                    Detection::AnyOf(combinations.into_iter().map(Detection::AllOf).collect());
            }
        }
        Detection::AnyOf(subs) => {
            for sub in subs.iter_mut() {
                transform_detection_fields(
                    sub,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    transform_fn,
                    rule_title,
                )?;
            }
        }
        Detection::ArrayMatch { body, .. } => {
            transform_detection_fields(
                body.as_mut(),
                state,
                detection_conditions,
                field_name_conditions,
                transform_fn,
                rule_title,
            )?;
        }
        Detection::And(subs) => {
            for sub in subs.iter_mut() {
                transform_detection_fields(
                    sub,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    transform_fn,
                    rule_title,
                )?;
            }
        }
        Detection::Conditional { named, .. } => {
            for sub in named.values_mut() {
                transform_detection_fields(
                    sub,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    transform_fn,
                    rule_title,
                )?;
            }
        }
        Detection::Keywords(_) => {}
    }
    Ok(())
}

fn transform_field_reference_values<F>(
    item: &mut DetectionItem,
    state: &PipelineState,
    field_name_conditions: &[&ConditionSet<FieldNameCondition>],
    transform_fn: &F,
    rule_title: &str,
) -> Result<()>
where
    F: Fn(&str) -> Option<Vec<String>>,
{
    if !item.field.modifiers.contains(&Modifier::FieldRef) {
        return Ok(());
    }

    let mut mapped_values = Vec::new();
    for value in item.values.drain(..) {
        let SigmaValue::String(field_ref) = &value else {
            mapped_values.push(value);
            continue;
        };
        let Some(field_name) = field_ref.as_plain() else {
            mapped_values.push(value);
            continue;
        };
        if !field_conditions_match(&field_name, state, field_name_conditions) {
            mapped_values.push(value);
            continue;
        }

        match transform_fn(&field_name) {
            Some(names) if !names.is_empty() => {
                if mapped_values.len().saturating_add(names.len()) > MAX_FIELD_MAPPING_COMBINATIONS
                {
                    return Err(EvalError::InvalidModifiers(format!(
                        "field reference mapping would produce more than \
                         {MAX_FIELD_MAPPING_COMBINATIONS} values (rule: {rule_title})"
                    )));
                }
                mapped_values.extend(
                    names
                        .into_iter()
                        .map(|name| SigmaValue::String(SigmaString::new(&name))),
                );
            }
            _ => mapped_values.push(value),
        }
    }
    item.values = mapped_values;
    Ok(())
}

/// Build the Cartesian product of a sequence of alternative lists.
///
/// `[[a, b], [c]]` → `[[a, c], [b, c]]`.
/// Empty input yields a single empty combination so callers handle the edge
/// case uniformly.
fn cartesian_product<T: Clone>(input: Vec<Vec<T>>) -> Vec<Vec<T>> {
    let mut result: Vec<Vec<T>> = vec![Vec::new()];
    for group in input {
        let mut next = Vec::with_capacity(result.len() * group.len().max(1));
        for prefix in &result {
            for elem in &group {
                let mut combo = prefix.clone();
                combo.push(elem.clone());
                next.push(combo);
            }
        }
        result = next;
    }
    result
}

fn field_conditions_match(
    field_name: &str,
    state: &PipelineState,
    condition_sets: &[&ConditionSet<FieldNameCondition>],
) -> bool {
    condition_sets
        .iter()
        .all(|set| set.matches(|condition| condition.matches_field_name(field_name, state)))
}

// =============================================================================
// Drop detection items
// =============================================================================

pub(super) fn drop_detection_items(
    rule: &mut SigmaRule,
    state: &PipelineState,
    detection_conditions: &[&ConditionSet<DetectionItemCondition>],
    field_name_conditions: &[&ConditionSet<FieldNameCondition>],
) {
    for detection in rule.detection.named.values_mut() {
        drop_from_detection(
            detection,
            state,
            detection_conditions,
            field_name_conditions,
        );
    }
}

fn drop_from_detection(
    detection: &mut Detection,
    state: &PipelineState,
    detection_conditions: &[&ConditionSet<DetectionItemCondition>],
    field_name_conditions: &[&ConditionSet<FieldNameCondition>],
) {
    match detection {
        Detection::AllOf(items) => {
            items.retain(|item| {
                !should_drop_item(item, state, detection_conditions, field_name_conditions)
            });
        }
        Detection::AnyOf(subs) => {
            for sub in subs.iter_mut() {
                drop_from_detection(sub, state, detection_conditions, field_name_conditions);
            }
        }
        Detection::ArrayMatch { body, .. } => {
            drop_from_detection(
                body.as_mut(),
                state,
                detection_conditions,
                field_name_conditions,
            );
        }
        Detection::And(subs) => {
            for sub in subs.iter_mut() {
                drop_from_detection(sub, state, detection_conditions, field_name_conditions);
            }
        }
        Detection::Conditional { named, .. } => {
            for sub in named.values_mut() {
                drop_from_detection(sub, state, detection_conditions, field_name_conditions);
            }
        }
        Detection::Keywords(_) => {}
    }
}

fn should_drop_item(
    item: &DetectionItem,
    state: &PipelineState,
    detection_conditions: &[&ConditionSet<DetectionItemCondition>],
    field_name_conditions: &[&ConditionSet<FieldNameCondition>],
) -> bool {
    let det_match = detection_conditions_match(item, state, detection_conditions);

    let field_match = if let Some(ref name) = item.field.name {
        field_conditions_match(name, state, field_name_conditions)
    } else {
        condition_sets_are_empty(field_name_conditions)
    };

    det_match && field_match
}

fn detection_conditions_match(
    item: &DetectionItem,
    state: &PipelineState,
    condition_sets: &[&ConditionSet<DetectionItemCondition>],
) -> bool {
    condition_sets
        .iter()
        .all(|set| set.matches(|condition| condition.matches_item(item, state)))
}

fn condition_sets_are_empty<T>(condition_sets: &[&ConditionSet<T>]) -> bool {
    condition_sets
        .iter()
        .all(|condition_set| condition_set.conditions.is_empty())
}

// =============================================================================
// Add conditions
// =============================================================================

pub(super) fn add_conditions(
    rule: &mut SigmaRule,
    conditions: &HashMap<String, Vec<SigmaValue>>,
    field_refs: &HashMap<String, String>,
    negated: bool,
    prepend: bool,
) {
    let mut items: Vec<DetectionItem> = conditions
        .iter()
        .map(|(field, values)| DetectionItem {
            field: FieldSpec::new(Some(field.clone()), Vec::new()),
            values: values.clone(),
        })
        .collect();

    // Field-to-field equalities lower through the `fieldref` modifier so the
    // value is treated as another field name (`field = other_field`), not a
    // string literal.
    items.extend(field_refs.iter().map(|(field, target)| DetectionItem {
        field: FieldSpec::new(Some(field.clone()), vec![Modifier::FieldRef]),
        values: vec![SigmaValue::String(SigmaString::new(target))],
    }));

    let det_name = format!("__pipeline_cond_{}", rule.detection.named.len());
    rule.detection
        .named
        .insert(det_name.clone(), Detection::AllOf(items));

    // Add to existing conditions: AND (or AND NOT if negated)
    let cond_ref = ConditionExpr::Identifier(det_name);
    let cond_expr = if negated {
        ConditionExpr::Not(Box::new(cond_ref))
    } else {
        cond_ref
    };

    rule.detection.conditions = rule
        .detection
        .conditions
        .iter()
        .map(|existing| {
            // `prepend` puts the added condition first (`new AND
            // existing`) so left-to-right short-circuiting engines
            // evaluate the cheap discriminator before the rule body;
            // the default appends (`existing AND new`).
            let parts = if prepend {
                vec![cond_expr.clone(), existing.clone()]
            } else {
                vec![existing.clone(), cond_expr.clone()]
            };
            ConditionExpr::And(parts)
        })
        .collect();
}

// =============================================================================
// Replace strings
// =============================================================================

#[allow(clippy::too_many_arguments)]
pub(super) fn replace_strings_in_rule(
    rule: &mut SigmaRule,
    state: &PipelineState,
    detection_conditions: &[&ConditionSet<DetectionItemCondition>],
    field_name_conditions: &[&ConditionSet<FieldNameCondition>],
    re: &Regex,
    replacement: &str,
    skip_special: bool,
) {
    for detection in rule.detection.named.values_mut() {
        replace_strings_in_detection(
            detection,
            state,
            detection_conditions,
            field_name_conditions,
            re,
            replacement,
            skip_special,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn replace_strings_in_detection(
    detection: &mut Detection,
    state: &PipelineState,
    detection_conditions: &[&ConditionSet<DetectionItemCondition>],
    field_name_conditions: &[&ConditionSet<FieldNameCondition>],
    re: &Regex,
    replacement: &str,
    skip_special: bool,
) {
    match detection {
        Detection::AllOf(items) => {
            for item in items.iter_mut() {
                let det_match = detection_conditions_match(item, state, detection_conditions);
                let field_match = if let Some(ref name) = item.field.name {
                    field_conditions_match(name, state, field_name_conditions)
                } else {
                    condition_sets_are_empty(field_name_conditions)
                };

                if det_match && field_match {
                    replace_strings_in_values(&mut item.values, re, replacement, skip_special);
                }
            }
        }
        Detection::AnyOf(subs) => {
            for sub in subs.iter_mut() {
                replace_strings_in_detection(
                    sub,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    re,
                    replacement,
                    skip_special,
                );
            }
        }
        Detection::ArrayMatch { body, .. } => {
            replace_strings_in_detection(
                body.as_mut(),
                state,
                detection_conditions,
                field_name_conditions,
                re,
                replacement,
                skip_special,
            );
        }
        Detection::And(subs) => {
            for sub in subs.iter_mut() {
                replace_strings_in_detection(
                    sub,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    re,
                    replacement,
                    skip_special,
                );
            }
        }
        Detection::Conditional { named, .. } => {
            for sub in named.values_mut() {
                replace_strings_in_detection(
                    sub,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    re,
                    replacement,
                    skip_special,
                );
            }
        }
        Detection::Keywords(values) => {
            replace_strings_in_values(values, re, replacement, skip_special);
        }
    }
}

fn replace_strings_in_values(
    values: &mut [SigmaValue],
    re: &Regex,
    replacement: &str,
    skip_special: bool,
) {
    for value in values.iter_mut() {
        if let SigmaValue::String(s) = value {
            if skip_special && s.contains_wildcards() {
                // Replace only in plain segments, preserving wildcards
                let new_parts: Vec<StringPart> = s
                    .parts
                    .iter()
                    .map(|part| match part {
                        StringPart::Plain(text) => {
                            let replaced = re.replace_all(text, replacement);
                            StringPart::Plain(replaced.into_owned())
                        }
                        special => special.clone(),
                    })
                    .collect();
                if new_parts != s.parts {
                    let new_original = parts_to_original(&new_parts);
                    s.parts = new_parts;
                    s.original = new_original;
                }
            } else {
                let replaced = re.replace_all(&s.original, replacement);
                if replaced != s.original {
                    *s = SigmaString::new(&replaced);
                }
            }
        }
    }
}

/// Reconstruct the `original` string from parts, re-escaping wildcards.
fn parts_to_original(parts: &[StringPart]) -> String {
    let mut out = String::new();
    for part in parts {
        match part {
            StringPart::Plain(text) => {
                for c in text.chars() {
                    if c == '*' || c == '?' || c == '\\' {
                        out.push('\\');
                    }
                    out.push(c);
                }
            }
            StringPart::Special(SpecialChar::WildcardMulti) => out.push('*'),
            StringPart::Special(SpecialChar::WildcardSingle) => out.push('?'),
        }
    }
    out
}

// =============================================================================
// Placeholder expansion
// =============================================================================

pub(super) fn expand_placeholders_in_rule(
    rule: &mut SigmaRule,
    state: &PipelineState,
    wildcard: bool,
    allow_unresolved: bool,
    include: Option<&[String]>,
    exclude: Option<&[String]>,
) -> Result<()> {
    for detection in rule.detection.named.values_mut() {
        expand_placeholders_in_detection(
            detection,
            state,
            wildcard,
            allow_unresolved,
            include,
            exclude,
        )?;
    }
    Ok(())
}

fn expand_placeholders_in_detection(
    detection: &mut Detection,
    state: &PipelineState,
    wildcard: bool,
    allow_unresolved: bool,
    include: Option<&[String]>,
    exclude: Option<&[String]>,
) -> Result<()> {
    match detection {
        Detection::AllOf(items) => {
            for item in items.iter_mut() {
                if item.field.modifiers.contains(&Modifier::Expand) {
                    expand_placeholders_in_values(
                        &mut item.values,
                        state,
                        wildcard,
                        allow_unresolved,
                        include,
                        exclude,
                    )?;
                }
            }
        }
        Detection::AnyOf(subs) => {
            for sub in subs.iter_mut() {
                expand_placeholders_in_detection(
                    sub,
                    state,
                    wildcard,
                    allow_unresolved,
                    include,
                    exclude,
                )?;
            }
        }
        Detection::ArrayMatch { body, .. } => {
            expand_placeholders_in_detection(
                body.as_mut(),
                state,
                wildcard,
                allow_unresolved,
                include,
                exclude,
            )?;
        }
        Detection::And(subs) => {
            for sub in subs.iter_mut() {
                expand_placeholders_in_detection(
                    sub,
                    state,
                    wildcard,
                    allow_unresolved,
                    include,
                    exclude,
                )?;
            }
        }
        Detection::Conditional { named, .. } => {
            for sub in named.values_mut() {
                expand_placeholders_in_detection(
                    sub,
                    state,
                    wildcard,
                    allow_unresolved,
                    include,
                    exclude,
                )?;
            }
        }
        Detection::Keywords(_) => {}
    }
    Ok(())
}

fn expand_placeholders_in_values(
    values: &mut Vec<SigmaValue>,
    state: &PipelineState,
    wildcard: bool,
    allow_unresolved: bool,
    include: Option<&[String]>,
    exclude: Option<&[String]>,
) -> Result<()> {
    let mut expanded_values = Vec::new();
    for value in values.drain(..) {
        if let SigmaValue::String(ref s) = value
            && s.original.contains('%')
        {
            expanded_values.extend(expand_placeholder_string(
                &s.original,
                state,
                wildcard,
                allow_unresolved,
                include,
                exclude,
            )?);
            continue;
        }
        expanded_values.push(value);
    }
    *values = expanded_values;
    Ok(())
}

/// The first placeholder at or after byte `from` of raw Sigma source text, as
/// the offsets of its opening and closing `%`. A `%` escaped by a backslash
/// does not open one, and a name is non-empty and has no `*`, `?`, or
/// backslash.
fn find_placeholder(s: &str, from: usize) -> Option<(usize, usize)> {
    let mut search = from;
    while let Some(offset) = s[search..].find('%') {
        let open = search + offset;
        let backslashes = s[..open].bytes().rev().take_while(|&b| b == b'\\').count();
        let rest = &s[open + 1..];
        if backslashes % 2 == 0
            && let Some(len) = rest.find(['%', '*', '?', '\\'])
            && len > 0
            && rest[len..].starts_with('%')
        {
            return Some((open, open + 1 + len));
        }
        search = open + 1;
    }
    None
}

const MAX_PLACEHOLDER_COMBINATIONS: usize = 4096;
const MAX_PLACEHOLDER_DEPTH: usize = 64;

/// Substitute every placeholder in the raw source text `s`, producing the
/// Cartesian product of multi-value variables.
fn expand_placeholder_string(
    s: &str,
    state: &PipelineState,
    wildcard: bool,
    allow_unresolved: bool,
    include: Option<&[String]>,
    exclude: Option<&[String]>,
) -> Result<Vec<SigmaValue>> {
    let mut pending = vec![(s.to_string(), 0usize)];
    let mut complete = Vec::new();
    let mut depth = 0;

    while !pending.is_empty() {
        let mut next = Vec::new();
        let mut substituted = false;
        'value: for (value, mut from) in pending {
            loop {
                let Some((open, close)) = find_placeholder(&value, from) else {
                    complete.push(value);
                    continue 'value;
                };
                let placeholder = &value[open + 1..close];
                let handled = include
                    .is_none_or(|names| names.iter().any(|name| name == placeholder))
                    && exclude.is_none_or(|names| !names.iter().any(|name| name == placeholder));
                if !handled {
                    from = close + 1;
                    continue;
                }
                if !wildcard && allow_unresolved && !state.vars.contains_key(placeholder) {
                    from = close + 1;
                    continue;
                }
                if depth >= MAX_PLACEHOLDER_DEPTH {
                    return Err(EvalError::InvalidModifiers(format!(
                        "placeholder expansion exceeds the maximum depth of {MAX_PLACEHOLDER_DEPTH}"
                    )));
                }
                substituted = true;
                let replacements: Vec<&str> = match (wildcard, state.vars.get(placeholder)) {
                    (true, _) => vec!["*"],
                    (false, Some(values)) => values.iter().map(String::as_str).collect(),
                    (false, None) => {
                        return Err(EvalError::InvalidModifiers(format!(
                            "placeholder replacement variable '{placeholder}' is not defined"
                        )));
                    }
                };

                if complete
                    .len()
                    .saturating_add(next.len())
                    .saturating_add(replacements.len())
                    > MAX_PLACEHOLDER_COMBINATIONS
                {
                    return Err(EvalError::InvalidModifiers(format!(
                        "placeholder expansion would produce more than \
                         {MAX_PLACEHOLDER_COMBINATIONS} values"
                    )));
                }

                for replacement in replacements {
                    next.push((
                        format!("{}{}{}", &value[..open], replacement, &value[close + 1..]),
                        open + replacement.len(),
                    ));
                }
                continue 'value;
            }
        }
        if substituted {
            depth += 1;
        }
        pending = next;
    }

    Ok(complete
        .into_iter()
        .map(|value| SigmaValue::String(SigmaString::new(&value)))
        .collect())
}

// =============================================================================
// Named string function helper (for FieldNameTransform)
// =============================================================================

pub(super) fn apply_named_string_fn(func: &str, s: &str) -> String {
    match func {
        "lower" | "lowercase" => s.to_lowercase(),
        "upper" | "uppercase" => s.to_uppercase(),
        "title" => s
            .split(|c: char| !c.is_alphanumeric())
            .filter(|w| !w.is_empty())
            .map(|w| {
                let mut c = w.chars();
                match c.next() {
                    None => String::new(),
                    Some(f) => f.to_uppercase().collect::<String>() + &c.as_str().to_lowercase(),
                }
            })
            .collect::<Vec<_>>()
            .join("_"),
        "snake_case" => {
            let mut out = String::new();
            for (i, ch) in s.chars().enumerate() {
                if ch.is_uppercase() && i > 0 {
                    out.push('_');
                }
                out.push(ch.to_lowercase().next().unwrap_or(ch));
            }
            out
        }
        _ => s.to_string(),
    }
}

// =============================================================================
// Hashes field decomposition
// =============================================================================

pub(super) fn decompose_hashes_field(
    rule: &mut SigmaRule,
    valid_algos: &[String],
    field_prefix: &str,
    drop_algo_prefix: bool,
) {
    for detection in rule.detection.named.values_mut() {
        decompose_hashes_in_detection(detection, valid_algos, field_prefix, drop_algo_prefix);
    }
}

fn decompose_hashes_in_detection(
    detection: &mut Detection,
    valid_algos: &[String],
    field_prefix: &str,
    drop_algo_prefix: bool,
) {
    match detection {
        Detection::AllOf(items) => {
            let mut new_items: Vec<DetectionItem> = Vec::new();
            let mut i = 0;
            while i < items.len() {
                let item = &items[i];
                let is_hashes = item
                    .field
                    .name
                    .as_deref()
                    .map(|n| n.eq_ignore_ascii_case("hashes"))
                    .unwrap_or(false);

                if is_hashes {
                    for val in &item.values {
                        if let SigmaValue::String(s) = val {
                            let plain = s.as_plain().unwrap_or_else(|| s.original.clone());
                            for pair in plain.split(',') {
                                let pair = pair.trim();
                                if let Some((algo, hash)) = pair.split_once('=') {
                                    let algo_upper = algo.trim().to_uppercase();
                                    if valid_algos.is_empty()
                                        || valid_algos
                                            .iter()
                                            .any(|a| a.eq_ignore_ascii_case(&algo_upper))
                                    {
                                        let field_name = if drop_algo_prefix {
                                            field_prefix.to_string()
                                        } else {
                                            format!("{field_prefix}{}", algo.trim())
                                        };
                                        new_items.push(DetectionItem {
                                            field: FieldSpec::new(
                                                Some(field_name),
                                                item.field.modifiers.clone(),
                                            ),
                                            values: vec![SigmaValue::String(SigmaString::new(
                                                hash.trim(),
                                            ))],
                                        });
                                    }
                                }
                            }
                        }
                    }
                } else {
                    new_items.push(items[i].clone());
                }
                i += 1;
            }
            *items = new_items;
        }
        Detection::AnyOf(subs) => {
            for sub in subs.iter_mut() {
                decompose_hashes_in_detection(sub, valid_algos, field_prefix, drop_algo_prefix);
            }
        }
        Detection::ArrayMatch { body, .. } => {
            decompose_hashes_in_detection(
                body.as_mut(),
                valid_algos,
                field_prefix,
                drop_algo_prefix,
            );
        }
        Detection::And(subs) => {
            for sub in subs.iter_mut() {
                decompose_hashes_in_detection(sub, valid_algos, field_prefix, drop_algo_prefix);
            }
        }
        Detection::Conditional { named, .. } => {
            for sub in named.values_mut() {
                decompose_hashes_in_detection(sub, valid_algos, field_prefix, drop_algo_prefix);
            }
        }
        Detection::Keywords(_) => {}
    }
}

// =============================================================================
// Map string values
// =============================================================================

pub(super) fn map_string_values(
    rule: &mut SigmaRule,
    state: &PipelineState,
    detection_conditions: &[&ConditionSet<DetectionItemCondition>],
    field_name_conditions: &[&ConditionSet<FieldNameCondition>],
    mapping: &HashMap<String, Vec<String>>,
) {
    for detection in rule.detection.named.values_mut() {
        map_strings_in_detection(
            detection,
            state,
            detection_conditions,
            field_name_conditions,
            mapping,
        );
    }
}

fn map_strings_in_detection(
    detection: &mut Detection,
    state: &PipelineState,
    detection_conditions: &[&ConditionSet<DetectionItemCondition>],
    field_name_conditions: &[&ConditionSet<FieldNameCondition>],
    mapping: &HashMap<String, Vec<String>>,
) {
    match detection {
        Detection::AllOf(items) => {
            for item in items.iter_mut() {
                if item_conditions_match(item, state, detection_conditions, field_name_conditions) {
                    map_string_expand_values(&mut item.values, mapping);
                }
            }
        }
        Detection::AnyOf(subs) => {
            for sub in subs.iter_mut() {
                map_strings_in_detection(
                    sub,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    mapping,
                );
            }
        }
        Detection::ArrayMatch { body, .. } => {
            map_strings_in_detection(
                body.as_mut(),
                state,
                detection_conditions,
                field_name_conditions,
                mapping,
            );
        }
        Detection::And(subs) => {
            for sub in subs.iter_mut() {
                map_strings_in_detection(
                    sub,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    mapping,
                );
            }
        }
        Detection::Conditional { named, .. } => {
            for sub in named.values_mut() {
                map_strings_in_detection(
                    sub,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    mapping,
                );
            }
        }
        Detection::Keywords(values) => {
            map_string_expand_values(values, mapping);
        }
    }
}

/// Map string values with one-to-many support.
///
/// When a mapping entry has multiple replacements (e.g. `"foo": ["bar", "baz"]`),
/// the original value is replaced with the first alternative and additional
/// alternatives are appended to the values list. This expands the detection
/// item's value list, matching pySigma's `MapStringTransformation` behavior.
fn map_string_expand_values(values: &mut Vec<SigmaValue>, mapping: &HashMap<String, Vec<String>>) {
    let mut extra: Vec<(usize, Vec<SigmaValue>)> = Vec::new();

    for (i, val) in values.iter_mut().enumerate() {
        if let SigmaValue::String(s) = val {
            let plain = s.as_plain().unwrap_or_else(|| s.original.clone());
            if let Some(replacements) = mapping.get(&plain) {
                if let Some(first) = replacements.first() {
                    *s = SigmaString::new(first);
                }
                if replacements.len() > 1 {
                    let extras: Vec<SigmaValue> = replacements[1..]
                        .iter()
                        .map(|r| SigmaValue::String(SigmaString::new(r)))
                        .collect();
                    extra.push((i, extras));
                }
            }
        }
    }

    // Insert extra values in reverse order so indices remain valid
    for (idx, extras) in extra.into_iter().rev() {
        for (j, v) in extras.into_iter().enumerate() {
            values.insert(idx + 1 + j, v);
        }
    }
}

// =============================================================================
// Set value
// =============================================================================

pub(super) fn set_detection_item_values(
    rule: &mut SigmaRule,
    state: &PipelineState,
    detection_conditions: &[&ConditionSet<DetectionItemCondition>],
    field_name_conditions: &[&ConditionSet<FieldNameCondition>],
    value: &SigmaValue,
) {
    for detection in rule.detection.named.values_mut() {
        set_values_in_detection(
            detection,
            state,
            detection_conditions,
            field_name_conditions,
            value,
        );
    }
}

fn set_values_in_detection(
    detection: &mut Detection,
    state: &PipelineState,
    detection_conditions: &[&ConditionSet<DetectionItemCondition>],
    field_name_conditions: &[&ConditionSet<FieldNameCondition>],
    value: &SigmaValue,
) {
    match detection {
        Detection::AllOf(items) => {
            for item in items.iter_mut() {
                if item_conditions_match(item, state, detection_conditions, field_name_conditions) {
                    item.values = vec![value.clone()];
                }
            }
        }
        Detection::AnyOf(subs) => {
            for sub in subs.iter_mut() {
                set_values_in_detection(
                    sub,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    value,
                );
            }
        }
        Detection::ArrayMatch { body, .. } => {
            set_values_in_detection(
                body.as_mut(),
                state,
                detection_conditions,
                field_name_conditions,
                value,
            );
        }
        Detection::And(subs) => {
            for sub in subs.iter_mut() {
                set_values_in_detection(
                    sub,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    value,
                );
            }
        }
        Detection::Conditional { named, .. } => {
            for sub in named.values_mut() {
                set_values_in_detection(
                    sub,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    value,
                );
            }
        }
        Detection::Keywords(_) => {}
    }
}

// =============================================================================
// Convert type
// =============================================================================

pub(super) fn convert_detection_item_types(
    rule: &mut SigmaRule,
    state: &PipelineState,
    detection_conditions: &[&ConditionSet<DetectionItemCondition>],
    field_name_conditions: &[&ConditionSet<FieldNameCondition>],
    target_type: &str,
) {
    for detection in rule.detection.named.values_mut() {
        convert_types_in_detection(
            detection,
            state,
            detection_conditions,
            field_name_conditions,
            target_type,
        );
    }
}

fn convert_types_in_detection(
    detection: &mut Detection,
    state: &PipelineState,
    detection_conditions: &[&ConditionSet<DetectionItemCondition>],
    field_name_conditions: &[&ConditionSet<FieldNameCondition>],
    target_type: &str,
) {
    match detection {
        Detection::AllOf(items) => {
            for item in items.iter_mut() {
                if item_conditions_match(item, state, detection_conditions, field_name_conditions) {
                    for val in item.values.iter_mut() {
                        *val = convert_value(val, target_type);
                    }
                }
            }
        }
        Detection::AnyOf(subs) => {
            for sub in subs.iter_mut() {
                convert_types_in_detection(
                    sub,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    target_type,
                );
            }
        }
        Detection::ArrayMatch { body, .. } => {
            convert_types_in_detection(
                body.as_mut(),
                state,
                detection_conditions,
                field_name_conditions,
                target_type,
            );
        }
        Detection::And(subs) => {
            for sub in subs.iter_mut() {
                convert_types_in_detection(
                    sub,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    target_type,
                );
            }
        }
        Detection::Conditional { named, .. } => {
            for sub in named.values_mut() {
                convert_types_in_detection(
                    sub,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    target_type,
                );
            }
        }
        Detection::Keywords(_) => {}
    }
}

fn convert_value(val: &SigmaValue, target: &str) -> SigmaValue {
    match target {
        "str" | "string" => match val {
            SigmaValue::String(_) => val.clone(),
            SigmaValue::Integer(n) => SigmaValue::String(SigmaString::new(&n.to_string())),
            SigmaValue::Float(f) => SigmaValue::String(SigmaString::new(&f.to_string())),
            SigmaValue::Bool(b) => SigmaValue::String(SigmaString::new(&b.to_string())),
            SigmaValue::Null => SigmaValue::String(SigmaString::new("null")),
        },
        "int" | "integer" => match val {
            SigmaValue::String(s) => {
                let plain = s.as_plain().unwrap_or_else(|| s.original.clone());
                plain
                    .parse::<i64>()
                    .map(SigmaValue::Integer)
                    .unwrap_or_else(|_| val.clone())
            }
            SigmaValue::Float(f) => SigmaValue::Integer(*f as i64),
            SigmaValue::Bool(b) => SigmaValue::Integer(if *b { 1 } else { 0 }),
            _ => val.clone(),
        },
        "float" => match val {
            SigmaValue::String(s) => {
                let plain = s.as_plain().unwrap_or_else(|| s.original.clone());
                plain
                    .parse::<f64>()
                    .map(SigmaValue::Float)
                    .unwrap_or_else(|_| val.clone())
            }
            SigmaValue::Integer(n) => SigmaValue::Float(*n as f64),
            SigmaValue::Bool(b) => SigmaValue::Float(if *b { 1.0 } else { 0.0 }),
            _ => val.clone(),
        },
        "bool" | "boolean" => match val {
            SigmaValue::String(s) => {
                let plain = s.as_plain().unwrap_or_else(|| s.original.clone());
                match plain.to_lowercase().as_str() {
                    "true" | "1" | "yes" => SigmaValue::Bool(true),
                    "false" | "0" | "no" => SigmaValue::Bool(false),
                    _ => val.clone(),
                }
            }
            SigmaValue::Integer(n) => SigmaValue::Bool(*n != 0),
            SigmaValue::Float(f) => SigmaValue::Bool(*f != 0.0),
            _ => val.clone(),
        },
        _ => val.clone(),
    }
}

// =============================================================================
// Case transformation
// =============================================================================

pub(super) fn apply_case_transformation(
    rule: &mut SigmaRule,
    state: &PipelineState,
    detection_conditions: &[&ConditionSet<DetectionItemCondition>],
    field_name_conditions: &[&ConditionSet<FieldNameCondition>],
    case_type: &str,
) {
    for detection in rule.detection.named.values_mut() {
        apply_case_in_detection(
            detection,
            state,
            detection_conditions,
            field_name_conditions,
            case_type,
        );
    }
}

fn apply_case_in_detection(
    detection: &mut Detection,
    state: &PipelineState,
    detection_conditions: &[&ConditionSet<DetectionItemCondition>],
    field_name_conditions: &[&ConditionSet<FieldNameCondition>],
    case_type: &str,
) {
    match detection {
        Detection::AllOf(items) => {
            for item in items.iter_mut() {
                if item_conditions_match(item, state, detection_conditions, field_name_conditions) {
                    for val in item.values.iter_mut() {
                        apply_case_to_value(val, case_type);
                    }
                }
            }
        }
        Detection::AnyOf(subs) => {
            for sub in subs.iter_mut() {
                apply_case_in_detection(
                    sub,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    case_type,
                );
            }
        }
        Detection::ArrayMatch { body, .. } => {
            apply_case_in_detection(
                body.as_mut(),
                state,
                detection_conditions,
                field_name_conditions,
                case_type,
            );
        }
        Detection::And(subs) => {
            for sub in subs.iter_mut() {
                apply_case_in_detection(
                    sub,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    case_type,
                );
            }
        }
        Detection::Conditional { named, .. } => {
            for sub in named.values_mut() {
                apply_case_in_detection(
                    sub,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    case_type,
                );
            }
        }
        Detection::Keywords(values) => {
            for val in values.iter_mut() {
                apply_case_to_value(val, case_type);
            }
        }
    }
}

fn apply_case_to_value(val: &mut SigmaValue, case_type: &str) {
    if let SigmaValue::String(s) = val {
        let transformed = match case_type {
            "lower" | "lowercase" => s.original.to_lowercase(),
            "upper" | "uppercase" => s.original.to_uppercase(),
            "snake_case" => apply_named_string_fn("snake_case", &s.original),
            _ => return,
        };
        if transformed != s.original {
            *s = SigmaString::new(&transformed);
        }
    }
}

// =============================================================================
// Shared helper: check if a detection item matches both sets of conditions
// =============================================================================

fn item_conditions_match(
    item: &DetectionItem,
    state: &PipelineState,
    detection_conditions: &[&ConditionSet<DetectionItemCondition>],
    field_name_conditions: &[&ConditionSet<FieldNameCondition>],
) -> bool {
    let det_match = detection_conditions_match(item, state, detection_conditions);

    let field_match = if let Some(ref name) = item.field.name {
        field_conditions_match(name, state, field_name_conditions)
    } else {
        condition_sets_are_empty(field_name_conditions)
    };

    det_match && field_match
}

// =============================================================================
// Helper: check if rule has any item matching conditions
// =============================================================================

pub(super) fn rule_has_matching_item(
    rule: &SigmaRule,
    state: &PipelineState,
    conditions: &[&ConditionSet<DetectionItemCondition>],
) -> bool {
    for detection in rule.detection.named.values() {
        if detection_has_matching_item(detection, state, conditions) {
            return true;
        }
    }
    false
}

fn detection_has_matching_item(
    detection: &Detection,
    state: &PipelineState,
    conditions: &[&ConditionSet<DetectionItemCondition>],
) -> bool {
    match detection {
        Detection::AllOf(items) => items
            .iter()
            .any(|item| detection_conditions_match(item, state, conditions)),
        Detection::AnyOf(subs) => subs
            .iter()
            .any(|sub| detection_has_matching_item(sub, state, conditions)),
        Detection::ArrayMatch { body, .. } => {
            detection_has_matching_item(body.as_ref(), state, conditions)
        }
        Detection::And(subs) => subs
            .iter()
            .any(|sub| detection_has_matching_item(sub, state, conditions)),
        Detection::Conditional { named, .. } => named
            .values()
            .any(|sub| detection_has_matching_item(sub, state, conditions)),
        Detection::Keywords(_) => false,
    }
}
