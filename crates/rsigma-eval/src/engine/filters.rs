use rsigma_parser::{ConditionExpr, LogSource, SelectorPattern};

/// Asymmetric containment check for filter-to-rule matching: every field the
/// filter specifies must be present and equal in the rule. Fields the filter
/// omits are treated as wildcards (match any rule). This means a filter with
/// only `product: windows` applies to rules that have `product: windows`
/// regardless of their category/service, but a filter with
/// `category: process_creation` does NOT apply to a rule that lacks a category.
pub(super) fn filter_logsource_contains(filter_ls: &LogSource, rule_ls: &LogSource) -> bool {
    fn field_matches(filter_field: &Option<String>, rule_field: &Option<String>) -> bool {
        match filter_field {
            None => true,
            Some(fv) => match rule_field {
                Some(rv) => fv.eq_ignore_ascii_case(rv),
                None => false,
            },
        }
    }

    field_matches(&filter_ls.category, &rule_ls.category)
        && field_matches(&filter_ls.product, &rule_ls.product)
        && field_matches(&filter_ls.service, &rule_ls.service)
}

/// Rewrite all `Identifier` nodes in a condition expression tree, prefixing
/// each name with `__filter_{counter}_` so it references the namespaced
/// detection keys injected into the target rule.
pub(super) fn rewrite_condition_identifiers(expr: &ConditionExpr, counter: usize) -> ConditionExpr {
    match expr {
        ConditionExpr::Identifier(name) => {
            ConditionExpr::Identifier(format!("__filter_{counter}_{name}"))
        }
        ConditionExpr::And(children) => ConditionExpr::And(
            children
                .iter()
                .map(|c| rewrite_condition_identifiers(c, counter))
                .collect(),
        ),
        ConditionExpr::Or(children) => ConditionExpr::Or(
            children
                .iter()
                .map(|c| rewrite_condition_identifiers(c, counter))
                .collect(),
        ),
        ConditionExpr::Not(child) => {
            ConditionExpr::Not(Box::new(rewrite_condition_identifiers(child, counter)))
        }
        ConditionExpr::Selector {
            quantifier,
            pattern,
        } => {
            let pattern = match pattern {
                SelectorPattern::Them => SelectorPattern::Pattern(format!("__filter_{counter}_*")),
                SelectorPattern::Pattern(pattern) => {
                    SelectorPattern::Pattern(format!("__filter_{counter}_{pattern}"))
                }
            };
            ConditionExpr::Selector {
                quantifier: quantifier.clone(),
                pattern,
            }
        }
    }
}

/// Conflict-based compatibility check for hot-path logsource pruning.
///
/// Returns `false` only when a dimension is set on BOTH the rule and the
/// event and the two values differ (case-insensitive). A dimension unset on
/// either side is a wildcard, so the rule is kept. The standard `product`,
/// `service`, and `category` dimensions are checked, plus any custom dimension
/// keys present on both sides (a rule custom key the event does not assert is a
/// wildcard, and vice versa). `definition` is ignored.
///
/// This is deliberately distinct from the subset [`logsource_matches`] (and
/// the filter-side [`filter_logsource_contains`]): subset semantics require
/// every dimension the rule names to be present and equal in the event, which
/// would drop a `product: windows, category: process_creation` rule for an
/// event tagged only `product: windows` (no category) and silently lose the
/// detection. Conflict-based semantics keep that rule (the event never
/// asserted a conflicting category) and skip only rules whose stated
/// dimension genuinely disagrees with the event.
pub(super) fn logsource_compatible(rule_ls: &LogSource, event_ls: &LogSource) -> bool {
    fn conflicts(rule_field: &Option<String>, event_field: &Option<String>) -> bool {
        match (rule_field, event_field) {
            (Some(r), Some(e)) => !r.eq_ignore_ascii_case(e),
            _ => false,
        }
    }

    // A custom dimension conflicts only when the same key is present on both
    // sides with differing values; keys on one side only are wildcards.
    let custom_conflict = rule_ls.custom.iter().any(|(key, rule_value)| {
        event_ls
            .custom
            .get(key)
            .is_some_and(|event_value| !rule_value.eq_ignore_ascii_case(event_value))
    });

    !(conflicts(&rule_ls.product, &event_ls.product)
        || conflicts(&rule_ls.service, &event_ls.service)
        || conflicts(&rule_ls.category, &event_ls.category)
        || custom_conflict)
}

/// Asymmetric check: every field specified in `rule_ls` must be present and
/// match in `event_ls`. Used for routing events to rules by logsource.
pub(super) fn logsource_matches(rule_ls: &LogSource, event_ls: &LogSource) -> bool {
    if let Some(ref cat) = rule_ls.category {
        match &event_ls.category {
            Some(ec) if ec.eq_ignore_ascii_case(cat) => {}
            _ => return false,
        }
    }
    if let Some(ref prod) = rule_ls.product {
        match &event_ls.product {
            Some(ep) if ep.eq_ignore_ascii_case(prod) => {}
            _ => return false,
        }
    }
    if let Some(ref svc) = rule_ls.service {
        match &event_ls.service {
            Some(es) if es.eq_ignore_ascii_case(svc) => {}
            _ => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsigma_parser::{Quantifier, SelectorPattern};
    use std::collections::HashMap;

    fn ls(product: Option<&str>, custom: &[(&str, &str)]) -> LogSource {
        LogSource {
            product: product.map(str::to_string),
            custom: custom
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<HashMap<_, _>>(),
            ..LogSource::default()
        }
    }

    #[test]
    fn custom_dimension_conflict_prunes_only_on_disagreement() {
        // Same custom key, differing values -> conflict (skip).
        assert!(!logsource_compatible(
            &ls(None, &[("tenant", "acme")]),
            &ls(None, &[("tenant", "globex")]),
        ));
        // Same custom key, same value (case-insensitive) -> keep.
        assert!(logsource_compatible(
            &ls(None, &[("tenant", "ACME")]),
            &ls(None, &[("tenant", "acme")]),
        ));
        // Key only on the rule side -> wildcard, keep.
        assert!(logsource_compatible(
            &ls(None, &[("tenant", "acme")]),
            &ls(None, &[]),
        ));
        // Key only on the event side -> wildcard, keep.
        assert!(logsource_compatible(
            &ls(None, &[]),
            &ls(None, &[("tenant", "acme")]),
        ));
        // Standard-dimension conflict still prunes alongside custom.
        assert!(!logsource_compatible(
            &ls(Some("linux"), &[]),
            &ls(Some("windows"), &[("tenant", "acme")]),
        ));
    }

    #[test]
    fn selector_patterns_are_scoped_to_injected_filter_detections() {
        let expression = ConditionExpr::Selector {
            quantifier: Quantifier::Any,
            pattern: SelectorPattern::Pattern("selection_*".to_string()),
        };
        assert_eq!(
            rewrite_condition_identifiers(&expression, 3),
            ConditionExpr::Selector {
                quantifier: Quantifier::Any,
                pattern: SelectorPattern::Pattern("__filter_3_selection_*".to_string()),
            }
        );
    }

    #[test]
    fn them_is_scoped_to_injected_filter_detections() {
        let expression = ConditionExpr::Selector {
            quantifier: Quantifier::All,
            pattern: SelectorPattern::Them,
        };
        assert_eq!(
            rewrite_condition_identifiers(&expression, 2),
            ConditionExpr::Selector {
                quantifier: Quantifier::All,
                pattern: SelectorPattern::Pattern("__filter_2_*".to_string()),
            }
        );
    }
}
