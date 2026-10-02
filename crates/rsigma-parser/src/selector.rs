//! Detection-name glob matching for `... of selection_*` selector expressions.
//!
//! The selector matcher is shared by the parser, the evaluator, and the
//! converter so that a pattern like `sel*main` resolves to the same set of
//! detection identifiers regardless of which subsystem expands it. Keeping the
//! semantics in one place also avoids the historical drift between `eval` and
//! `convert`, where `convert` supported a middle `*` (`sel*main`) but `eval`
//! did not.

use crate::ast::SelectorPattern;

/// Check whether a detection identifier matches a glob `pattern`.
///
/// A single `*` is treated as a wildcard. The supported shapes are:
///
/// - `*` — match any identifier
/// - `selection_*` — match identifiers starting with `selection_`
/// - `*_main` — match identifiers ending with `_main`
/// - `sel*main` — match identifiers starting with `sel` and ending with `main`
/// - `selection` — exact match
///
/// All other characters are matched literally. The function does not interpret
/// any other meta-character; in particular `?` is not a wildcard.
///
/// # Examples
///
/// ```
/// use rsigma_parser::detection_name_matches;
/// assert!(detection_name_matches("selection_*", "selection_main"));
/// assert!(detection_name_matches("*_main", "selection_main"));
/// assert!(detection_name_matches("sel*main", "selection_main"));
/// assert!(!detection_name_matches("sel*main", "filter_main"));
/// ```
pub fn detection_name_matches(pattern: &str, name: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return name.starts_with(prefix);
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        return name.ends_with(suffix);
    }
    if let Some((prefix, suffix)) = pattern.split_once('*') {
        return name.starts_with(prefix) && name.ends_with(suffix);
    }
    pattern == name
}

impl SelectorPattern {
    /// Return true if this selector pattern matches a detection identifier.
    ///
    /// Identifiers beginning with `_` are hidden from `them` and from every
    /// pattern that does not itself begin with `_`, as in the Sigma
    /// specification and pySigma. Otherwise
    /// [`SelectorPattern::Pattern`] dispatches through
    /// [`detection_name_matches`].
    pub fn matches_detection_name(&self, name: &str) -> bool {
        match self {
            SelectorPattern::Them => !name.starts_with('_'),
            SelectorPattern::Pattern(pat) => {
                (pat.starts_with('_') || !name.starts_with('_'))
                    && detection_name_matches(pat, name)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn star_only_matches_anything() {
        assert!(detection_name_matches("*", "anything"));
        assert!(detection_name_matches("*", ""));
    }

    #[test]
    fn star_suffix_matches_prefix() {
        assert!(detection_name_matches("selection_*", "selection_main"));
        assert!(detection_name_matches("selection_*", "selection_"));
        assert!(!detection_name_matches("selection_*", "filter_main"));
    }

    #[test]
    fn star_prefix_matches_suffix() {
        assert!(detection_name_matches("*_main", "selection_main"));
        assert!(!detection_name_matches("*_main", "selection_alt"));
    }

    #[test]
    fn star_middle_matches_prefix_and_suffix() {
        // The regression that previously diverged between eval and convert:
        // eval did not implement the middle `*` branch, so the same selector
        // pattern resolved to different detection sets in the two crates.
        assert!(detection_name_matches("sel*main", "selection_main"));
        assert!(!detection_name_matches("sel*main", "filter_main"));
        assert!(!detection_name_matches("sel*main", "selection_alt"));
    }

    #[test]
    fn exact_match_without_star() {
        assert!(detection_name_matches("selection", "selection"));
        assert!(!detection_name_matches("selection", "filter"));
        assert!(!detection_name_matches("selection", "selection_main"));
    }

    #[test]
    fn underscore_pattern_is_literal() {
        // A leading underscore in the glob is an ordinary character; hiding
        // `_` identifiers is the selector's job, not the glob's.
        assert!(detection_name_matches("_helper", "_helper"));
        assert!(!detection_name_matches("_helper", "helper"));
        assert!(detection_name_matches("*", "_helper"));
    }

    #[test]
    fn selector_pattern_them_skips_underscore_names() {
        let them = SelectorPattern::Them;
        assert!(them.matches_detection_name("selection"));
        assert!(!them.matches_detection_name("_internal"));
    }

    #[test]
    fn selector_pattern_pattern_uses_glob() {
        let pat = SelectorPattern::Pattern("selection_*".to_string());
        assert!(pat.matches_detection_name("selection_main"));
        assert!(!pat.matches_detection_name("filter_main"));
    }

    #[test]
    fn selector_pattern_skips_underscore_names_unless_it_starts_with_one() {
        let star = SelectorPattern::Pattern("*".to_string());
        assert!(star.matches_detection_name("selection"));
        assert!(!star.matches_detection_name("_internal"));
        let suffix = SelectorPattern::Pattern("*_main".to_string());
        assert!(!suffix.matches_detection_name("_sel_main"));

        let internal = SelectorPattern::Pattern("_internal".to_string());
        assert!(internal.matches_detection_name("_internal"));
        let hidden = SelectorPattern::Pattern("_*".to_string());
        assert!(hidden.matches_detection_name("_internal"));
        assert!(!hidden.matches_detection_name("selection"));
    }
}
