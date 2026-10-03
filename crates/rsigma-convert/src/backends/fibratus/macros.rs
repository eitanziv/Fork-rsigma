//! Fibratus macro library and AST-output recognition pass.
//!
//! Each entry pairs a macro name with the **clause sequence** the
//! Fibratus backend would emit if a user wrote the macro's expansion
//! verbatim in a Sigma rule. After the backend builds a rule's full
//! condition string, [`recognize`] walks the top-level `and` clauses
//! and replaces any contiguous run that matches a macro's clause
//! sequence with the macro name, so the rendered output reads like
//! the upstream [Fibratus rules library](https://github.com/rabbitstack/fibratus/tree/master/rules)
//! (`spawn_process and ps.exe iendswith '\\cmd.exe'` rather than
//! `evt.name = 'CreateProcess' and ps.exe iendswith '\\cmd.exe'`).
//!
//! Every rendered form of a clause is accepted at recognition time so a
//! macro matches whether a clause was emitted with the case-sensitive
//! string-equality operator (`field = 'literal'`, what `evt.name` and
//! `-O case_sensitive=true` produce), the case-insensitive one
//! (`field ~= 'literal'`, the default for non-`evt.name` literals), the
//! literal inequality (`field != value`), or the De Morgan negated
//! equality the `add_condition` pipeline emits for an inequality clause
//! (`not (field ~= 'literal')`), which is how a disposition guard such as
//! `create_file`'s `file.operation != 'OPEN'` reaches the recognizer.

use std::sync::LazyLock;

// =============================================================================
// Macro source table
// =============================================================================

/// Macro source entries: `(macro_name, upstream_canonical_expression)`.
///
/// Kept as documentation of the original Fibratus macro library; the
/// recognition pass works off the rendered output forms in the
/// private `MACRO_CLAUSES` table (derived from these at startup).
pub const EXPRESSION_MACROS: &[(&str, &str)] = &[
    ("spawn_process", "evt.name = 'CreateProcess'"),
    ("create_thread", "evt.name = 'CreateThread'"),
    ("write_file", "evt.name = 'WriteFile'"),
    ("rename_file", "evt.name = 'RenameFile'"),
    ("read_file", "evt.name = 'ReadFile'"),
    ("delete_file", "evt.name = 'DeleteFile'"),
    ("set_file_information", "evt.name = 'SetFileInformation'"),
    ("load_module", "evt.name = 'LoadModule'"),
    ("unload_module", "evt.name = 'UnloadModule'"),
    ("send_socket", "evt.name = 'Send'"),
    ("recv_socket", "evt.name = 'Recv'"),
    ("connect_socket", "evt.name = 'Connect'"),
    ("accept_socket", "evt.name = 'Accept'"),
    ("virtual_alloc", "evt.name = 'VirtualAlloc'"),
    ("virtual_free", "evt.name = 'VirtualFree'"),
    ("map_view_file", "evt.name = 'MapViewFile'"),
    ("unmap_view_file", "evt.name = 'UnmapViewFile'"),
    ("duplicate_handle", "evt.name = 'DuplicateHandle'"),
    ("create_handle", "evt.name = 'CreateHandle'"),
    ("query_dns", "evt.name = 'QueryDns'"),
    ("reply_dns", "evt.name = 'ReplyDns'"),
    // Multi-clause macros, matched as contiguous clause runs.
    //
    // `create_remote_thread` is `create_thread` plus the cross-process
    // guards (`evt.pid != 4` excludes the System process; `evt.pid !=
    // thread.pid` requires the target thread to live in a different
    // process). Listed before the bare `create_thread` is irrelevant to
    // matching (the recognizer tries longest clause runs first), but its
    // inequality clauses are why the pipeline injects them as negated
    // equalities.
    (
        "create_remote_thread",
        "evt.name = 'CreateThread' and evt.pid != 4 and evt.pid != thread.pid",
    ),
    (
        "open_file",
        "evt.name = 'CreateFile' and file.operation = 'OPEN' and file.status = 'Success'",
    ),
    (
        "create_file",
        "evt.name = 'CreateFile' and file.operation != 'OPEN' and file.status = 'Success'",
    ),
    (
        "create_new_file",
        "evt.name = 'CreateFile' and file.operation = 'CREATE' and file.status = 'Success'",
    ),
    (
        "create_file_supersede",
        "evt.name = 'CreateFile' and file.operation = 'SUPERSEDE'",
    ),
    (
        "set_value",
        "evt.name = 'RegSetValue' and registry.status = 'Success'",
    ),
    (
        "create_key",
        "evt.name = 'RegCreateKey' and registry.status = 'Success'",
    ),
    (
        "open_process",
        "evt.name = 'OpenProcess' and ps.access.status = 'Success'",
    ),
    (
        "open_thread",
        "evt.name = 'OpenThread' and thread.access.status = 'Success'",
    ),
    (
        "open_registry",
        "evt.name = 'RegOpenKey' and registry.status = 'Success'",
    ),
];

/// One macro's pre-rendered clause sequence, each clause carrying every
/// rendered form the backend may emit for it.
///
/// Stored as `(macro_name, per_clause_forms)`. A single upstream clause
/// can surface in several rendered shapes depending on how the conversion
/// ran, so each clause keeps the set of all acceptable forms:
///
/// - case-sensitive exact equality (`field = 'literal'`, used for
///   `evt.name` and `-O case_sensitive=true`);
/// - case-insensitive string equality (`field ~= 'literal'`, the default
///   for a non-`evt.name` literal);
/// - literal inequality (`field != value`); and
/// - the De Morgan negated equality the `add_condition` pipeline emits for
///   an inequality macro clause (`not (field = value)` for a number,
///   `not (field ~= 'literal')` for a string, and `not (field ~= other)`
///   for a field reference).
///
/// Each clause is matched independently against its own form set, so a
/// macro whose `evt.name` clause renders with `=` while a sibling status
/// clause renders with `~=` (or a disposition clause renders as a negated
/// equality) still matches.
type MacroClauses = (&'static str, Vec<Vec<String>>);

/// Pre-rendered macro clauses, derived from [`EXPRESSION_MACROS`] at
/// first access via [`LazyLock`]. The recognizer compares clause-by-clause
/// against each clause's accepted-form set, so a rule that mixes operator
/// forms across separate macros still recognizes each one independently.
static MACRO_CLAUSES: LazyLock<Vec<MacroClauses>> = LazyLock::new(|| {
    EXPRESSION_MACROS
        .iter()
        .map(|(name, src)| {
            let forms: Vec<Vec<String>> = split_clauses(src)
                .into_iter()
                .map(accepted_clause_forms)
                .collect();
            (*name, forms)
        })
        .collect()
});

/// Macro name lookup: is this name a known Fibratus expression macro?
///
/// Used by the macro recognizer and by future linters to avoid
/// emitting collisions when a detection name happens to share a
/// macro identifier.
pub fn is_known_macro(name: &str) -> bool {
    EXPRESSION_MACROS.iter().any(|(n, _)| *n == name)
}

// =============================================================================
// Recognition pass
// =============================================================================

/// Rewrite a Fibratus filter expression so recognized macro clause
/// runs are replaced with the macro name (`spawn_process`,
/// `open_file`, `modify_registry`, ...). The input is the bare
/// condition string the backend's `convert_condition` walk produces;
/// the output is the same expression with longer-prefix-first greedy
/// macro substitutions applied across the top-level `and` clauses.
///
/// The recognizer never reorders clauses, never crosses an `or` /
/// parenthesis boundary, and never splits operands of a single
/// clause. A clause that does not exactly match any macro stays
/// verbatim, so the output is byte-equivalent to the input whenever
/// no macro applies.
pub fn recognize(condition: &str) -> String {
    if condition.is_empty() {
        return String::new();
    }
    let clauses = split_top_level_and(condition);
    if clauses.len() < 2 && !clauses.first().is_some_and(|c| matches_any_macro(c)) {
        // Single bare clause that does not match any macro: shortcut.
        return condition.to_string();
    }

    // Sort macros by descending clause count so the longest-prefix
    // match wins (`open_file` over the bare `create_file_supersede`
    // when the condition carries the full three-clause sequence).
    let mut macros: Vec<&MacroClauses> = MACRO_CLAUSES.iter().collect();
    macros.sort_by_key(|m| std::cmp::Reverse(m.1.len()));

    let mut out: Vec<String> = Vec::with_capacity(clauses.len());
    let mut i = 0;
    while i < clauses.len() {
        let mut matched = None;
        for (name, clause_forms) in &macros {
            let len = clause_forms.len();
            if i + len > clauses.len() {
                continue;
            }
            let slice = &clauses[i..i + len];
            if clauses_match(slice, clause_forms) {
                matched = Some((*name, len));
                break;
            }
        }
        match matched {
            Some((name, len)) => {
                out.push(name.to_string());
                i += len;
            }
            None => {
                out.push(clauses[i].clone());
                i += 1;
            }
        }
    }
    out.join(" and ")
}

fn matches_any_macro(clause: &str) -> bool {
    let binding = clause.to_string();
    let slice = std::slice::from_ref(&binding);
    MACRO_CLAUSES
        .iter()
        .any(|(_, forms)| clauses_match(slice, forms))
}

/// Whether `slice` matches a macro's clause sequence, comparing each
/// clause against its own accepted-form set independently. Per-clause
/// matching means a macro whose `evt.name` clause renders with `=`, a
/// status clause renders with `~=`, and a disposition clause renders as a
/// negated equality still matches without a uniform operator across the
/// whole run.
fn clauses_match(slice: &[String], clause_forms: &[Vec<String>]) -> bool {
    if slice.len() != clause_forms.len() {
        return false;
    }
    slice
        .iter()
        .zip(clause_forms)
        .all(|(got, accepted)| accepted.iter().any(|form| got.trim() == form))
}

// =============================================================================
// Internal: clause splitting and operator normalization
// =============================================================================

/// Split an expression on top-level `and` boundaries, preserving the
/// inner structure of parenthesized groups and single-quoted string
/// literals (no `and` inside `(...)` or `'...'` is treated as a
/// boundary). Mirrors [`super::envelope::soft_wrap`]'s internal
/// splitter so envelope wrapping and macro recognition see the same
/// clause boundaries.
fn split_top_level_and(expr: &str) -> Vec<String> {
    let bytes = expr.as_bytes();
    let mut out: Vec<String> = Vec::new();
    let mut start = 0usize;
    let mut depth = 0i32;
    let mut in_str = false;
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if in_str {
            if b == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if b == b'\'' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        match b {
            b'\'' => in_str = true,
            b'(' => depth += 1,
            b')' => depth -= 1,
            _ => {}
        }
        if depth == 0 && matches_token(bytes, i, b" and ") {
            let piece = expr[start..i].trim().to_string();
            if !piece.is_empty() {
                out.push(piece);
            }
            i += b" and ".len();
            start = i;
            continue;
        }
        i += 1;
    }
    let tail = expr[start..].trim().to_string();
    if !tail.is_empty() {
        out.push(tail);
    }
    out
}

fn matches_token(bytes: &[u8], i: usize, kw: &[u8]) -> bool {
    if i + kw.len() > bytes.len() {
        return false;
    }
    bytes[i..i + kw.len()].eq_ignore_ascii_case(kw)
}

/// Split a multi-clause macro source string on top-level ` and `, the
/// same way the recognizer splits its input. Used at startup to
/// pre-decompose `EXPRESSION_MACROS` into clause vectors.
fn split_clauses(src: &str) -> Vec<&str> {
    let bytes = src.as_bytes();
    let mut out: Vec<&str> = Vec::new();
    let mut start = 0usize;
    let mut depth = 0i32;
    let mut in_str = false;
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if in_str {
            if b == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if b == b'\'' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        match b {
            b'\'' => in_str = true,
            b'(' => depth += 1,
            b')' => depth -= 1,
            _ => {}
        }
        if depth == 0 && matches_token(bytes, i, b" and ") {
            out.push(src[start..i].trim());
            i += b" and ".len();
            start = i;
            continue;
        }
        i += 1;
    }
    let tail = src[start..].trim();
    if !tail.is_empty() {
        out.push(tail);
    }
    out
}

/// All rendered forms the backend may emit for one upstream macro clause.
///
/// Always includes the verbatim upstream form. For an equality clause
/// (`field = 'literal'`) it adds the case-insensitive default
/// (`field ~= 'literal'`). For an inequality clause (`field != value`) it
/// adds the De Morgan negated equalities the `add_condition` pipeline
/// produces: `not (field = value)` always, and `not (field ~= value)` when
/// the right-hand side is a quoted literal or another field. A numeric or
/// boolean right-hand side stays on `=`.
fn accepted_clause_forms(clause: &str) -> Vec<String> {
    let clause = clause.trim();
    let mut forms = vec![clause.to_string()];
    let ci = to_ci_eq(clause);
    if ci != clause {
        forms.push(ci);
    }
    if let Some((lhs, rhs)) = split_top_level_neq(clause) {
        let lhs = lhs.trim();
        let rhs = rhs.trim();
        forms.push(format!("not ({lhs} = {rhs})"));
        if rhs.starts_with('\'') || is_field_operand(rhs) {
            forms.push(format!("not ({lhs} ~= {rhs})"));
        }
    }
    forms
}

/// Split a clause on its first top-level ` != ` operator, returning
/// `(lhs, rhs)`. Respects parenthesis and single-quoted-string nesting so
/// a `!=` inside a literal or a group is not treated as the operator.
fn split_top_level_neq(clause: &str) -> Option<(&str, &str)> {
    let bytes = clause.as_bytes();
    let mut depth = 0i32;
    let mut in_str = false;
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if in_str {
            if b == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if b == b'\'' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        match b {
            b'\'' => in_str = true,
            b'(' => depth += 1,
            b')' => depth -= 1,
            _ => {}
        }
        if depth == 0 && matches_token(bytes, i, b" != ") {
            return Some((&clause[..i], &clause[i + b" != ".len()..]));
        }
        i += 1;
    }
    None
}

/// Convert a cased-form clause (`field = 'literal'`) into the
/// default-form output (`field ~= 'literal'`) so the recognizer matches
/// both styles. `~=` is Fibratus's case-insensitive string-equality
/// operator and is what the backend emits for a non-`evt.name` literal
/// without `|cased`.
///
/// Only the ` = '<literal>'` shape is transformed. Numeric, boolean,
/// `!=`, regex, function-call, and list (`in (...)`) clauses are passed
/// through unchanged. Field-to-field `~=` is accepted from the inequality
/// path in [`accepted_clause_forms`], because a field reference renders
/// with `~=` unless the rule asks for case-sensitive comparison.
fn to_ci_eq(clause: &str) -> String {
    // Find a top-level ` = '` boundary; if none, return verbatim.
    let bytes = clause.as_bytes();
    let mut depth = 0i32;
    let mut in_str = false;
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if in_str {
            if b == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if b == b'\'' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        match b {
            b'\'' => in_str = true,
            b'(' => depth += 1,
            b')' => depth -= 1,
            _ => {}
        }
        if depth == 0 && matches_token(bytes, i, b" = '") {
            let mut out = String::with_capacity(clause.len() + 6);
            out.push_str(&clause[..i]);
            out.push_str(" ~= '");
            out.push_str(&clause[i + b" = '".len()..]);
            return out;
        }
        i += 1;
    }
    clause.to_string()
}

/// Whether `rhs` is another field rather than a number, boolean, or quote.
///
/// Field references render with `~=`. Numbers and booleans stay on `=`.
fn is_field_operand(rhs: &str) -> bool {
    let rhs = rhs.trim();
    let Some(first) = rhs.bytes().next() else {
        return false;
    };
    if first == b'\'' || first == b'"' || first.is_ascii_digit() || first == b'-' || first == b'+' {
        return false;
    }
    !rhs.eq_ignore_ascii_case("true") && !rhs.eq_ignore_ascii_case("false")
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_macro_lookup() {
        assert!(is_known_macro("spawn_process"));
        assert!(is_known_macro("create_thread"));
        assert!(is_known_macro("open_file"));
        // `create_file` (any creation disposition != OPEN) is the
        // canonical upstream file-creation macro.
        assert!(is_known_macro("create_file"));
        // Composite macros upstream defines on top of other macros
        // (`modify_registry`, `inbound_network`, `outbound_network`,
        // `load_driver`, ...) are deliberately absent from the
        // single-clause table; multi-step recognition can land them in
        // a follow-up.
        assert!(!is_known_macro("modify_registry"));
        assert!(!is_known_macro("not_a_macro"));
    }

    // -----------------------------------------------------------------
    // Single-clause recognition
    // -----------------------------------------------------------------

    #[test]
    fn recognize_spawn_process_case_insensitive_form() {
        // A non-`evt.name` literal would render `~=`; the recognizer
        // accepts that case-insensitive form for any clause.
        let out = recognize("evt.name ~= 'CreateProcess'");
        assert_eq!(out, "spawn_process");
    }

    #[test]
    fn recognize_spawn_process_cased_form() {
        // The backend renders `evt.name` with the exact `=` operator;
        // this is the form a real conversion emits.
        let out = recognize("evt.name = 'CreateProcess'");
        assert_eq!(out, "spawn_process");
    }

    #[test]
    fn recognize_spawn_process_with_extra_clauses() {
        let out = recognize(
            "evt.name = 'CreateProcess' and ps.exe iendswith '\\cmd.exe' and ps.cmdline icontains 'whoami'",
        );
        assert_eq!(
            out,
            "spawn_process and ps.exe iendswith '\\cmd.exe' and ps.cmdline icontains 'whoami'",
        );
    }

    #[test]
    fn recognize_write_file_and_read_file() {
        let out = recognize("evt.name = 'WriteFile' and file.path iendswith '\\out.log'");
        assert_eq!(out, "write_file and file.path iendswith '\\out.log'");
        let out2 = recognize("evt.name = 'ReadFile'");
        assert_eq!(out2, "read_file");
    }

    // -----------------------------------------------------------------
    // Multi-clause recognition (greedy longest match)
    // -----------------------------------------------------------------

    #[test]
    fn recognize_open_file_three_clauses() {
        // `evt.name` renders with `=`; the file.operation/file.status
        // literals render with the case-insensitive `~=`. The per-clause
        // matcher accepts the mix.
        let out = recognize(
            "evt.name = 'CreateFile' and file.operation ~= 'OPEN' and file.status ~= 'Success'",
        );
        assert_eq!(out, "open_file");
    }

    #[test]
    fn recognize_open_file_keeps_trailing_clauses() {
        let out = recognize(
            "evt.name = 'CreateFile' and file.operation ~= 'OPEN' and file.status ~= 'Success' and file.path iendswith '\\secret.txt'",
        );
        assert_eq!(out, "open_file and file.path iendswith '\\secret.txt'");
    }

    #[test]
    fn recognize_set_value_two_clauses() {
        let out = recognize(
            "evt.name = 'RegSetValue' and registry.status ~= 'Success' and registry.path icontains '\\Run\\'",
        );
        assert_eq!(out, "set_value and registry.path icontains '\\Run\\'",);
    }

    #[test]
    fn recognize_create_remote_thread_field_inequality() {
        let out = recognize(
            "evt.name = 'CreateThread' and not (evt.pid = 4) and not (evt.pid ~= thread.pid)",
        );
        assert_eq!(out, "create_remote_thread");
    }

    #[test]
    fn recognize_create_file_matches_inequality_disposition() {
        // The `create_file` macro keeps its `file.operation != 'OPEN'`
        // clause verbatim in both forms (`!=` is not transformed), and
        // its `=`-equality clauses match either operator form.
        let out = recognize(
            "evt.name = 'CreateFile' and file.operation != 'OPEN' and file.status ~= 'Success'",
        );
        assert_eq!(out, "create_file");
        // The OPEN disposition is the distinct `open_file` macro, not
        // `create_file`.
        let out2 = recognize(
            "evt.name = 'CreateFile' and file.operation ~= 'OPEN' and file.status ~= 'Success'",
        );
        assert_eq!(out2, "open_file");
    }

    #[test]
    fn recognize_create_file_from_negated_equality_disposition() {
        // The `add_condition` pipeline injects the OPEN-disposition guard
        // as a negated equality (`not (file.operation ~= 'OPEN')`), the
        // De Morgan equivalent of the macro's `file.operation != 'OPEN'`.
        // The recognizer accepts that form and still folds the run.
        let out = recognize(
            "evt.name = 'CreateFile' and not (file.operation ~= 'OPEN') and file.status ~= 'Success'",
        );
        assert_eq!(out, "create_file");
        // And it keeps trailing rule-body clauses verbatim.
        let out2 = recognize(
            "evt.name = 'CreateFile' and not (file.operation ~= 'OPEN') and file.status ~= 'Success' and file.path iendswith '.rdp'",
        );
        assert_eq!(out2, "create_file and file.path iendswith '.rdp'");
    }

    #[test]
    fn recognize_open_process_two_clauses_cased() {
        // Cased form: backend emitted with `-O case_sensitive=true`.
        let out = recognize("evt.name = 'OpenProcess' and ps.access.status = 'Success'");
        assert_eq!(out, "open_process");
    }

    // -----------------------------------------------------------------
    // No-false-positive cases
    // -----------------------------------------------------------------

    #[test]
    fn recognize_does_not_match_with_different_value() {
        // `evt.name = 'CreateThread'` is a macro (`create_thread`);
        // `'CreateProcess'` is a different macro (`spawn_process`).
        // `'TerminateProcess'` is neither, so it passes through.
        let out = recognize("evt.name = 'TerminateProcess'");
        assert_eq!(out, "evt.name = 'TerminateProcess'");
    }

    #[test]
    fn recognize_does_not_match_with_extra_modifier() {
        // `iendswith` is a partial-match operator; even on the same
        // field/value pair it must not match the equality-based macro.
        let out = recognize("evt.name iendswith 'CreateProcess'");
        assert_eq!(out, "evt.name iendswith 'CreateProcess'");
    }

    #[test]
    fn recognize_does_not_cross_or_groups() {
        // The OR group is one top-level clause; the inner contents
        // are parenthesized, so the splitter does not see them as
        // separate `and`s. `spawn_process` is therefore not inside.
        let out =
            recognize("(evt.name = 'CreateProcess' or evt.name = 'CreateThread') and ps.pid = 4");
        assert_eq!(
            out,
            "(evt.name = 'CreateProcess' or evt.name = 'CreateThread') and ps.pid = 4",
        );
    }

    #[test]
    fn recognize_picks_longest_match() {
        // Both `evt.name = 'CreateFile'` (no macro alone, but a prefix
        // of three) and the full `open_file` triple are available; the
        // greedy longest-match must produce `open_file`, not three bare
        // clauses.
        let out = recognize(
            "evt.name = 'CreateFile' and file.operation ~= 'OPEN' and file.status ~= 'Success'",
        );
        assert_eq!(out, "open_file");
        // Without the trailing two clauses the bare `evt.name = '...'`
        // is not itself a macro, so the input passes through.
        let out2 = recognize("evt.name = 'CreateFile'");
        assert_eq!(out2, "evt.name = 'CreateFile'");
    }

    #[test]
    fn recognize_passes_through_when_no_macro_matches() {
        let input = "ps.exe iendswith '\\cmd.exe' and ps.cmdline icontains 'whoami'";
        assert_eq!(recognize(input), input);
    }

    #[test]
    fn recognize_handles_empty_input() {
        assert_eq!(recognize(""), "");
    }

    // -----------------------------------------------------------------
    // Splitter sanity (respects parens and quotes)
    // -----------------------------------------------------------------

    #[test]
    fn split_keeps_paren_groups_intact() {
        let out = split_top_level_and("(a or b) and c and (d and e)");
        assert_eq!(out, vec!["(a or b)", "c", "(d and e)"]);
    }

    #[test]
    fn split_keeps_quoted_and_inside_strings() {
        let out = split_top_level_and("field = 'and inside string' and other");
        assert_eq!(out, vec!["field = 'and inside string'", "other"]);
    }

    #[test]
    fn to_ci_eq_substitutes_first_top_level_equality() {
        assert_eq!(
            to_ci_eq("evt.name = 'CreateProcess'"),
            "evt.name ~= 'CreateProcess'",
        );
    }

    #[test]
    fn to_ci_eq_leaves_inequality_alone() {
        // `evt.pid != 4` uses `!=`, not ` = '`, so to_ci_eq passes it
        // through unchanged. `file.operation != 'OPEN'` (the create_file
        // middle clause) is likewise untouched.
        assert_eq!(to_ci_eq("evt.pid != 4"), "evt.pid != 4");
        assert_eq!(
            to_ci_eq("file.operation != 'OPEN'"),
            "file.operation != 'OPEN'",
        );
    }
}
