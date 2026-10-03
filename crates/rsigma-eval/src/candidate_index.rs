//! Witness-based candidate index for rule pre-filtering.
//!
//! At load time each rule is analyzed into an OR-set of [`Witness`]es:
//! necessary conditions, at least one of which holds on every event the rule
//! can match (see [`crate::witness`]). This module inverts that relation, so
//! an event's own shape selects the rules worth evaluating.
//!
//! Four lookup structures, one per witness kind:
//!
//! - **presence**: rules gated on a field merely existing, which is what
//!   keeps rules built from regexes, CIDR blocks, and numeric comparisons out
//!   of the always-evaluated set.
//! - **exact**: rules gated on a field's folded value, or one of its array
//!   members, equalling a literal.
//! - **substring**: one Aho-Corasick automaton per field over the needles
//!   that field's rules require.
//! - **keyword**: one automaton over the needles that field-less keyword
//!   detections require, matched against every string value in the event.
//!
//! Rules with no sound witness are always evaluated, partitioned by logsource
//! `product` so routing can skip the ones that conflict with an event.
//!
//! The index is an **over-approximation**: it may return rules that turn out
//! not to match, and never omits one that would. The differential tests in
//! `engine::diff_tests` hold that line against a full scan.

use std::borrow::Cow;

use ahash::{HashMap, HashMapExt};
use aho_corasick::{AhoCorasick, AhoCorasickKind, MatchKind};
use rsigma_parser::fieldpath::{first_unescaped, unescape_brackets};

use crate::compiler::CompiledRule;
use crate::event::{Event, EventValue};
use crate::matcher::ascii_lowercase_cow;
use crate::witness::{RuleWitness, Witness, analyze_rule};

/// Cap on the needles fed to a single automaton. Beyond this, the rules that
/// contributed them become always-evaluated rather than paying an unbounded
/// build cost; SigmaHQ's busiest field stays well under it.
const MAX_NEEDLES_PER_AUTOMATON: usize = 1 << 16;

/// Minimum rule count before an incremental append may trigger a rebuild, so
/// small rule sets are not rebuilt on every add.
const INCREMENTAL_REBUILD_FLOOR: usize = 64;

/// Everything the index knows about one event field.
#[derive(Default)]
struct FieldEntry {
    /// Rules gated on this field being present.
    presence: Vec<usize>,
    /// Folded literal to the rules gated on the field equalling it.
    exact: HashMap<String, Vec<usize>>,
    /// Substring needles required by this field's rules.
    needles: Option<NeedleSet>,
}

impl FieldEntry {
    /// Whether resolving this field's value can add anything, or only its
    /// presence matters.
    fn needs_value(&self) -> bool {
        !self.exact.is_empty() || self.needles.is_some()
    }
}

/// An Aho-Corasick automaton over a needle set, with each pattern's rules.
struct NeedleSet {
    automaton: AhoCorasick,
    pattern_to_rules: Vec<Vec<usize>>,
}

impl NeedleSet {
    /// Build an automaton over `needle_to_rules`. Returns `None` when the set
    /// is empty, too large, or the automaton fails to build; the caller then
    /// falls back to always-evaluating the rules involved.
    fn build(needle_to_rules: HashMap<String, Vec<usize>>) -> Option<Self> {
        if needle_to_rules.is_empty() || needle_to_rules.len() > MAX_NEEDLES_PER_AUTOMATON {
            return None;
        }

        // Sort so pattern ids, and therefore the whole structure, are
        // identical for identical inputs.
        let mut entries: Vec<(String, Vec<usize>)> = needle_to_rules.into_iter().collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));

        let mut patterns = Vec::with_capacity(entries.len());
        let mut pattern_to_rules = Vec::with_capacity(entries.len());
        for (needle, mut rules) in entries {
            rules.sort_unstable();
            rules.dedup();
            patterns.push(needle);
            pattern_to_rules.push(rules);
        }

        // `Standard` is the only match kind that supports overlapping
        // iteration, and overlapping is required: a needle wholly contained
        // in another must still select its own rules.
        //
        // Witness needles are stored folded. ASCII case-insensitive search
        // lets the hot path scan the original haystack without allocating a
        // lowercase copy; non-ASCII haystacks still fold once before search.
        // Prefer a DFA for the dense keyword/field automata; fall back if the
        // DFA is too large to build.
        let automaton = AhoCorasick::builder()
            .match_kind(MatchKind::Standard)
            .ascii_case_insensitive(true)
            .kind(Some(AhoCorasickKind::DFA))
            .build(&patterns)
            .ok()
            .or_else(|| {
                AhoCorasick::builder()
                    .match_kind(MatchKind::Standard)
                    .ascii_case_insensitive(true)
                    .build(&patterns)
                    .ok()
            })?;

        Some(NeedleSet {
            automaton,
            pattern_to_rules,
        })
    }

    /// Mark rules whose needles occur in `haystack`.
    ///
    /// ASCII haystacks are searched in place (automaton is ASCII
    /// case-insensitive). Non-ASCII haystacks are Unicode-folded once so
    /// already-folded Unicode needles still match.
    fn mark(&self, haystack: &str, out: &mut CandidateSet) {
        if haystack.is_ascii() {
            self.mark_haystack(haystack, out);
        } else {
            let folded = ascii_lowercase_cow(haystack);
            self.mark_haystack(folded.as_ref(), out);
        }
    }

    fn mark_haystack(&self, haystack: &str, out: &mut CandidateSet) {
        for m in self.automaton.find_overlapping_iter(haystack) {
            if let Some(rules) = self.pattern_to_rules.get(m.pattern().as_usize()) {
                out.extend(rules);
            }
        }
    }
}

/// Every rule referenced by a needle map, for the fallback path.
fn rules_of(needle_to_rules: &HashMap<String, Vec<usize>>) -> Vec<usize> {
    let mut out: Vec<usize> = needle_to_rules.values().flatten().copied().collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// Deduplicating accumulator for candidate rule indices.
struct CandidateSet {
    seen: Vec<bool>,
    out: Vec<usize>,
}

impl CandidateSet {
    fn new(rule_count: usize) -> Self {
        CandidateSet {
            seen: vec![false; rule_count],
            out: Vec::new(),
        }
    }

    fn extend(&mut self, rules: &[usize]) {
        for &idx in rules {
            if let Some(slot) = self.seen.get_mut(idx)
                && !*slot
            {
                *slot = true;
                self.out.push(idx);
            }
        }
    }

    /// Ascending rule order, which makes the engine's result order a function
    /// of the rule set alone rather than of hash iteration order.
    fn finish(mut self) -> Vec<usize> {
        self.out.sort_unstable();
        self.out
    }
}

/// Witness-based inverted index over compiled rules.
pub(crate) struct CandidateIndex {
    fields: HashMap<String, FieldEntry>,
    /// Event-facing top-level key → index field paths to probe.
    ///
    /// Keys are unescaped the way JSON object keys appear (`args[0]`), while
    /// values keep the witness spelling (`args\[0\]`, `actor.id`, …). Sparse
    /// events iterate their own keys and only touch these buckets.
    fields_for_event_key: HashMap<String, Vec<String>>,
    keyword: Option<NeedleSet>,
    /// Rules with no sound witness, always evaluated.
    always: Vec<usize>,
    /// `always` partitioned by the rule's lowercased logsource `product`
    /// (`None` for product-less rules), each bucket ascending.
    always_by_product: HashMap<Option<String>, Vec<usize>>,
    /// Rules appended since the last full build whose witnesses could not be
    /// folded into the existing automata. Treated as always-evaluated until
    /// the next rebuild clears them.
    pending: Vec<usize>,
    rule_count: usize,
    /// Rule count at the last full build, for the doubling rebuild watermark.
    rebuild_baseline: usize,
}

impl CandidateIndex {
    pub(crate) fn empty() -> Self {
        CandidateIndex {
            fields: HashMap::new(),
            fields_for_event_key: HashMap::new(),
            keyword: None,
            always: Vec::new(),
            always_by_product: HashMap::new(),
            pending: Vec::new(),
            rule_count: 0,
            rebuild_baseline: 0,
        }
    }

    /// Build an index over `rules`.
    pub(crate) fn build(rules: &[CompiledRule]) -> Self {
        let mut index = Self::empty();
        index.rule_count = rules.len();
        index.rebuild_baseline = rules.len();

        // Accumulate needles across all rules before building any automaton:
        // one automaton per field over the whole corpus, not per rule.
        let mut field_needles: HashMap<String, HashMap<String, Vec<usize>>> = HashMap::new();
        let mut keyword_needles: HashMap<String, Vec<usize>> = HashMap::new();

        for (rule_idx, rule) in rules.iter().enumerate() {
            match analyze_rule(rule) {
                RuleWitness::Open => index.mark_always(rule_idx, rule),
                RuleWitness::AnyOf(witnesses) => {
                    for witness in witnesses {
                        match witness {
                            Witness::Presence { field } => {
                                index.entry(field).presence.push(rule_idx);
                            }
                            Witness::Exact { field, value } => {
                                index
                                    .entry(field)
                                    .exact
                                    .entry(value)
                                    .or_default()
                                    .push(rule_idx);
                            }
                            Witness::Substring { field, needle } => {
                                field_needles
                                    .entry(field)
                                    .or_default()
                                    .entry(needle)
                                    .or_default()
                                    .push(rule_idx);
                            }
                            Witness::Keyword { needle } => {
                                keyword_needles.entry(needle).or_default().push(rule_idx);
                            }
                        }
                    }
                }
            }
        }

        for (field, needles) in field_needles {
            let orphans = rules_of(&needles);
            match NeedleSet::build(needles) {
                Some(set) => index.entry(field).needles = Some(set),
                // The needle set could not be indexed, so a rule that relies
                // on it has no complete gate left and must be evaluated
                // against every event.
                None => index.mark_all_always(&orphans, rules),
            }
        }

        let keyword_orphans = rules_of(&keyword_needles);
        index.keyword = NeedleSet::build(keyword_needles);
        if index.keyword.is_none() {
            index.mark_all_always(&keyword_orphans, rules);
        }

        index.sort_buckets();
        index
    }

    /// Fold a single newly appended rule into the index.
    ///
    /// Presence and exact witnesses go straight into their maps. A substring
    /// or keyword witness cannot be inserted into an already-built automaton,
    /// so the rule joins `pending` and is a candidate for every event until
    /// the next rebuild. [`should_rebuild`]'s doubling watermark bounds how
    /// long that lasts and keeps the amortized cost per added rule constant.
    ///
    /// Callers must append with strictly increasing `rule_idx` so the
    /// always-evaluated buckets stay ascending.
    ///
    /// [`should_rebuild`]: CandidateIndex::should_rebuild
    pub(crate) fn append_rule(&mut self, rule_idx: usize, rule: &CompiledRule) {
        if rule_idx + 1 > self.rule_count {
            self.rule_count = rule_idx + 1;
        }

        let RuleWitness::AnyOf(witnesses) = analyze_rule(rule) else {
            self.always.push(rule_idx);
            let product = rule.logsource.product.as_deref().map(str::to_lowercase);
            self.always_by_product
                .entry(product)
                .or_default()
                .push(rule_idx);
            return;
        };

        if witnesses
            .iter()
            .any(|w| matches!(w, Witness::Substring { .. } | Witness::Keyword { .. }))
        {
            self.pending.push(rule_idx);
            return;
        }

        for witness in witnesses {
            match witness {
                Witness::Presence { field } => self.entry(field).presence.push(rule_idx),
                Witness::Exact { field, value } => {
                    self.entry(field)
                        .exact
                        .entry(value)
                        .or_default()
                        .push(rule_idx);
                }
                // Excluded by the check above.
                Witness::Substring { .. } | Witness::Keyword { .. } => {}
            }
        }
    }

    /// Whether the engine should rebuild the index at the current rule count.
    ///
    /// True once the rule count has at least doubled since the last full
    /// build, with [`INCREMENTAL_REBUILD_FLOOR`] as a floor. Doubling keeps
    /// the amortized per-rule build cost constant while bounding how many
    /// rules sit in `pending`.
    pub(crate) fn should_rebuild(&self, rule_count: usize) -> bool {
        let threshold = self
            .rebuild_baseline
            .saturating_mul(2)
            .max(INCREMENTAL_REBUILD_FLOOR);
        rule_count >= threshold && rule_count > self.rebuild_baseline
    }

    fn entry(&mut self, field: String) -> &mut FieldEntry {
        // Register under the unescaped full path so a flat JSON key that
        // contains dots (`process.command_line`) still finds its witnesses,
        // and under the first path segment so nested objects (`process: {…}`)
        // do too. `get_field` itself tries flat then nested.
        let flat = unescape_brackets(&field).into_owned();
        push_probe_field(&mut self.fields_for_event_key, flat, &field);
        if let Some(root) = nested_root_key(&field) {
            push_probe_field(&mut self.fields_for_event_key, root.into_owned(), &field);
        } else if let Some(root) = positional_root_key(&field) {
            // `args[0]` / `args[-1]` need the `args` array present on the event.
            push_probe_field(&mut self.fields_for_event_key, root.into_owned(), &field);
        }
        self.fields.entry(field).or_default()
    }

    fn mark_always(&mut self, rule_idx: usize, rule: &CompiledRule) {
        self.always.push(rule_idx);
        let product = rule.logsource.product.as_deref().map(str::to_lowercase);
        self.always_by_product
            .entry(product)
            .or_default()
            .push(rule_idx);
    }

    fn mark_all_always(&mut self, rule_indices: &[usize], rules: &[CompiledRule]) {
        for &rule_idx in rule_indices {
            if let Some(rule) = rules.get(rule_idx) {
                self.mark_always(rule_idx, rule);
            }
        }
    }

    fn sort_buckets(&mut self) {
        for entry in self.fields.values_mut() {
            entry.presence.sort_unstable();
            entry.presence.dedup();
            for rules in entry.exact.values_mut() {
                rules.sort_unstable();
                rules.dedup();
            }
        }
        for bucket in self.fields_for_event_key.values_mut() {
            bucket.sort_unstable();
            bucket.dedup();
        }
        self.always.sort_unstable();
        self.always.dedup();
        for bucket in self.always_by_product.values_mut() {
            bucket.sort_unstable();
            bucket.dedup();
        }
    }

    /// Candidate rule indices for `event`, in ascending order.
    pub(crate) fn candidates(&self, event: &impl Event) -> Vec<usize> {
        let mut set = CandidateSet::new(self.rule_count);
        set.extend(&self.always);
        set.extend(&self.pending);
        self.collect_field_hits(event, &mut set);
        self.collect_keyword_hits(event, &mut set);
        set.finish()
    }

    /// Like [`candidates`], but skips always-evaluated rules whose logsource
    /// `product` conflicts with `event_product`.
    ///
    /// Only the always-evaluated set is partitioned. Witness hits are returned
    /// regardless of product; the caller applies the residual
    /// `logsource_compatible` filter, which drops conflicting hits and also
    /// enforces `service` and `category`.
    ///
    /// [`candidates`]: CandidateIndex::candidates
    pub(crate) fn candidates_with_logsource(
        &self,
        event: &impl Event,
        event_product: Option<&str>,
    ) -> Vec<usize> {
        let Some(product) = event_product.map(str::to_lowercase) else {
            return self.candidates(event);
        };

        let mut set = CandidateSet::new(self.rule_count);
        for bucket in [
            self.always_by_product.get(&None),
            self.always_by_product.get(&Some(product)),
        ]
        .into_iter()
        .flatten()
        {
            set.extend(bucket);
        }
        set.extend(&self.pending);
        self.collect_field_hits(event, &mut set);
        self.collect_keyword_hits(event, &mut set);
        set.finish()
    }

    fn collect_field_hits(&self, event: &impl Event, set: &mut CandidateSet) {
        // When the event can name its top-level keys, probe only fields under
        // those roots. On sparse payloads (e.g. raw Windows `message`+`product`)
        // this turns an O(indexed fields) miss storm into O(event keys).
        if event.visit_top_level_keys(&mut |key| {
            if let Some(fields) = self.fields_for_event_key.get(key) {
                for field in fields {
                    if let Some(entry) = self.fields.get(field) {
                        Self::apply_field_hit(event, field, entry, set);
                    }
                }
            }
        }) {
            return;
        }

        for (field, entry) in &self.fields {
            Self::apply_field_hit(event, field, entry, set);
        }
    }

    fn apply_field_hit(
        event: &impl Event,
        field: &str,
        entry: &FieldEntry,
        set: &mut CandidateSet,
    ) {
        let Some(value) = event.get_field(field) else {
            return;
        };
        set.extend(&entry.presence);

        if !entry.needs_value() {
            return;
        }

        let has_exact = !entry.exact.is_empty();
        let needles = entry.needles.as_ref();

        // Every string form the matchers would compare against: scalars
        // by their textual form, arrays member by member.
        for_each_projection(&value, &mut |projection| {
            if has_exact {
                // Exact maps are keyed by folded literals; fold once and
                // reuse the same bytes for substring marking.
                let folded = ascii_lowercase_cow(projection);
                if let Some(rules) = entry.exact.get(folded.as_ref()) {
                    set.extend(rules);
                }
                if let Some(needles) = needles {
                    needles.mark_haystack(folded.as_ref(), set);
                }
            } else if let Some(needles) = needles {
                // Substring-only: ASCII case-insensitive AC scans in place.
                needles.mark(projection, set);
            }
        });
    }

    fn collect_keyword_hits(&self, event: &impl Event, set: &mut CandidateSet) {
        let Some(keyword) = &self.keyword else {
            return;
        };
        event.visit_string_values(&mut |value| {
            keyword.mark(value, set);
        });
    }

    /// Number of always-evaluated rules an event with `event_product` skips.
    /// `O(1)`; zero when `event_product` is `None`.
    pub(crate) fn conflicting_unindexable_count(&self, event_product: Option<&str>) -> usize {
        let Some(product) = event_product.map(str::to_lowercase) else {
            return 0;
        };
        let none_len = self.always_by_product.get(&None).map_or(0, Vec::len);
        let match_len = self
            .always_by_product
            .get(&Some(product))
            .map_or(0, Vec::len);
        self.always.len() - none_len - match_len
    }

    #[cfg(test)]
    pub(crate) fn rule_count(&self) -> usize {
        self.rule_count
    }

    /// Number of rules that are candidates for every event.
    #[cfg(test)]
    pub(crate) fn always_count(&self) -> usize {
        let mut all: Vec<usize> = self.always.clone();
        all.extend(&self.pending);
        all.sort_unstable();
        all.dedup();
        all.len()
    }

    /// Number of distinct fields the index looks up.
    #[cfg(test)]
    pub(crate) fn indexed_field_count(&self) -> usize {
        self.fields.len()
    }
}

fn push_probe_field(map: &mut HashMap<String, Vec<String>>, key: String, field: &str) {
    let bucket = map.entry(key).or_default();
    if !bucket.iter().any(|f| f == field) {
        bucket.push(field.to_string());
    }
}

/// First nested-path segment of `field`, when it has an unescaped dot.
///
/// `actor.id` → `actor`. Flat keys (including `process.command_line` as a
/// single key, or `args\[0\]`) yield `None` here; callers register those via
/// the unescaped full field name instead.
fn nested_root_key(field: &str) -> Option<Cow<'_, str>> {
    let pos = first_unescaped(field, b'.').filter(|&p| p > 0)?;
    let segment = &field[..pos];
    let name = match first_unescaped(segment, b'[') {
        Some(p) if p > 0 => &segment[..p],
        _ => segment,
    };
    if name.is_empty() {
        return None;
    }
    Some(unescape_brackets(name))
}

/// Root array name for a positional path with no further dots (`args[-1]`).
///
/// Escaped-bracket literals (`args\[0\]`) have no unescaped `[` and yield
/// `None`, so they stay keyed only by their unescaped flat name.
fn positional_root_key(field: &str) -> Option<Cow<'_, str>> {
    if first_unescaped(field, b'.').is_some() {
        return None;
    }
    let pos = first_unescaped(field, b'[').filter(|&p| p > 0)?;
    Some(unescape_brackets(&field[..pos]))
}

/// Collect the string forms of an event value that a matcher would compare
/// against, mirroring the evaluator's own coercion: numbers and bools by
/// their textual form, arrays member by member, objects and nulls not at all.
fn for_each_projection(value: &EventValue<'_>, visit: &mut dyn FnMut(&str)) {
    match value {
        EventValue::Str(s) => visit(s.as_ref()),
        EventValue::Int(n) => visit(&n.to_string()),
        EventValue::Float(f) => visit(&f.to_string()),
        EventValue::Bool(b) => visit(if *b { "true" } else { "false" }),
        EventValue::Array(members) => {
            for member in members {
                for_each_projection(member, visit);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Engine;
    use crate::event::JsonEvent;
    use rsigma_parser::parse_sigma_yaml;
    use serde_json::json;

    fn build(yaml: &str) -> (Engine, CandidateIndex) {
        let collection = parse_sigma_yaml(yaml).unwrap();
        let mut engine = Engine::new();
        engine.add_collection(&collection).unwrap();
        let index = CandidateIndex::build(engine.rules());
        (engine, index)
    }

    fn candidates(index: &CandidateIndex, event: &serde_json::Value) -> Vec<usize> {
        index.candidates(&JsonEvent::borrow(event))
    }

    const EXACT_RULE: &str = r#"
title: Exact
logsource:
    product: windows
detection:
    selection:
        EventType: 'login'
    condition: selection
"#;

    #[test]
    fn exact_witness_selects_only_matching_events() {
        let (_, index) = build(EXACT_RULE);
        assert_eq!(index.rule_count(), 1);
        assert_eq!(index.always_count(), 0);
        assert_eq!(index.indexed_field_count(), 1);

        assert_eq!(candidates(&index, &json!({"EventType": "login"})), vec![0]);
        // Case-insensitive by default, so the folded value still hits.
        assert_eq!(candidates(&index, &json!({"EventType": "LOGIN"})), vec![0]);
        assert!(candidates(&index, &json!({"EventType": "logout"})).is_empty());
        assert!(candidates(&index, &json!({"Other": "login"})).is_empty());
    }

    #[test]
    fn nested_root_key_segments() {
        assert_eq!(nested_root_key("CommandLine"), None);
        assert_eq!(nested_root_key("actor.id").as_deref(), Some("actor"));
        assert_eq!(nested_root_key("name[0].x").as_deref(), Some("name"));
        assert_eq!(nested_root_key(r"args\[0\]"), None);
        assert_eq!(
            nested_root_key("process.command_line").as_deref(),
            Some("process")
        );
    }

    #[test]
    fn flat_dotted_json_key_is_selected() {
        let (_, index) = build(
            r#"
title: T
logsource:
    category: test
detection:
    selection:
        process.command_line|contains: 'whoami'
    condition: selection
"#,
        );
        assert_eq!(
            candidates(&index, &json!({"process.command_line": "cmd /c whoami"})),
            vec![0]
        );
        assert_eq!(
            candidates(
                &index,
                &json!({"process": {"command_line": "cmd /c whoami"}})
            ),
            vec![0]
        );
    }

    #[test]
    fn sparse_event_still_finds_nested_field_under_present_root() {
        let (_, index) = build(
            r#"
title: Nested
logsource:
    category: test
detection:
    selection:
        actor.id: 'user123'
    condition: selection
"#,
        );
        assert_eq!(
            candidates(&index, &json!({"actor": {"id": "user123"}, "noise": 1})),
            vec![0]
        );
        // Absent root must not select the rule even when another key looks similar.
        assert!(candidates(&index, &json!({"message": "actor.id=user123"})).is_empty());
    }

    /// The old exact-only index could not index a substring rule and evaluated
    /// it against every event. It is now gated on its needle.
    #[test]
    fn substring_rule_is_indexed_not_always_evaluated() {
        let (_, index) = build(
            r#"
title: Contains
logsource:
    category: test
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
"#,
        );
        assert_eq!(index.always_count(), 0);
        assert_eq!(
            candidates(&index, &json!({"CommandLine": "cmd /c WHOAMI"})),
            vec![0]
        );
        assert!(candidates(&index, &json!({"CommandLine": "cmd /c dir"})).is_empty());
    }

    #[test]
    fn keyword_rule_is_indexed_against_every_string_value() {
        let (_, index) = build(
            r#"
title: Keywords
logsource:
    category: test
detection:
    keywords:
        - 'vssadmin delete shadows'
    condition: keywords
"#,
        );
        assert_eq!(index.always_count(), 0);
        assert_eq!(
            candidates(&index, &json!({"anything": "VSSADMIN DELETE SHADOWS /all"})),
            vec![0]
        );
        // Nested values count, matching the keyword matcher's own traversal.
        assert_eq!(
            candidates(
                &index,
                &json!({"outer": {"inner": "vssadmin delete shadows"}})
            ),
            vec![0]
        );
        assert!(candidates(&index, &json!({"anything": "benign"})).is_empty());
    }

    /// Case matrix: index may over-approximate, but must never omit a rule the
    /// engine would match for ASCII upper/lower, `|cased`, and non-ASCII CI.
    #[test]
    fn case_folding_matrix_never_drops_true_matches() {
        let cases: &[(&str, &str, serde_json::Value, bool)] = &[
            (
                "ci-contains-upper",
                r#"
title: T
logsource:
    category: test
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
"#,
                json!({"CommandLine": "cmd /c WHOAMI"}),
                true,
            ),
            (
                "ci-contains-lower",
                r#"
title: T
logsource:
    category: test
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
"#,
                json!({"CommandLine": "cmd /c whoami"}),
                true,
            ),
            (
                "ci-contains-miss",
                r#"
title: T
logsource:
    category: test
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
"#,
                json!({"CommandLine": "cmd /c dir"}),
                false,
            ),
            (
                "cased-contains-exact",
                r#"
title: T
logsource:
    category: test
detection:
    selection:
        CommandLine|contains|cased: 'WhoAmi'
    condition: selection
"#,
                json!({"CommandLine": "prefix WhoAmi suffix"}),
                true,
            ),
            (
                "cased-contains-wrong-case",
                r#"
title: T
logsource:
    category: test
detection:
    selection:
        CommandLine|contains|cased: 'WhoAmi'
    condition: selection
"#,
                json!({"CommandLine": "prefix whoami suffix"}),
                false,
            ),
            (
                "ci-keyword-upper",
                r#"
title: T
logsource:
    category: test
detection:
    keywords:
        - 'mimikatz'
    condition: keywords
"#,
                json!({"payload": "MIMIKATZ.exe"}),
                true,
            ),
            (
                "ci-keyword-lower",
                r#"
title: T
logsource:
    category: test
detection:
    keywords:
        - 'mimikatz'
    condition: keywords
"#,
                json!({"payload": "mimikatz.exe"}),
                true,
            ),
            (
                "ci-unicode-contains",
                r#"
title: T
logsource:
    category: test
detection:
    selection:
        User|contains: 'Ärzte'
    condition: selection
"#,
                json!({"User": "gruppe Ärzte west"}),
                true,
            ),
            (
                "ci-unicode-contains-folded-haystack",
                r#"
title: T
logsource:
    category: test
detection:
    selection:
        User|contains: 'ärzte'
    condition: selection
"#,
                json!({"User": "gruppe ÄRZTE west"}),
                true,
            ),
            (
                "ci-exact-mixed-case",
                r#"
title: T
logsource:
    category: test
detection:
    selection:
        Image: 'Cmd.EXE'
    condition: selection
"#,
                json!({"Image": "cmd.exe"}),
                true,
            ),
            (
                "cased-exact-match",
                r#"
title: T
logsource:
    category: test
detection:
    selection:
        Image|cased: 'Cmd.exe'
    condition: selection
"#,
                json!({"Image": "Cmd.exe"}),
                true,
            ),
            (
                "cased-exact-wrong-case",
                r#"
title: T
logsource:
    category: test
detection:
    selection:
        Image|cased: 'Cmd.exe'
    condition: selection
"#,
                json!({"Image": "cmd.exe"}),
                false,
            ),
        ];

        for (name, yaml, event_json, expect_match) in cases {
            let (engine, index) = build(yaml);
            let event = JsonEvent::borrow(event_json);
            let matched = !engine.evaluate(&event).is_empty();
            assert_eq!(
                matched, *expect_match,
                "{name}: engine match expectation drifted"
            );
            let selected = index.candidates(&event);
            if matched {
                assert!(
                    selected.contains(&0),
                    "{name}: index dropped a true engine match; candidates={selected:?}"
                );
            }
        }
    }

    /// Matchers whose value space the index cannot enumerate still gate on
    /// their field being present, which is what keeps them off the
    /// always-evaluated list.
    #[test]
    fn opaque_matchers_are_gated_on_field_presence() {
        for detection in [
            "        CommandLine|re: '^.{200,}$'\n",
            "        DestinationIp|cidr: '10.0.0.0/8'\n",
            "        EventID|gte: 4000\n",
        ] {
            let yaml = format!(
                "title: T\nlogsource:\n    category: test\ndetection:\n    selection:\n{detection}    condition: selection\n"
            );
            let (_, index) = build(&yaml);
            assert_eq!(index.always_count(), 0, "for {detection}");
            assert!(
                candidates(&index, &json!({"Unrelated": "x"})).is_empty(),
                "an event without the field must not be a candidate for {detection}"
            );
        }

        let (_, index) = build(
            r#"
title: Cidr
logsource:
    category: test
detection:
    selection:
        DestinationIp|cidr: '10.0.0.0/8'
    condition: selection
"#,
        );
        assert_eq!(
            candidates(&index, &json!({"DestinationIp": "192.0.2.1"})),
            vec![0],
            "presence alone gates the rule; the matcher decides the rest"
        );
    }

    #[test]
    fn negated_condition_is_always_evaluated() {
        let (_, index) = build(
            r#"
title: Negated
logsource:
    category: test
detection:
    selection:
        Image: 'cmd.exe'
    filter:
        User: 'SYSTEM'
    condition: selection or not filter
"#,
        );
        assert_eq!(index.always_count(), 1);
        assert_eq!(candidates(&index, &json!({"Unrelated": "x"})), vec![0]);
    }

    #[test]
    fn or_over_detections_indexes_every_branch() {
        let (_, index) = build(
            r#"
title: Either
logsource:
    category: test
detection:
    selection:
        - Image|endswith: '\wmic.exe'
        - CommandLine|contains: 'process call create'
    condition: selection
"#,
        );
        assert_eq!(index.always_count(), 0);
        assert_eq!(
            candidates(&index, &json!({"Image": r"C:\a\wmic.exe"})),
            vec![0]
        );
        assert_eq!(
            candidates(&index, &json!({"CommandLine": "process call create"})),
            vec![0]
        );
        assert!(candidates(&index, &json!({"Image": r"C:\a\cmd.exe"})).is_empty());
    }

    #[test]
    fn numeric_and_array_event_values_are_projected_like_the_matcher() {
        let (_, index) = build(
            r#"
title: Numbers
logsource:
    category: test
detection:
    selection:
        EventID: 4688
    condition: selection
---
title: Arrays
logsource:
    category: test
detection:
    selection:
        Image|endswith: '\wmic.exe'
    condition: selection
"#,
        );
        // `EventID: 4688` compiles to a numeric matcher, so the rule is gated
        // on presence and any EventID value selects it.
        assert!(candidates(&index, &json!({"EventID": 4688})).contains(&0));
        assert!(candidates(&index, &json!({"EventID": "4688"})).contains(&0));
        // An array-valued field is projected member by member.
        assert!(candidates(&index, &json!({"Image": [r"C:\a\wmic.exe", "other"]})).contains(&1));
    }

    #[test]
    fn candidates_are_deduplicated_and_ascending() {
        let (_, index) = build(
            r#"
title: A
logsource:
    category: test
detection:
    selection:
        CommandLine|contains:
            - 'alpha'
            - 'beta'
    condition: selection
---
title: B
logsource:
    category: test
detection:
    selection:
        CommandLine|contains: 'alpha'
    condition: selection
---
title: C
logsource:
    category: test
detection:
    selection:
        Image: 'x'
    condition: selection
"#,
        );
        let got = candidates(&index, &json!({"CommandLine": "alpha beta", "Image": "x"}));
        assert_eq!(got, vec![0, 1, 2]);
    }

    #[test]
    fn empty_index_has_no_candidates() {
        let index = CandidateIndex::empty();
        assert!(candidates(&index, &json!({"any": "thing"})).is_empty());
    }

    /// Appending rules one at a time must select at least what a batched build
    /// selects. The incremental path parks automaton-backed rules in a
    /// conservative fallback, so it may select more.
    #[test]
    fn append_rule_never_selects_less_than_build() {
        let yaml = r#"
title: Exact
logsource:
    category: test
detection:
    selection:
        EventType: 'login'
    condition: selection
---
title: Contains
logsource:
    category: test
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
---
title: Keywords
logsource:
    category: test
detection:
    keywords:
        - 'mimikatz'
    condition: keywords
---
title: Negated
logsource:
    category: test
detection:
    selection:
        Image: 'cmd.exe'
    filter:
        User: 'SYSTEM'
    condition: selection and not filter
"#;
        let (engine, batched) = build(yaml);
        let mut incremental = CandidateIndex::empty();
        for (idx, rule) in engine.rules().iter().enumerate() {
            incremental.append_rule(idx, rule);
        }

        for event in [
            json!({}),
            json!({"EventType": "login"}),
            json!({"CommandLine": "whoami"}),
            json!({"note": "mimikatz"}),
            json!({"Image": "cmd.exe"}),
            json!({"unrelated": "value"}),
        ] {
            let batched_set = candidates(&batched, &event);
            let incremental_set = candidates(&incremental, &event);
            for idx in &batched_set {
                assert!(
                    incremental_set.contains(idx),
                    "incremental append dropped rule {idx} for {event}"
                );
            }
        }
    }

    #[test]
    fn rebuild_watermark_doubles_and_clears_pending() {
        let (engine, mut index) = build(EXACT_RULE);
        assert!(!index.should_rebuild(1));
        // Below the floor, no rebuild is worth it however much it grows.
        assert!(!index.should_rebuild(INCREMENTAL_REBUILD_FLOOR - 1));
        assert!(index.should_rebuild(INCREMENTAL_REBUILD_FLOOR));

        // A substring rule appended incrementally is conservatively always a
        // candidate until the rebuild folds it into an automaton.
        index.append_rule(1, &{
            let collection = parse_sigma_yaml(
                r#"
title: Contains
logsource:
    category: test
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
"#,
            )
            .unwrap();
            let mut e = Engine::new();
            e.add_collection(&collection).unwrap();
            e.rules()[0].clone()
        });
        assert!(candidates(&index, &json!({"unrelated": "x"})).contains(&1));
        let _ = engine;
    }

    #[test]
    fn always_evaluated_rules_are_partitioned_by_product() {
        let yaml = r#"
title: Windows Negated
logsource:
    product: windows
detection:
    selection:
        Image: 'cmd.exe'
    filter:
        User: 'SYSTEM'
    condition: selection or not filter
---
title: Linux Negated
logsource:
    product: linux
detection:
    selection:
        exe: 'bash'
    filter:
        user: 'root'
    condition: selection or not filter
---
title: Product Less Negated
logsource:
    category: test
detection:
    selection:
        a: 'b'
    filter:
        c: 'd'
    condition: selection or not filter
"#;
        let (_, index) = build(yaml);
        assert_eq!(index.always_count(), 3);

        let event = json!({"unrelated": "x"});
        // Every always-evaluated rule without a product filter.
        assert_eq!(candidates(&index, &event), vec![0, 1, 2]);

        // With a product, the conflicting bucket is never iterated.
        let windows = index.candidates_with_logsource(&JsonEvent::borrow(&event), Some("windows"));
        assert_eq!(windows, vec![0, 2]);
        assert_eq!(index.conflicting_unindexable_count(Some("windows")), 1);
        assert_eq!(index.conflicting_unindexable_count(Some("linux")), 1);
        assert_eq!(index.conflicting_unindexable_count(None), 0);
    }

    /// Product partitioning may only ever remove rules whose product actually
    /// conflicts.
    #[test]
    fn logsource_pruning_only_drops_conflicting_products() {
        let (engine, index) = build(
            r#"
title: Windows
logsource:
    product: windows
detection:
    selection:
        Image|contains: 'cmd'
    filter:
        User: 'SYSTEM'
    condition: selection or not filter
---
title: Linux
logsource:
    product: linux
detection:
    selection:
        exe|contains: 'sh'
    filter:
        user: 'root'
    condition: selection or not filter
"#,
        );
        let event = json!({"Image": r"C:\cmd.exe", "exe": "/bin/sh"});
        let all = candidates(&index, &event);
        let pruned = index.candidates_with_logsource(&JsonEvent::borrow(&event), Some("windows"));
        for idx in &all {
            if !pruned.contains(idx) {
                let product = engine.rules()[*idx].logsource.product.as_deref();
                assert_eq!(
                    product,
                    Some("linux"),
                    "rule {idx} was pruned without a conflicting product"
                );
            }
        }
    }

    #[test]
    fn literal_bracket_field_name_is_selected() {
        let (_, index) = build(
            r#"
title: T
logsource: { category: test }
detection:
    selection:
        args[0]: 'cmd.exe'
    condition: selection
"#,
        );
        assert!(
            index.fields.contains_key(r"args\[0\]"),
            "fields={:?}",
            index.fields.keys().collect::<Vec<_>>()
        );
        assert_eq!(
            index.fields_for_event_key.get("args[0]"),
            Some(&vec![r"args\[0\]".to_string()])
        );
        assert_eq!(candidates(&index, &json!({"args[0]": "cmd.exe"})), vec![0]);
    }
}
