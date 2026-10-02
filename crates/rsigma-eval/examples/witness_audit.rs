//! Static corpus witness audit (performance baseline, Phase 0).
//!
//! Answers the go/no-go question for witness-based candidate indexing: what
//! fraction of a real rule corpus carries a *sound required-positive witness*,
//! and what candidate rate would a witness index produce on representative
//! event lanes?
//!
//! A witness set for a rule is an OR-set of conditions such that **if the rule
//! matches an event, at least one witness must hold** (a necessary condition,
//! never a sufficient one). Witnesses are extracted from the lowered HIR:
//!
//! - exact field values, `contains`/`startswith`/`endswith` literals,
//!   mandatory wildcard literal segments, fieldless keyword literals,
//!   mandatory regex literals (via `regex-syntax`), decoded `base64`/
//!   `base64offset`/`wide` literals, dash-invariant `windash` segments,
//!   numeric equality values, and field presence.
//! - negations, `null`, `exists: false`, opaque regexes, unresolved
//!   placeholders, and vacuous array quantifiers stay **fail-open** (the rule
//!   must always be evaluated), exactly as a sound index would treat them.
//!
//! AND nodes need only one witnessed branch (the strongest is chosen); OR
//! nodes require every branch witnessed (the union is taken).
//!
//! The candidate simulation is a deliberate over-approximation (all string
//! witnesses degrade to case-folded substring search, presence checks are
//! case-folded), so reported candidate rates are an upper bound on what a
//! sound witness index would return.
//!
//! Usage:
//!   cargo run --release -p rsigma-eval --example witness_audit -- \
//!       <rules-dir> [--events <lane.ndjson>]... [--json]

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use aho_corasick::AhoCorasick;
use base64::Engine as _;
use rsigma_ir::{
    IrCondition, IrDetection, IrDetectionItem, IrEncoding, IrMatcher, IrNumber, IrPattern,
    IrPatternPart, IrRule, IrStrOp, LowerOptions, lower_rule,
};
use rsigma_parser::{ArrayQuantifier, Quantifier, parse_sigma_yaml};

// ---------------------------------------------------------------------------
// Witness model
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum WitnessKind {
    /// Exact field-value equality (strongest; today's index handles only this).
    ExactField,
    /// Anchored or unanchored substring on a specific field.
    Substring,
    /// Substring over any string value in the event (keywords, array scopes).
    Keyword,
    /// Mandatory literal extracted from a regex.
    RegexLiteral,
    /// Literal derived by replaying encoding modifiers (base64, wide, ...).
    Encoded,
    /// The field must be present for the rule to match (weakest).
    Presence,
}

#[derive(Clone, Debug)]
struct Witness {
    kind: WitnessKind,
    /// `None` means keyword scope (any string value in the event).
    field: Option<String>,
    /// Case-folded literal for string kinds; `None` for `Presence`.
    literal: Option<String>,
}

impl Witness {
    fn presence(field: &str) -> Self {
        Witness {
            kind: WitnessKind::Presence,
            field: Some(field.to_string()),
            literal: None,
        }
    }

    fn is_string(&self) -> bool {
        self.literal.is_some()
    }
}

/// Result of analyzing a node: either a sound OR-set of witnesses, or
/// fail-open with the blocking reason.
#[derive(Clone, Debug)]
enum Analysis {
    Witnesses(Vec<Witness>),
    Open(&'static str),
}

use Analysis::{Open, Witnesses};

/// Strength of a witness set, used to pick the best branch under AND.
/// Higher is better: all-string sets beat sets containing presence
/// witnesses, longer minimum literals beat shorter, fewer witnesses beat
/// more.
fn score(ws: &[Witness]) -> (u8, usize, isize) {
    let all_string = ws.iter().all(Witness::is_string);
    let min_len = ws
        .iter()
        .filter_map(|w| w.literal.as_deref().map(str::len))
        .min()
        .unwrap_or(0);
    (u8::from(all_string), min_len, -(ws.len() as isize))
}

/// AND semantics: the rule matches only if every child matches, so any one
/// witnessed child is a sound necessary condition. Pick the strongest.
fn and_combine(children: impl IntoIterator<Item = Analysis>) -> Analysis {
    let mut best: Option<Vec<Witness>> = None;
    let mut reason = "empty-and";
    for child in children {
        match child {
            Witnesses(ws) => {
                if best.as_deref().is_none_or(|b| score(&ws) > score(b)) {
                    best = Some(ws);
                }
            }
            Open(r) => reason = r,
        }
    }
    match best {
        Some(ws) => Witnesses(ws),
        None => Open(reason),
    }
}

/// OR semantics: the rule can match through any child, so every child must be
/// witnessed; the union is the witness set.
fn or_combine(children: impl IntoIterator<Item = Analysis>) -> Analysis {
    let mut union: Vec<Witness> = Vec::new();
    for child in children {
        match child {
            Witnesses(ws) => union.extend(ws),
            Open(r) => return Open(r),
        }
    }
    if union.is_empty() {
        Open("empty-or")
    } else {
        Witnesses(union)
    }
}

// ---------------------------------------------------------------------------
// HIR analysis
// ---------------------------------------------------------------------------

fn analyze_rule(rule: &IrRule) -> Analysis {
    if rule.conditions.is_empty() {
        return Open("no-condition");
    }
    // A rule with several conditions fires when any of them matches.
    or_combine(
        rule.conditions
            .iter()
            .map(|c| analyze_condition(c, &rule.detections)),
    )
}

fn analyze_condition(cond: &IrCondition, dets: &HashMap<String, IrDetection>) -> Analysis {
    match cond {
        IrCondition::Detection(name) => match dets.get(name) {
            Some(det) => analyze_detection(det),
            None => Open("unknown-detection"),
        },
        IrCondition::And(children) => {
            and_combine(children.iter().map(|c| analyze_condition(c, dets)))
        }
        IrCondition::Or(children) => {
            or_combine(children.iter().map(|c| analyze_condition(c, dets)))
        }
        IrCondition::Not(_) => Open("negation"),
        IrCondition::Selector {
            quantifier,
            pattern,
        } => {
            let resolved: Vec<&IrDetection> = dets
                .iter()
                .filter(|(name, _)| pattern.matches_detection_name(name))
                .map(|(_, det)| det)
                .collect();
            if resolved.is_empty() {
                return Open("empty-selector");
            }
            match quantifier {
                Quantifier::All => and_combine(resolved.into_iter().map(analyze_detection)),
                Quantifier::Any => or_combine(resolved.into_iter().map(analyze_detection)),
                Quantifier::Count(n) if *n >= 1 => {
                    or_combine(resolved.into_iter().map(analyze_detection))
                }
                Quantifier::Count(_) => Open("count-zero"),
            }
        }
    }
}

fn analyze_detection(det: &IrDetection) -> Analysis {
    match det {
        IrDetection::AllOf(items) => and_combine(items.iter().map(analyze_item)),
        IrDetection::AnyOf(subs) => or_combine(subs.iter().map(analyze_detection)),
        IrDetection::Keywords(matcher) => analyze_matcher(matcher, None),
        IrDetection::And(subs) => and_combine(subs.iter().map(analyze_detection)),
        IrDetection::Conditional { named, condition } => analyze_condition(condition, named),
        IrDetection::ArrayMatch {
            field,
            quantifier,
            body,
        } => match quantifier {
            // At least one member matches the body, so the member's witness
            // literal appears somewhere in the event; degrade field-scoped
            // string witnesses to keyword scope. Presence witnesses on member
            // sub-fields are not top-level keys, so they cannot survive; fall
            // back to presence of the array field itself (a non-empty match
            // requires it).
            ArrayQuantifier::Any => match keywordize(analyze_detection(body)) {
                Witnesses(ws) => Witnesses(ws),
                Open(_) => Witnesses(vec![Witness::presence(field)]),
            },
            // Every member matches and the array must be non-empty: the array
            // field must exist.
            ArrayQuantifier::All => Witnesses(vec![Witness::presence(field)]),
            // Vacuously true on empty/missing arrays: no sound witness.
            ArrayQuantifier::AllOrEmpty | ArrayQuantifier::None => Open("array-vacuous"),
        },
    }
}

/// Degrade field-scoped string witnesses to keyword scope; drop presence
/// witnesses (their fields are member-relative, not top-level keys).
fn keywordize(analysis: Analysis) -> Analysis {
    match analysis {
        Open(r) => Open(r),
        Witnesses(ws) => {
            let kw: Vec<Witness> = ws
                .into_iter()
                .filter(|w| w.is_string())
                .map(|w| Witness {
                    kind: WitnessKind::Keyword,
                    field: None,
                    literal: w.literal,
                })
                .collect();
            if kw.is_empty() {
                Open("array-presence-only")
            } else {
                Witnesses(kw)
            }
        }
    }
}

fn analyze_item(item: &IrDetectionItem) -> Analysis {
    if item.exists == Some(false) {
        return Open("exists-false");
    }
    let base = analyze_matcher(&item.matcher, item.field.as_deref());
    match (&base, &item.field) {
        // A positive matcher on a field cannot match a missing field, so
        // field presence is a sound fallback witness.
        (Open(_), Some(field))
            if item.exists == Some(true) || matcher_requires_presence(&item.matcher) =>
        {
            Witnesses(vec![Witness::presence(field)])
        }
        _ => base,
    }
}

/// Whether a matcher can only match when the field is present.
fn matcher_requires_presence(matcher: &IrMatcher) -> bool {
    match matcher {
        IrMatcher::Not(_) | IrMatcher::Null | IrMatcher::Exists(false) => false,
        IrMatcher::AnyOf(children) => children.iter().all(matcher_requires_presence),
        IrMatcher::AllOf(children) => children.iter().any(matcher_requires_presence),
        IrMatcher::TimestampPart { inner, .. } => matcher_requires_presence(inner),
        _ => true,
    }
}

fn analyze_matcher(matcher: &IrMatcher, field: Option<&str>) -> Analysis {
    match matcher {
        IrMatcher::Str { op, pattern, .. } => analyze_str(*op, pattern, field),
        IrMatcher::Encoded {
            encodings,
            op: _,
            pattern,
            ..
        } => match pattern.as_plain() {
            Some(value) => encoded_witness(encodings, &value, field),
            None => Open("encoded-wildcard"),
        },
        IrMatcher::Regex { pattern, .. } => match regex_mandatory_literals(pattern) {
            Some(lits) => Witnesses(
                lits.into_iter()
                    .map(|l| Witness {
                        kind: WitnessKind::RegexLiteral,
                        field: field.map(str::to_string),
                        literal: Some(l.to_lowercase()),
                    })
                    .collect(),
            ),
            None => Open("regex-opaque"),
        },
        IrMatcher::NumericEq(IrNumber::Literal(n)) => Witnesses(vec![Witness {
            kind: WitnessKind::ExactField,
            field: field.map(str::to_string),
            literal: Some(format_number(*n)),
        }]),
        IrMatcher::NumericEq(IrNumber::DynamicSourceRef { .. }) => Open("dynamic-source"),
        IrMatcher::NumericGt(_)
        | IrMatcher::NumericGte(_)
        | IrMatcher::NumericLt(_)
        | IrMatcher::NumericLte(_) => Open("numeric-range"),
        IrMatcher::BoolEq(b) => Witnesses(vec![Witness {
            kind: WitnessKind::ExactField,
            field: field.map(str::to_string),
            literal: Some(b.to_string()),
        }]),
        IrMatcher::Exists(true) => match field {
            Some(f) => Witnesses(vec![Witness::presence(f)]),
            None => Open("exists-no-field"),
        },
        IrMatcher::Exists(false) => Open("exists-false"),
        IrMatcher::Cidr { .. } => Open("cidr"),
        IrMatcher::FieldRef { .. } => Open("fieldref"),
        IrMatcher::Null => Open("null"),
        IrMatcher::Expand { .. } => Open("placeholder"),
        IrMatcher::TimestampPart { .. } => Open("timestamp-part"),
        IrMatcher::Not(_) => Open("negation"),
        IrMatcher::AnyOf(children) => {
            or_combine(children.iter().map(|m| analyze_matcher(m, field)))
        }
        IrMatcher::AllOf(children) => {
            and_combine(children.iter().map(|m| analyze_matcher(m, field)))
        }
    }
}

fn analyze_str(op: IrStrOp, pattern: &IrPattern, field: Option<&str>) -> Analysis {
    if let Some(lit) = pattern.as_plain() {
        if lit.is_empty() {
            return Open("empty-literal");
        }
        let kind = match (field, op) {
            (None, _) => WitnessKind::Keyword,
            (Some(_), IrStrOp::Exact) => WitnessKind::ExactField,
            (Some(_), _) => WitnessKind::Substring,
        };
        return Witnesses(vec![Witness {
            kind,
            field: field.map(str::to_string),
            literal: Some(lit.to_lowercase()),
        }]);
    }
    // Wildcard pattern: every literal part must appear (in order), so the
    // longest part is a mandatory substring.
    let longest = pattern
        .parts
        .iter()
        .filter_map(|p| match p {
            IrPatternPart::Literal(l) => Some(l.as_str()),
            _ => None,
        })
        .max_by_key(|l| l.len())
        .unwrap_or("");
    if longest.is_empty() {
        return Open("wildcard-only");
    }
    Witnesses(vec![Witness {
        kind: if field.is_some() {
            WitnessKind::Substring
        } else {
            WitnessKind::Keyword
        },
        field: field.map(str::to_string),
        literal: Some(longest.to_lowercase()),
    }])
}

fn format_number(n: f64) -> String {
    if n.fract() == 0.0 && n.abs() < 1e15 {
        format!("{}", n as i64)
    } else {
        n.to_string()
    }
}

// ---------------------------------------------------------------------------
// Encoding replay (base64 / base64offset / wide / windash)
// ---------------------------------------------------------------------------

fn encoded_witness(encodings: &[IrEncoding], value: &str, field: Option<&str>) -> Analysis {
    if encodings.contains(&IrEncoding::Windash) {
        if encodings.len() > 1 {
            return Open("encoded-combo");
        }
        // Windash varies dash characters; the longest dash-free segment is
        // invariant across all variants.
        let seg = value
            .split(['-', '/', '\u{2013}', '\u{2014}', '\u{2015}'])
            .max_by_key(|s| s.len())
            .unwrap_or("");
        if seg.len() < 3 {
            return Open("windash-short");
        }
        return Witnesses(vec![Witness {
            kind: WitnessKind::Encoded,
            field: field.map(str::to_string),
            literal: Some(seg.to_lowercase()),
        }]);
    }

    let mut variants: Vec<Vec<u8>> = vec![value.as_bytes().to_vec()];
    for enc in encodings {
        match enc {
            IrEncoding::Wide | IrEncoding::Utf16 => {
                variants = variants
                    .iter()
                    .map(|v| v.iter().flat_map(|&b| [b, 0]).collect())
                    .collect();
            }
            IrEncoding::Utf16Be => {
                variants = variants
                    .iter()
                    .map(|v| v.iter().flat_map(|&b| [0, b]).collect())
                    .collect();
            }
            IrEncoding::Base64 => {
                variants = variants
                    .iter()
                    .map(|v| {
                        base64::engine::general_purpose::STANDARD_NO_PAD
                            .encode(v)
                            .into_bytes()
                    })
                    .collect();
            }
            IrEncoding::Base64Offset => {
                let mut next = Vec::new();
                for v in &variants {
                    for offset in 0usize..3 {
                        let mut padded = vec![0u8; offset];
                        padded.extend_from_slice(v);
                        let mut s =
                            base64::engine::general_purpose::STANDARD_NO_PAD.encode(&padded);
                        // Drop the leading chars influenced by the pad bytes
                        // and the trailing char influenced by what follows.
                        let lead = [0, 2, 3][offset];
                        if padded.len() % 3 != 0 && !s.is_empty() {
                            s.truncate(s.len() - 1);
                        }
                        let trimmed: String = s.chars().skip(lead).collect();
                        next.push(trimmed.into_bytes());
                    }
                }
                variants = next;
            }
            IrEncoding::Windash => unreachable!("handled above"),
        }
    }

    let mut lits = Vec::new();
    for v in variants {
        match String::from_utf8(v) {
            Ok(s) if s.len() >= 4 => lits.push(s),
            _ => return Open("encoded-binary"),
        }
    }
    if lits.is_empty() {
        return Open("encoded-empty");
    }
    Witnesses(
        lits.into_iter()
            .map(|l| Witness {
                kind: WitnessKind::Encoded,
                field: field.map(str::to_string),
                literal: Some(l.to_lowercase()),
            })
            .collect(),
    )
}

// ---------------------------------------------------------------------------
// Regex mandatory-literal extraction
// ---------------------------------------------------------------------------

/// Extract a sound OR-set of mandatory literals from a regex: if the regex
/// matches, at least one returned literal appears in the haystack. `None`
/// means no sound extraction exists (fail-open).
fn regex_mandatory_literals(pattern: &str) -> Option<Vec<String>> {
    let hir = regex_syntax::ParserBuilder::new()
        .utf8(false)
        .build()
        .parse(pattern)
        .ok()?;
    let lits = hir_mandatory_literals(&hir)?;
    // Tiny literals (single chars) are sound but useless; treat as opaque.
    if lits.iter().any(|l| l.len() < 2) {
        return None;
    }
    Some(lits)
}

fn hir_mandatory_literals(hir: &regex_syntax::hir::Hir) -> Option<Vec<String>> {
    use regex_syntax::hir::HirKind;
    match hir.kind() {
        HirKind::Literal(lit) => {
            let s = std::str::from_utf8(&lit.0).ok()?;
            if s.is_empty() {
                None
            } else {
                Some(vec![s.to_string()])
            }
        }
        HirKind::Concat(children) => {
            // AND: any child's mandatory set is mandatory; take the best
            // (longest minimum literal).
            children
                .iter()
                .filter_map(hir_mandatory_literals)
                .max_by_key(|lits| lits.iter().map(String::len).min().unwrap_or(0))
        }
        HirKind::Alternation(children) => {
            // OR: every branch must contribute.
            let mut union = Vec::new();
            for child in children {
                union.extend(hir_mandatory_literals(child)?);
            }
            Some(union)
        }
        HirKind::Repetition(rep) if rep.min >= 1 => hir_mandatory_literals(&rep.sub),
        HirKind::Capture(cap) => hir_mandatory_literals(&cap.sub),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Current exact-only index policy (approximated at the HIR level)
// ---------------------------------------------------------------------------

/// Mirror of `RuleIndex::append_rule`: a rule is indexable only if every
/// named detection yields at least one field-scoped exact string pair.
fn indexable_under_current_policy(rule: &IrRule) -> bool {
    !rule.detections.is_empty() && rule.detections.values().all(detection_has_exact_pair)
}

fn detection_has_exact_pair(det: &IrDetection) -> bool {
    match det {
        IrDetection::AllOf(items) => items
            .iter()
            .any(|i| i.field.is_some() && matcher_has_exact_string(&i.matcher)),
        IrDetection::AnyOf(subs) | IrDetection::And(subs) => {
            subs.iter().any(detection_has_exact_pair)
        }
        IrDetection::ArrayMatch { .. }
        | IrDetection::Conditional { .. }
        | IrDetection::Keywords(_) => false,
    }
}

fn matcher_has_exact_string(matcher: &IrMatcher) -> bool {
    match matcher {
        IrMatcher::Str {
            op: IrStrOp::Exact,
            pattern,
            ..
        } => pattern.is_plain(),
        IrMatcher::AnyOf(children) | IrMatcher::AllOf(children) => {
            children.iter().any(matcher_has_exact_string)
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Corpus loading
// ---------------------------------------------------------------------------

struct RuleAudit {
    title: String,
    path: PathBuf,
    indexable_now: bool,
    analysis: Analysis,
}

fn walk_rules(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            walk_rules(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "yml" || e == "yaml") {
            out.push(path);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Candidate-rate simulation
// ---------------------------------------------------------------------------

struct Simulator {
    ac: AhoCorasick,
    /// pattern id -> rule indices carrying that literal witness.
    literal_rules: Vec<Vec<u32>>,
    /// folded field name -> rule indices with a presence witness on it.
    presence_rules: HashMap<String, Vec<u32>>,
    /// rules that are always candidates.
    fail_open: Vec<u32>,
    rule_count: usize,
}

impl Simulator {
    fn build(audits: &[RuleAudit]) -> Self {
        let mut literal_ids: HashMap<String, usize> = HashMap::new();
        let mut patterns: Vec<String> = Vec::new();
        let mut literal_rules: Vec<Vec<u32>> = Vec::new();
        let mut presence_rules: HashMap<String, Vec<u32>> = HashMap::new();
        let mut fail_open = Vec::new();

        for (idx, audit) in audits.iter().enumerate() {
            let idx = idx as u32;
            match &audit.analysis {
                Open(_) => fail_open.push(idx),
                Witnesses(ws) => {
                    for w in ws {
                        match &w.literal {
                            Some(lit) => {
                                let id = *literal_ids.entry(lit.clone()).or_insert_with(|| {
                                    patterns.push(lit.clone());
                                    literal_rules.push(Vec::new());
                                    patterns.len() - 1
                                });
                                if literal_rules[id].last() != Some(&idx) {
                                    literal_rules[id].push(idx);
                                }
                            }
                            None => {
                                let field = w.field.clone().unwrap_or_default().to_lowercase();
                                let bucket = presence_rules.entry(field).or_default();
                                if bucket.last() != Some(&idx) {
                                    bucket.push(idx);
                                }
                            }
                        }
                    }
                }
            }
        }

        Simulator {
            ac: AhoCorasick::new(&patterns).expect("witness literal automaton"),
            literal_rules,
            presence_rules,
            fail_open,
            rule_count: audits.len(),
        }
    }

    /// Candidate count for one event.
    fn candidates(&self, event: &serde_json::Value) -> usize {
        let mut haystack = String::new();
        let mut keys: HashSet<String> = HashSet::new();
        flatten(event, "", &mut haystack, &mut keys);

        let mut marked = vec![false; self.rule_count];
        let mut count = 0usize;
        let mark = |idx: u32, marked: &mut Vec<bool>, count: &mut usize| {
            let i = idx as usize;
            if !marked[i] {
                marked[i] = true;
                *count += 1;
            }
        };

        for m in self.ac.find_overlapping_iter(&haystack) {
            for &idx in &self.literal_rules[m.pattern().as_usize()] {
                mark(idx, &mut marked, &mut count);
            }
        }
        for key in &keys {
            if let Some(bucket) = self.presence_rules.get(key) {
                for &idx in bucket {
                    mark(idx, &mut marked, &mut count);
                }
            }
        }
        for &idx in &self.fail_open {
            mark(idx, &mut marked, &mut count);
        }
        count
    }
}

/// Case-fold every string/number/bool value into one separator-joined
/// haystack and collect case-folded dotted field keys.
fn flatten(
    value: &serde_json::Value,
    prefix: &str,
    haystack: &mut String,
    keys: &mut HashSet<String>,
) {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                let dotted = if prefix.is_empty() {
                    k.to_lowercase()
                } else {
                    format!("{prefix}.{}", k.to_lowercase())
                };
                keys.insert(dotted.clone());
                flatten(v, &dotted, haystack, keys);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                flatten(item, prefix, haystack, keys);
            }
        }
        serde_json::Value::String(s) => {
            haystack.push('\u{1}');
            haystack.push_str(&s.to_lowercase());
        }
        serde_json::Value::Number(n) => {
            haystack.push('\u{1}');
            let _ = write!(haystack, "{n}");
        }
        serde_json::Value::Bool(b) => {
            haystack.push('\u{1}');
            let _ = write!(haystack, "{b}");
        }
        serde_json::Value::Null => {}
    }
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

fn percentile(sorted: &[usize], p: f64) -> usize {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx]
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut rules_dir: Option<PathBuf> = None;
    let mut event_lanes: Vec<PathBuf> = Vec::new();
    let mut json_output = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--events" => {
                i += 1;
                event_lanes.push(PathBuf::from(&args[i]));
            }
            "--json" => json_output = true,
            arg => rules_dir = Some(PathBuf::from(arg)),
        }
        i += 1;
    }
    let Some(rules_dir) = rules_dir else {
        eprintln!("usage: witness_audit <rules-dir> [--events <lane.ndjson>]... [--json]");
        std::process::exit(2);
    };

    let mut files = Vec::new();
    walk_rules(&rules_dir, &mut files).expect("walk rules dir");
    files.sort();

    let mut audits: Vec<RuleAudit> = Vec::new();
    let mut parse_errors = 0usize;
    let mut lower_errors = 0usize;

    for path in &files {
        let Ok(text) = fs::read_to_string(path) else {
            parse_errors += 1;
            continue;
        };
        let collection = match parse_sigma_yaml(&text) {
            Ok(c) => c,
            Err(_) => {
                parse_errors += 1;
                continue;
            }
        };
        for rule in &collection.rules {
            match lower_rule(rule, &LowerOptions::default()) {
                Ok(ir) => audits.push(RuleAudit {
                    title: rule.title.clone(),
                    path: path.clone(),
                    indexable_now: indexable_under_current_policy(&ir),
                    analysis: analyze_rule(&ir),
                }),
                Err(_) => lower_errors += 1,
            }
        }
    }

    let total = audits.len();
    let indexable_now = audits.iter().filter(|a| a.indexable_now).count();

    // Classify each rule by its weakest witness (OR semantics: the weakest
    // link bounds the pruning power).
    let mut class_counts: HashMap<&'static str, usize> = HashMap::new();
    let mut open_reasons: HashMap<&'static str, usize> = HashMap::new();
    let mut min_lit_lens: Vec<usize> = Vec::new();
    for audit in &audits {
        match &audit.analysis {
            Open(reason) => {
                *class_counts.entry("fail-open").or_default() += 1;
                *open_reasons.entry(reason).or_default() += 1;
            }
            Witnesses(ws) => {
                let class = if ws.iter().any(|w| w.kind == WitnessKind::Presence) {
                    "presence"
                } else if ws.iter().all(|w| w.kind == WitnessKind::ExactField) {
                    "exact"
                } else {
                    "substring"
                };
                *class_counts.entry(class).or_default() += 1;
                if class != "presence"
                    && let Some(len) = ws
                        .iter()
                        .filter_map(|w| w.literal.as_deref().map(str::len))
                        .min()
                {
                    min_lit_lens.push(len);
                }
            }
        }
    }

    let pct = |n: usize| 100.0 * n as f64 / total.max(1) as f64;

    println!("== Witness audit ==");
    println!("rule files:        {}", files.len());
    println!(
        "rules audited:     {total}  (parse errors: {parse_errors}, lower errors: {lower_errors})"
    );
    println!();
    println!("current exact-only index policy:");
    println!(
        "  indexable:       {indexable_now:>6}  ({:.1}%)",
        pct(indexable_now)
    );
    println!(
        "  always-evaluated:{:>6}  ({:.1}%)",
        total - indexable_now,
        pct(total - indexable_now)
    );
    println!();
    println!("witness classes (weakest witness in each rule's OR-set):");
    for class in ["exact", "substring", "presence", "fail-open"] {
        let n = class_counts.get(class).copied().unwrap_or(0);
        println!("  {class:<12} {n:>6}  ({:.1}%)", pct(n));
    }
    println!();
    if !open_reasons.is_empty() {
        let mut reasons: Vec<_> = open_reasons.into_iter().collect();
        reasons.sort_by_key(|&(_, n)| std::cmp::Reverse(n));
        println!("fail-open reasons:");
        for (reason, n) in &reasons {
            println!("  {reason:<20} {n:>6}");
        }
        println!();
    }
    if !min_lit_lens.is_empty() {
        let buckets = [(1usize, 2usize), (3, 4), (5, 8), (9, usize::MAX)];
        println!("minimum witness literal length (string-witness rules):");
        for (lo, hi) in buckets {
            let n = min_lit_lens.iter().filter(|&&l| l >= lo && l <= hi).count();
            let label = if hi == usize::MAX {
                format!("{lo}+")
            } else {
                format!("{lo}-{hi}")
            };
            println!("  {label:<6} {n:>6}");
        }
        println!();
    }

    if !event_lanes.is_empty() {
        let sim = Simulator::build(&audits);
        println!(
            "candidate-rate simulation (upper bound; substring over-approximation, {} fail-open rules always included):",
            sim.fail_open.len()
        );
        println!(
            "  {:<24} {:>8} {:>10} {:>10} {:>10} {:>10}",
            "lane", "events", "mean", "p50", "p95", "max"
        );
        for lane in &event_lanes {
            let Ok(text) = fs::read_to_string(lane) else {
                eprintln!("warning: cannot read {}", lane.display());
                continue;
            };
            let mut counts: Vec<usize> = Vec::new();
            for line in text.lines() {
                if line.trim().is_empty() {
                    continue;
                }
                if let Ok(event) = serde_json::from_str::<serde_json::Value>(line) {
                    counts.push(sim.candidates(&event));
                }
            }
            counts.sort_unstable();
            let mean = counts.iter().sum::<usize>() as f64 / counts.len().max(1) as f64;
            let name = lane
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            println!(
                "  {:<24} {:>8} {:>7.1} ({:>4.1}%) {:>6} {:>10} {:>10}",
                name,
                counts.len(),
                mean,
                100.0 * mean / total.max(1) as f64,
                percentile(&counts, 0.50),
                percentile(&counts, 0.95),
                counts.last().copied().unwrap_or(0),
            );
        }
        println!();
    }

    if json_output {
        let mut per_rule = Vec::new();
        for audit in &audits {
            let (class, witnesses): (&str, Vec<serde_json::Value>) = match &audit.analysis {
                Open(reason) => (reason, Vec::new()),
                Witnesses(ws) => (
                    "witnessed",
                    ws.iter()
                        .map(|w| {
                            serde_json::json!({
                                "kind": format!("{:?}", w.kind),
                                "field": w.field,
                                "literal": w.literal,
                            })
                        })
                        .collect(),
                ),
            };
            per_rule.push(serde_json::json!({
                "title": audit.title,
                "path": audit.path.display().to_string(),
                "indexable_now": audit.indexable_now,
                "class": class,
                "witnesses": witnesses,
            }));
        }
        println!("{}", serde_json::to_string_pretty(&per_rule).unwrap());
    }
}
