//! Backend-neutral test backend modeled after pySigma's `TextQueryTestBackend`.
//!
//! Exercises most generic text backend features without targeting a specific SIEM.
//! Used to validate the `Backend` trait, `TextQueryConfig`, condition walker,
//! value escaping, modifier handling, and output formats.

use rsigma_eval::pipeline::state::PipelineState;
use rsigma_ir::{IrPattern, IrStrOp};
use rsigma_parser::*;

use crate::backend::*;
use crate::condition_ir::convert_rule_via_ir;
use crate::error::{ConvertError, Result};
use crate::state::{ConversionState, ConvertResult};

// =============================================================================
// TextQueryTestBackend config
// =============================================================================

pub static TEXT_QUERY_TEST_CONFIG: TextQueryConfig = TextQueryConfig {
    precedence: (TokenType::NOT, TokenType::AND, TokenType::OR),
    group_expression: "({expr})",
    token_separator: " ",

    and_token: "and",
    or_token: "or",
    not_token: "not",
    eq_token: "=",

    not_eq_token: Some("!="),
    eq_expression: None,
    not_eq_expression: None,
    convert_not_as_not_eq: false,

    wildcard_multi: "*",
    wildcard_single: "?",

    str_quote: "\"",
    str_quote_pattern: None,
    str_quote_pattern_negation: false,
    escape_char: "\\",
    add_escaped: &[":"],
    filter_chars: &["&"],

    field_quote: Some("'"),
    field_quote_pattern: Some(r"^\w+$"),
    field_quote_pattern_negation: true,
    field_escape: None,
    field_escape_pattern: None,

    startswith_expression: Some("{field} startswith {value}"),
    not_startswith_expression: None,
    startswith_expression_allow_special: false,
    endswith_expression: Some("{field} endswith {value}"),
    not_endswith_expression: None,
    endswith_expression_allow_special: false,
    contains_expression: Some("{field} contains {value}"),
    not_contains_expression: None,
    contains_expression_allow_special: false,
    wildcard_match_expression: Some("{field} match {value}"),

    case_sensitive_match_expression: Some("{field} casematch {value}"),
    case_sensitive_startswith_expression: Some("{field} startswith_cased {value}"),
    case_sensitive_endswith_expression: Some("{field} endswith_cased {value}"),
    case_sensitive_contains_expression: Some("{field} contains_cased {value}"),

    re_expression: Some("{field}=/{regex}/"),
    not_re_expression: None,
    re_escape_char: Some("\\"),
    re_escape: &["/"],
    re_escape_escape_char: None,

    cidr_expression: Some("cidrmatch(\"{value}\", {field})"),
    not_cidr_expression: None,

    field_null_expression: "{field} is null",
    field_exists_expression: Some("exists({field})"),
    field_not_exists_expression: Some("notexists({field})"),

    compare_op_expression: Some("{field}{op}{value}"),
    compare_ops: &[
        ("lt", "<"),
        ("lte", "<="),
        ("gt", ">"),
        ("gte", ">="),
        ("neq", "!="),
    ],

    convert_or_as_in: true,
    convert_and_as_in: true,
    in_expressions_allow_wildcards: true,
    field_in_list_expression: Some("{field} {op} ({list})"),
    or_in_operator: Some("in"),
    and_in_operator: Some("contains-all"),
    list_separator: ", ",

    unbound_value_str_expression: Some("_={value}"),
    unbound_value_num_expression: Some("_={value}"),
    unbound_value_re_expression: Some("_=/{value}/"),

    field_eq_field_expression: Some("{field1}=fieldref({field2})"),
    field_eq_field_escaping_quoting: true,

    deferred_start: Some(" | "),
    deferred_separator: Some(" | "),
    deferred_only_query: "*",

    bool_true: "1",
    bool_false: "0",
    query_expression: "{query}",
    state_defaults: &[],
};

// =============================================================================
// TextQueryTestBackend
// =============================================================================

pub struct TextQueryTestBackend {
    pub config: &'static TextQueryConfig,
}

impl TextQueryTestBackend {
    pub fn new() -> Self {
        Self {
            config: &TEXT_QUERY_TEST_CONFIG,
        }
    }
}

impl Default for TextQueryTestBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl Backend for TextQueryTestBackend {
    fn name(&self) -> &str {
        "test"
    }

    fn formats(&self) -> &[(&str, &str)] {
        &[
            ("default", "plain query list"),
            ("test", "wrapped query [ {query} ]"),
            ("state", "index={state.index} ({query})"),
            ("str", "newline-joined queries"),
        ]
    }

    fn requires_pipeline(&self) -> bool {
        false
    }

    // --- Detection rule conversion ---

    fn convert_rule(
        &self,
        rule: &SigmaRule,
        output_format: &str,
        pipeline_state: &PipelineState,
    ) -> Result<Vec<String>> {
        convert_rule_via_ir(self, rule, output_format, pipeline_state)
    }

    // --- Condition combinators ---

    fn convert_condition_and(&self, exprs: &[String]) -> Result<String> {
        Ok(text_convert_condition_and(self.config, exprs))
    }

    fn convert_condition_or(&self, exprs: &[String]) -> Result<String> {
        Ok(text_convert_condition_or(self.config, exprs))
    }

    fn convert_condition_not(&self, expr: &str) -> Result<String> {
        Ok(text_convert_condition_not(self.config, expr))
    }

    fn convert_condition_group(
        &self,
        expr: &str,
        outer: TokenType,
        inner: TokenType,
    ) -> Result<String> {
        Ok(text_convert_condition_group(
            self.config,
            expr,
            outer,
            inner,
        ))
    }

    // --- Field/value escaping ---

    fn escape_and_quote_field(&self, field: &str) -> String {
        text_escape_and_quote_field(self.config, field)
    }

    // --- Value-type-specific leaves (IR-native) ---

    fn convert_field_str(
        &self,
        field: &str,
        op: IrStrOp,
        pattern: &IrPattern,
        case_insensitive: bool,
        _state: &mut ConversionState,
    ) -> Result<ConvertResult> {
        text_convert_field_str_ir(self.config, field, op, pattern, case_insensitive)
    }

    fn convert_field_eq_num(
        &self,
        field: &str,
        value: f64,
        _state: &mut ConversionState,
    ) -> Result<String> {
        let f = text_escape_and_quote_field(self.config, field);
        if value.fract() == 0.0 {
            Ok(format!("{f}={}", value as i64))
        } else {
            Ok(format!("{f}={value}"))
        }
    }

    fn convert_field_eq_bool(
        &self,
        field: &str,
        value: bool,
        _state: &mut ConversionState,
    ) -> Result<String> {
        let f = text_escape_and_quote_field(self.config, field);
        let v = if value {
            self.config.bool_true
        } else {
            self.config.bool_false
        };
        Ok(format!("{f}={v}"))
    }

    fn convert_field_eq_null(&self, field: &str, _state: &mut ConversionState) -> Result<String> {
        let f = text_escape_and_quote_field(self.config, field);
        Ok(self.config.field_null_expression.replace("{field}", &f))
    }

    fn convert_field_regex(
        &self,
        field: &str,
        pattern: &str,
        _flags: RegexFlags,
        _state: &mut ConversionState,
    ) -> Result<ConvertResult> {
        let f = text_escape_and_quote_field(self.config, field);
        let re_val = text_convert_value_re(self.config, pattern);
        let expr = self
            .config
            .re_expression
            .ok_or_else(|| ConvertError::UnsupportedModifier("regex".into()))?;
        Ok(ConvertResult::Query(
            expr.replace("{field}", &f).replace("{regex}", &re_val),
        ))
    }

    fn convert_field_eq_cidr(
        &self,
        field: &str,
        cidr: &str,
        _state: &mut ConversionState,
    ) -> Result<ConvertResult> {
        let f = text_escape_and_quote_field(self.config, field);
        let expr = self
            .config
            .cidr_expression
            .ok_or_else(|| ConvertError::UnsupportedModifier("cidr".into()))?;
        Ok(ConvertResult::Query(
            expr.replace("{field}", &f).replace("{value}", cidr),
        ))
    }

    fn convert_field_compare_op(
        &self,
        field: &str,
        op: CompareOp,
        value: f64,
        _state: &mut ConversionState,
    ) -> Result<String> {
        let f = text_escape_and_quote_field(self.config, field);
        let op_name = match op {
            CompareOp::Lt => "lt",
            CompareOp::Lte => "lte",
            CompareOp::Gt => "gt",
            CompareOp::Gte => "gte",
        };
        let op_token = self
            .config
            .compare_ops
            .iter()
            .find(|(name, _)| *name == op_name)
            .map(|(_, token)| *token)
            .ok_or_else(|| ConvertError::UnsupportedModifier(op_name.into()))?;

        let expr = self
            .config
            .compare_op_expression
            .ok_or_else(|| ConvertError::UnsupportedModifier("compare".into()))?;

        let val_str = if value.fract() == 0.0 {
            (value as i64).to_string()
        } else {
            value.to_string()
        };
        Ok(expr
            .replace("{field}", &f)
            .replace("{op}", op_token)
            .replace("{value}", &val_str))
    }

    fn convert_field_exists(
        &self,
        field: &str,
        exists: bool,
        _state: &mut ConversionState,
    ) -> Result<String> {
        let f = text_escape_and_quote_field(self.config, field);
        if exists {
            let expr = self
                .config
                .field_exists_expression
                .ok_or_else(|| ConvertError::UnsupportedModifier("exists".into()))?;
            Ok(expr.replace("{field}", &f))
        } else {
            let expr = self
                .config
                .field_not_exists_expression
                .ok_or_else(|| ConvertError::UnsupportedModifier("not exists".into()))?;
            Ok(expr.replace("{field}", &f))
        }
    }

    fn convert_field_eq_query_expr(
        &self,
        field: &str,
        expr: &str,
        _id: &str,
        _state: &mut ConversionState,
    ) -> Result<String> {
        let f = text_escape_and_quote_field(self.config, field);
        Ok(format!("{f}={expr}"))
    }

    fn convert_field_ref(
        &self,
        field1: &str,
        field2: &str,
        op: IrStrOp,
        case_insensitive: bool,
        _state: &mut ConversionState,
    ) -> Result<ConvertResult> {
        if !case_insensitive {
            return Err(ConvertError::UnsupportedModifier(
                "cased field reference (fieldref|cased)".into(),
            ));
        }
        if !matches!(op, IrStrOp::Exact) {
            let f1 = text_escape_and_quote_field(self.config, field1);
            let f2 = text_escape_and_quote_field(self.config, field2);
            let token = match op {
                IrStrOp::Contains => "contains",
                IrStrOp::StartsWith => "startswith",
                IrStrOp::EndsWith => "endswith",
                IrStrOp::Exact => unreachable!("exact handled below"),
            };
            return Ok(ConvertResult::Query(format!("{f1} {token} {f2}")));
        }
        let expr = self
            .config
            .field_eq_field_expression
            .ok_or_else(|| ConvertError::UnsupportedModifier("fieldref".into()))?;
        let f1 = text_escape_and_quote_field(self.config, field1);
        let f2 = if self.config.field_eq_field_escaping_quoting {
            text_escape_and_quote_field(self.config, field2)
        } else {
            field2.to_string()
        };
        Ok(ConvertResult::Query(
            expr.replace("{field1}", &f1).replace("{field2}", &f2),
        ))
    }

    fn convert_keyword_str(
        &self,
        pattern: &IrPattern,
        _state: &mut ConversionState,
    ) -> Result<String> {
        let v = text_convert_ir_pattern(self.config, pattern);
        let expr = self
            .config
            .unbound_value_str_expression
            .ok_or(ConvertError::UnsupportedKeyword)?;
        Ok(expr.replace("{value}", &v))
    }

    fn convert_keyword_num(&self, value: f64, _state: &mut ConversionState) -> Result<String> {
        let expr = self
            .config
            .unbound_value_num_expression
            .ok_or(ConvertError::UnsupportedKeyword)?;
        let s = if value.fract() == 0.0 {
            (value as i64).to_string()
        } else {
            value.to_string()
        };
        Ok(expr.replace("{value}", &s))
    }

    // --- Query finalization ---

    fn finish_query(
        &self,
        rule: &SigmaRule,
        query: String,
        state: &ConversionState,
    ) -> Result<String> {
        Ok(text_finish_query(self.config, &query, state, rule))
    }

    fn finalize_query(
        &self,
        _rule: &SigmaRule,
        query: String,
        _index: usize,
        state: &ConversionState,
        output_format: &str,
    ) -> Result<String> {
        match output_format {
            "default" => Ok(query),
            "test" => Ok(format!("[ {query} ]")),
            "state" => {
                let index = state.get_state_str("index").unwrap_or("default_index");
                Ok(format!("index={index} ({query})"))
            }
            "str" => Ok(query),
            other => Err(ConvertError::RuleConversion(format!(
                "unknown output format: {other}"
            ))),
        }
    }

    fn finalize_output(&self, queries: Vec<String>, output_format: &str) -> Result<String> {
        match output_format {
            "str" => Ok(queries.join("\n")),
            _ => Ok(queries.join("\n")),
        }
    }
}

// =============================================================================
// MandatoryPipelineTestBackend
// =============================================================================

/// Variant that requires a pipeline (for testing the pipeline-required error path).
pub struct MandatoryPipelineTestBackend(TextQueryTestBackend);

impl MandatoryPipelineTestBackend {
    pub fn new() -> Self {
        Self(TextQueryTestBackend::new())
    }
}

impl Default for MandatoryPipelineTestBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl Backend for MandatoryPipelineTestBackend {
    fn name(&self) -> &str {
        "test_mandatory_pipeline"
    }

    fn formats(&self) -> &[(&str, &str)] {
        self.0.formats()
    }

    fn requires_pipeline(&self) -> bool {
        true
    }

    fn convert_rule(
        &self,
        rule: &SigmaRule,
        output_format: &str,
        pipeline_state: &PipelineState,
    ) -> Result<Vec<String>> {
        self.0.convert_rule(rule, output_format, pipeline_state)
    }

    fn convert_condition_and(&self, exprs: &[String]) -> Result<String> {
        self.0.convert_condition_and(exprs)
    }

    fn convert_condition_or(&self, exprs: &[String]) -> Result<String> {
        self.0.convert_condition_or(exprs)
    }

    fn convert_condition_not(&self, expr: &str) -> Result<String> {
        self.0.convert_condition_not(expr)
    }

    fn convert_condition_group(
        &self,
        expr: &str,
        outer: TokenType,
        inner: TokenType,
    ) -> Result<String> {
        self.0.convert_condition_group(expr, outer, inner)
    }

    fn escape_and_quote_field(&self, field: &str) -> String {
        self.0.escape_and_quote_field(field)
    }

    fn convert_field_str(
        &self,
        field: &str,
        op: IrStrOp,
        pattern: &IrPattern,
        case_insensitive: bool,
        state: &mut ConversionState,
    ) -> Result<ConvertResult> {
        self.0
            .convert_field_str(field, op, pattern, case_insensitive, state)
    }

    fn convert_field_eq_num(
        &self,
        field: &str,
        value: f64,
        state: &mut ConversionState,
    ) -> Result<String> {
        self.0.convert_field_eq_num(field, value, state)
    }

    fn convert_field_eq_bool(
        &self,
        field: &str,
        value: bool,
        state: &mut ConversionState,
    ) -> Result<String> {
        self.0.convert_field_eq_bool(field, value, state)
    }

    fn convert_field_eq_null(&self, field: &str, state: &mut ConversionState) -> Result<String> {
        self.0.convert_field_eq_null(field, state)
    }

    fn convert_field_regex(
        &self,
        field: &str,
        pattern: &str,
        flags: RegexFlags,
        state: &mut ConversionState,
    ) -> Result<ConvertResult> {
        self.0.convert_field_regex(field, pattern, flags, state)
    }

    fn convert_field_eq_cidr(
        &self,
        field: &str,
        cidr: &str,
        state: &mut ConversionState,
    ) -> Result<ConvertResult> {
        self.0.convert_field_eq_cidr(field, cidr, state)
    }

    fn convert_field_compare_op(
        &self,
        field: &str,
        op: CompareOp,
        value: f64,
        state: &mut ConversionState,
    ) -> Result<String> {
        self.0.convert_field_compare_op(field, op, value, state)
    }

    fn convert_field_exists(
        &self,
        field: &str,
        exists: bool,
        state: &mut ConversionState,
    ) -> Result<String> {
        self.0.convert_field_exists(field, exists, state)
    }

    fn convert_field_eq_query_expr(
        &self,
        field: &str,
        expr: &str,
        id: &str,
        state: &mut ConversionState,
    ) -> Result<String> {
        self.0.convert_field_eq_query_expr(field, expr, id, state)
    }

    fn convert_field_ref(
        &self,
        field1: &str,
        field2: &str,
        op: IrStrOp,
        case_insensitive: bool,
        state: &mut ConversionState,
    ) -> Result<ConvertResult> {
        self.0
            .convert_field_ref(field1, field2, op, case_insensitive, state)
    }

    fn convert_keyword_str(
        &self,
        pattern: &IrPattern,
        state: &mut ConversionState,
    ) -> Result<String> {
        self.0.convert_keyword_str(pattern, state)
    }

    fn convert_keyword_num(&self, value: f64, state: &mut ConversionState) -> Result<String> {
        self.0.convert_keyword_num(value, state)
    }

    fn finish_query(
        &self,
        rule: &SigmaRule,
        query: String,
        state: &ConversionState,
    ) -> Result<String> {
        self.0.finish_query(rule, query, state)
    }

    fn finalize_query(
        &self,
        rule: &SigmaRule,
        query: String,
        index: usize,
        state: &ConversionState,
        output_format: &str,
    ) -> Result<String> {
        self.0
            .finalize_query(rule, query, index, state, output_format)
    }

    fn finalize_output(&self, queries: Vec<String>, output_format: &str) -> Result<String> {
        self.0.finalize_output(queries, output_format)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rsigma_parser::parse_sigma_yaml;

    fn convert_rule_yaml(yaml: &str) -> Vec<String> {
        let collection = parse_sigma_yaml(yaml).unwrap();
        let backend = TextQueryTestBackend::new();
        let mut results = Vec::new();
        for rule in &collection.rules {
            let queries = backend
                .convert_rule(rule, "default", &PipelineState::default())
                .unwrap();
            results.extend(queries);
        }
        results
    }

    #[test]
    fn test_simple_eq() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        CommandLine: whoami
    condition: selection
"#,
        );
        assert_eq!(queries, vec!["CommandLine=\"whoami\""]);
    }

    #[test]
    fn test_and_condition() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    sel1:
        FieldA: val1
    sel2:
        FieldB: val2
    condition: sel1 and sel2
"#,
        );
        assert_eq!(queries, vec!["FieldA=\"val1\" and FieldB=\"val2\""]);
    }

    #[test]
    fn test_or_condition() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    sel1:
        FieldA: val1
    sel2:
        FieldB: val2
    condition: sel1 or sel2
"#,
        );
        assert_eq!(queries, vec!["FieldA=\"val1\" or FieldB=\"val2\""]);
    }

    #[test]
    fn test_not_condition() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        FieldA: val1
    filter:
        FieldB: val2
    condition: selection and not filter
"#,
        );
        assert_eq!(queries, vec!["FieldA=\"val1\" and not FieldB=\"val2\""]);
    }

    #[test]
    fn test_contains_modifier() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
"#,
        );
        assert_eq!(queries, vec!["CommandLine contains \"whoami\""]);
    }

    #[test]
    fn test_startswith_modifier() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        CommandLine|startswith: cmd
    condition: selection
"#,
        );
        assert_eq!(queries, vec!["CommandLine startswith \"cmd\""]);
    }

    #[test]
    fn test_endswith_modifier() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        CommandLine|endswith: '.exe'
    condition: selection
"#,
        );
        assert_eq!(queries, vec!["CommandLine endswith \".exe\""]);
    }

    #[test]
    fn test_wildcard_value() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        CommandLine: '*whoami*'
    condition: selection
"#,
        );
        assert_eq!(queries, vec!["CommandLine match *whoami*"]);
    }

    #[test]
    fn test_numeric_value() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        EventID: 4688
    condition: selection
"#,
        );
        assert_eq!(queries, vec!["EventID=4688"]);
    }

    #[test]
    fn test_boolean_value() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        Enabled: true
    condition: selection
"#,
        );
        assert_eq!(queries, vec!["Enabled=1"]);
    }

    #[test]
    fn test_null_value() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        FieldA: null
    condition: selection
"#,
        );
        assert_eq!(queries, vec!["FieldA is null"]);
    }

    #[test]
    fn test_exists_modifier() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        FieldA|exists: true
    condition: selection
"#,
        );
        assert_eq!(queries, vec!["exists(FieldA)"]);
    }

    #[test]
    fn test_not_exists_modifier() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        FieldA|exists: false
    condition: selection
"#,
        );
        assert_eq!(queries, vec!["notexists(FieldA)"]);
    }

    #[test]
    fn test_re_modifier() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        CommandLine|re: '.*whoami.*'
    condition: selection
"#,
        );
        assert_eq!(queries, vec!["CommandLine=/.*whoami.*/"]);
    }

    #[test]
    fn test_cidr_modifier() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        SourceIP|cidr: '10.0.0.0/8'
    condition: selection
"#,
        );
        assert_eq!(queries, vec!["cidrmatch(\"10.0.0.0/8\", SourceIP)"]);
    }

    #[test]
    fn test_gte_modifier() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        EventCount|gte: 10
    condition: selection
"#,
        );
        assert_eq!(queries, vec!["EventCount>=10"]);
    }

    #[test]
    fn test_multiple_values_or() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        CommandLine:
            - whoami
            - ipconfig
    condition: selection
"#,
        );
        assert_eq!(
            queries,
            vec!["CommandLine=\"whoami\" or CommandLine=\"ipconfig\""]
        );
    }

    #[test]
    fn test_multiple_values_all() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        CommandLine|all:
            - whoami
            - ipconfig
    condition: selection
"#,
        );
        assert_eq!(
            queries,
            vec!["CommandLine=\"whoami\" and CommandLine=\"ipconfig\""]
        );
    }

    #[test]
    fn test_value_list_under_and_is_grouped() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        Image:
            - a
            - b
        CommandLine: x
    condition: selection
"#,
        );
        assert_eq!(
            queries,
            vec!["(Image=\"a\" or Image=\"b\") and CommandLine=\"x\""]
        );
    }

    #[test]
    fn test_not_groups_compound_operands_only() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        Image: a
    filter_1:
        CommandLine: b
    filter_2:
        ParentImage: c
        User: d
    filter_3:
        User: e
    condition: selection and not 1 of filter_* and not filter_3 and not (filter_1 and not filter_3)
"#,
        );
        assert_eq!(
            queries,
            vec![
                "Image=\"a\" and not (CommandLine=\"b\" or ParentImage=\"c\" and User=\"d\" or User=\"e\") \
                 and not User=\"e\" and not (CommandLine=\"b\" and not User=\"e\")"
            ]
        );
    }

    #[test]
    fn test_and_under_or_is_bare() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    sel_1:
        Image: a
        User: b
    sel_2:
        Image: c
    condition: 1 of sel_*
"#,
        );
        assert_eq!(queries, vec!["Image=\"a\" and User=\"b\" or Image=\"c\""]);
    }

    #[test]
    fn test_escape_chars() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        FieldA: 'value:with&special'
    condition: selection
"#,
        );
        // `:` should be escaped with `\`, `&` should be filtered
        assert_eq!(queries, vec!["FieldA=\"value\\:withspecial\""]);
    }

    #[test]
    fn test_output_format_test() {
        let collection = parse_sigma_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        FieldA: val1
    condition: selection
"#,
        )
        .unwrap();
        let backend = TextQueryTestBackend::new();
        let queries = backend
            .convert_rule(&collection.rules[0], "test", &PipelineState::default())
            .unwrap();
        assert_eq!(queries, vec!["[ FieldA=\"val1\" ]"]);
    }

    #[test]
    fn test_output_format_state() {
        let collection = parse_sigma_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        FieldA: val1
    condition: selection
"#,
        )
        .unwrap();
        let backend = TextQueryTestBackend::new();
        let mut ps = PipelineState::default();
        ps.set_state(
            "index".to_string(),
            serde_json::Value::String("my_index".into()),
        );
        let queries = backend
            .convert_rule(&collection.rules[0], "state", &ps)
            .unwrap();
        assert_eq!(queries, vec!["index=my_index (FieldA=\"val1\")"]);
    }

    #[test]
    fn test_mandatory_pipeline_error() {
        let collection = parse_sigma_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        FieldA: val1
    condition: selection
"#,
        )
        .unwrap();
        let backend = MandatoryPipelineTestBackend::new();
        let result = crate::convert::convert_collection(&backend, &collection, &[], "default");
        assert!(matches!(result, Err(ConvertError::PipelineRequired)));
    }

    #[test]
    fn test_multiple_detection_items_and() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        FieldA: val1
        FieldB: val2
    condition: selection
"#,
        );
        assert_eq!(queries, vec!["FieldA=\"val1\" and FieldB=\"val2\""]);
    }

    #[test]
    fn test_keywords() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    keywords:
        - whoami
        - ipconfig
    condition: keywords
"#,
        );
        assert_eq!(queries, vec!["_=\"whoami\" or _=\"ipconfig\""]);
    }

    #[test]
    fn test_keywords_all_renders_one_term_per_value() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    keywords:
        '|all':
            - 'bash -c'
            - 4444
    condition: keywords
"#,
        );
        assert_eq!(queries, vec!["_=\"bash -c\" and _=4444"]);
    }

    #[test]
    fn test_negated_field_less_value_renders_a_negated_term() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    keywords:
        '|neq':
            - whoami
            - ipconfig
    condition: keywords
"#,
        );
        assert_eq!(queries, vec!["not (_=\"whoami\" or _=\"ipconfig\")"]);
    }

    #[test]
    fn test_anchored_field_less_value_is_unsupported() {
        let err = convert_rule_yaml_err(
            r#"
title: Test
logsource:
    category: test
detection:
    keywords:
        '|startswith': whoami
    condition: keywords
"#,
        );
        assert!(matches!(err, ConvertError::UnsupportedKeyword));
    }

    #[test]
    fn test_case_sensitive_contains() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        CommandLine|contains|cased: Whoami
    condition: selection
"#,
        );
        assert_eq!(queries, vec!["CommandLine contains_cased \"Whoami\""]);
    }

    #[test]
    fn test_re_with_slash_escaping() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        Path|re: 'C:/Windows/.*'
    condition: selection
"#,
        );
        // `:` is in add_escaped for string values, not re_escape, so it stays unescaped.
        // `/` is in re_escape, so both slashes get escaped.
        assert_eq!(queries, vec!["Path=/C:\\/Windows\\/.*/"]);
    }

    /// Convert a rule expected to fail and return the resulting error message.
    fn convert_rule_yaml_err(yaml: &str) -> ConvertError {
        let collection = parse_sigma_yaml(yaml).unwrap();
        let backend = TextQueryTestBackend::new();
        backend
            .convert_rule(&collection.rules[0], "default", &PipelineState::default())
            .expect_err("rule should fail to convert")
    }

    #[test]
    fn test_neq_modifier() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        Field|neq: forbidden
        EventID|neq: 1
        Image|fieldref|neq: ParentImage
    condition: selection
"#,
        );
        assert_eq!(
            queries,
            vec!["not Field=\"forbidden\" and not EventID=1 and not Image=fieldref(ParentImage)"]
        );
    }

    #[test]
    fn test_encoding_modifiers_expand_to_plain_matches() {
        for (modifier, expected) in [
            ("base64", r#"Field="LXBheWxvYWQ=""#),
            (
                "base64offset|contains",
                r#"Field contains "LXBheWxvYW" or Field contains "1wYXlsb2Fk" or Field contains "tcGF5bG9hZ""#,
            ),
            (
                "wide|base64offset|contains",
                r#"Field contains "LQBwAGEAeQBsAG8AYQBkA" or Field contains "0AcABhAHkAbABvAGEAZA" or Field contains "tAHAAYQB5AGwAbwBhAGQA""#,
            ),
            ("utf16|base64", r#"Field="//4tAHAAYQB5AGwAbwBhAGQA""#),
            ("utf16be|base64", r#"Field="AC0AcABhAHkAbABvAGEAZA==""#),
            (
                "windash|contains",
                r#"Field contains "-payload" or Field contains "/payload" or Field contains "–payload" or Field contains "—payload" or Field contains "―payload""#,
            ),
        ] {
            let yaml = format!(
                r#"
title: Test
logsource:
    category: test
detection:
    selection:
        Field|{modifier}: '-payload'
    condition: selection
"#
            );
            assert_eq!(convert_rule_yaml(&yaml), vec![expected], "{modifier}");
        }
    }

    #[test]
    fn test_encoding_expansion_keeps_or_grouped() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        Image|endswith: '\x.exe'
        CommandLine|windash|contains: ' -f '
    condition: selection
"#,
        );
        assert_eq!(
            queries,
            vec![
                r#"Image endswith "\\x.exe" and (CommandLine contains " -f " or CommandLine contains " /f " or CommandLine contains " –f " or CommandLine contains " —f " or CommandLine contains " ―f ")"#
            ]
        );
    }

    #[test]
    fn test_negated_encoding_expansion_is_grouped() {
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        A: x
        Field|windash|contains|neq: ' -f '
    condition: selection
"#,
        );
        assert_eq!(
            queries,
            vec![
                r#"A="x" and not (Field contains " -f " or Field contains " /f " or Field contains " –f " or Field contains " —f " or Field contains " ―f ")"#
            ]
        );
    }

    #[test]
    fn test_encoding_wildcard_with_base64_is_rejected() {
        let err = convert_rule_yaml_err(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        Field|base64offset|contains: 'pay*load'
    condition: selection
"#,
        );
        assert!(
            matches!(&err, ConvertError::UnsupportedValue(_)),
            "got: {err}"
        );
    }

    #[test]
    fn test_values_pysigma_rejects_fail_conversion() {
        for (detection, expected) in [
            ("Ip|cidr: '10.1.2.3/8'", "host bits set"),
            ("Count|gt: 'abc'", "abc"),
            ("A|fieldref|cased: B", "fieldref|cased"),
        ] {
            let yaml = format!(
                r#"
title: Test
logsource:
    category: test
detection:
    selection:
        {detection}
    condition: selection
"#
            );
            let err = convert_rule_yaml_err(&yaml);
            assert!(err.to_string().contains(expected), "{detection}: {err}");
        }
    }

    #[test]
    fn test_unresolved_expand_is_rejected() {
        let err = convert_rule_yaml_err(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        Field|expand: '%admin_users%'
    condition: selection
"#,
        );
        assert!(err.to_string().contains("%admin_users%"), "got: {err}");
    }

    #[test]
    fn test_default_path_rejects_timestamp_part_modifiers() {
        for modifier in ["minute", "hour", "day", "week", "month", "year"] {
            let yaml = format!(
                r#"
title: Test
logsource:
    category: test
detection:
    selection:
        TimeField|{modifier}: 5
    condition: selection
"#
            );
            let err = convert_rule_yaml_err(&yaml);
            assert!(
                matches!(&err, ConvertError::UnsupportedModifier(_)),
                "expected UnsupportedModifier for `{modifier}`, got: {err}",
            );
        }
    }

    #[test]
    fn test_default_path_rejects_regex_flag_without_re() {
        // `m` (multiline) and `s` (dotall) only have meaning alongside `re`;
        // outside that branch they would be silently dropped.
        for modifier in ["m", "s"] {
            let yaml = format!(
                r#"
title: Test
logsource:
    category: test
detection:
    selection:
        Field|{modifier}: anything
    condition: selection
"#
            );
            let err = convert_rule_yaml_err(&yaml);
            assert!(
                matches!(&err, ConvertError::UnsupportedModifier(_)),
                "expected UnsupportedModifier for `{modifier}`, got: {err}",
            );
        }
    }

    #[test]
    fn test_default_path_keeps_safe_modifiers_working() {
        // Sanity check: modifiers that ARE supported by the generic
        // dispatch (`contains`, `startswith`, `endswith`, `cased`, `i`)
        // still produce a query, so the new gate does not over-reject.
        let queries = convert_rule_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
"#,
        );
        assert_eq!(queries.len(), 1);
    }
}
