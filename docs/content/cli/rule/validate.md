# `rsigma rule validate`

{{ added "0.12.0" }}

Parse all Sigma rules in a directory (recursive) and report results.

## Synopsis

```text
rsigma rule validate [OPTIONS] <PATH>
```

## Description

Walks a directory, parses every `*.yml`/`*.yaml` Sigma file with `rsigma-parser`, optionally applies one or more processing pipelines, and compiles each rule with the evaluator's compiler. Reports the counts on stdout (human summary by default). Pass `--output-format json|ndjson|table|csv|tsv` for a structured envelope or `PATH,STATUS,ERRORS` rows. Exits with code `2` if any rule fails to parse or compile. See [Output Formats](../../reference/output.md).

This is the cheapest CI gate: no events are evaluated, just rules and pipelines. Wire it as the first step of every detection-as-code pipeline before [`rule lint`](lint.md) and [`engine eval`](../engine/eval.md) fixture tests.

For narrative coverage see [Linting Rules](../../guide/linting-rules.md) and [CI/CD](../../guide/ci-cd.md).

## Flags

| Flag | Description |
|------|-------------|
| `<PATH>` | Path to a directory containing Sigma YAML files (recursive). |
| `-v, --verbose` | Show details for each file, not just the summary. |
| `-p, --pipeline <PIPELINES>` | Processing pipeline(s) to apply. Builtin names (`ecs_windows`, `fibratus_windows`, `sysmon`) or YAML file paths. Repeatable. |
| `--source <FILE_OR_DIR>` | External source file(s) or directory of source files. Repeatable. Same standalone `sources:` YAML shape as the daemon's `--source`. Required for meaningful `--resolve-sources` runs after the v1.0 removal of pipeline-embedded `sources:`. |
| `--resolve-sources` | Resolve and fetch every loaded dynamic source during validation. Sources must be reachable for validation to pass. |

## Examples

### Plain validation

```bash
rsigma rule validate rules/
```

Output:

```text
Parsed 24 documents from rules/
  Detection rules:   22
  Correlation rules: 2
  Filter rules:      0
  Parse errors:      0
  Pipeline applied:  0 pipeline(s)
  Compiled OK:       24
  Compile errors:    0
```

### Validate with a pipeline applied

```bash
rsigma rule validate rules/ -p pipelines/ecs.yml
```

Catches rules that reference fields the pipeline drops or renames in an incompatible way.

### Strict CI: also exercise dynamic sources

```bash
rsigma rule validate rules/ -p pipelines/dynamic.yml --source sources.yml --resolve-sources
```

The job fails with exit `3` if any HTTP, file, or command source is unreachable. Use this on PR builds for repos that ship dynamic pipelines.

### Verbose per-file output

```bash
rsigma rule validate rules/ -v
```

Shows one line per file with its parse/compile status.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Every rule parsed and compiled cleanly. |
| `2` | At least one parse or compile error. |
| `3` | Pipeline file could not be loaded, `--source` load failure, `--resolve-sources` failed on a dynamic source, or the binary lacks the `daemon` feature needed for source resolution. |

## See also

- [`rule lint`](lint.md) for the spec-conformance gate ({{ rsigma.lint.rules }} lint rules, auto-fix).
- [`rule parse`](parse.md) for a single-file AST dump.
- [Linting Rules](../../guide/linting-rules.md) and [Processing Pipelines](../../guide/processing-pipelines.md).
- [CI/CD](../../guide/ci-cd.md) for the validate/lint/eval pipeline pattern.
