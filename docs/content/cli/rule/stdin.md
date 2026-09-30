# `rsigma rule stdin`

{{ added "0.12.0" }}

Read Sigma YAML from stdin and print the parsed AST as JSON.

## Synopsis

```text
rsigma rule stdin [OPTIONS]
```

## Description

Equivalent to [`rule parse`](parse.md), but reads the YAML body from stdin rather than from a file. Convenient for editor integrations, ad-hoc shell pipelines, and unit tests that synthesize a rule body on the fly.

## Flags

| Flag | Description |
|------|-------------|
| `-p, --pretty` | Pretty-print JSON output. |

## Examples

### Pipe a heredoc

```bash
rsigma rule stdin --pretty <<'EOF'
title: whoami
id: 8b1d8c97-5b3a-4d77-9b48-7c5f7c8b1a2a
status: experimental
logsource:
    product: windows
    category: process_creation
detection:
    sel:
        CommandLine|contains: 'whoami'
    condition: sel
level: medium
EOF
```

### Stream a generated rule

```bash
generate-sigma --product windows --action whoami | rsigma rule stdin
```

### Editor integration

```bash
# Vim: pipe the current buffer into rule stdin
:%!rsigma rule stdin --pretty
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Soft YAML issues (missing required fields, incomplete documents) are reported as warnings on stderr; the partial AST still prints to stdout. |
| `2` | stdin could not be read, or `parse_sigma_yaml` returned a hard parser error. |

`rule stdin` is intentionally lenient for editor integrations and shell pipelines where soft issues still produce a usable partial AST. For a strict gate, use [`rule validate`](validate.md) (which exits `2` on parse or compile errors).

## See also

- [`rule parse`](parse.md) for the file-based counterpart.
- [`rule lint`](lint.md) for spec-conformance checks.
- [Editor integration](../../editors/vscode.md) for the LSP-driven workflow.
