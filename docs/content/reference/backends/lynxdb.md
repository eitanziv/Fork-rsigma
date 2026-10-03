# LynxDB Backend

The `lynxdb` backend converts Sigma rules into [SPL2](https://docs.lynxdb.org/docs/sigma/spl2-mapping/)-compatible search expressions for LynxDB. Translation favors the native search syntax and defers features that LynxDB's parser cannot express directly to a `where` pipeline stage.

For the workflow walkthrough see [Rule Conversion](../../guide/rule-conversion.md#lynxdb). For LynxDB-side operational topics (REST API, saved queries, scheduled detection, drift runbook) see [Sigma rules on LynxDB](https://docs.lynxdb.org/docs/sigma/).

## How it differs from PostgreSQL

LynxDB is a log analytics engine with its own search language (SPL2 syntax). The translation strategy is therefore different:

- No table or schema concept; the target is an **index** (default `main`).
- No `WHERE` clause; conditions are encoded inline in the `search` keyword's expression.
- Boolean precedence is non-standard (`NOT > OR > AND`), so the backend parenthesizes wherever that precedence would change a condition's meaning.
- A subset of Sigma modifiers (regex, CIDR, single-character wildcards, case-sensitive matches) is **deferred**: emitted as a downstream pipeline stage instead of a native search term.

## Backend options

LynxDB has no CLI options today. The single configurable knob is the target index, controlled exclusively via pipeline `set_state`:

```yaml
transformations:
  - type: set_state
    key: index
    value: security_logs
```

Defaults:

| Knob | Default |
|------|---------|
| Index | `main` |

The state key `index` is validated identically to PostgreSQL identifiers (`^[A-Za-z_][A-Za-z0-9_$]*$`). A custom index gets baked into the `FROM <index>` prefix of every generated query.

## Modifier mapping

Verified against the LynxDB backend's golden tests at [`crates/rsigma-convert/src/backends/lynxdb`](https://github.com/timescale/rsigma/tree/main/crates/rsigma-convert/src/backends/lynxdb).

| Sigma feature | LynxDB SPL2 |
|---------------|-------------|
| Field equality | `field=value`, `field="quoted with spaces"` |
| Wildcard `*` | `field=prefix*`, `field=*contains*`, `field=*"with quotes"*` |
| Wildcard `?` (single char) | Deferred to a `where field=~"regex"` pipeline stage. |
| Regex (`re` modifier) | Deferred to a `where field=~"pattern"` pipeline stage. |
| CIDR (`cidr` modifier) | Deferred to a `where cidrmatch("cidr", field)` pipeline stage. |
| Case-sensitive (`cased` modifier) | `field=CASE(value)` |
| `exists: true`/`false` | `field=*`/`NOT field=*` |
| Boolean `AND`, `OR`, `NOT` | Parenthesized where the non-standard precedence (`NOT > OR > AND`) requires it: an `AND` under an `OR`, and a compound operand of `NOT`. |
| `null` value | `NOT field=*` (no equivalent of `IS NULL`). |
| IN-list (`field` with multiple values) | `field IN (val1, val2, ...)` (LynxDB's native IN form). |
| `all` modifier | values combined with explicit `AND` in the search expression. |
| Keywords | Bare quoted token (`field`-less): `"keyword"`. |

"Deferred" means the feature does not translate to a native LynxDB search term and is instead emitted as an SPL2 pipeline stage downstream of `search`. The query shape becomes `FROM main | search <native-bits> | where <deferred-bits>`.

Integer, float, and boolean values keep their literal SPL2 form (`EventID=4688`, `Enabled=true`). Strings with whitespace, special characters, or wildcards are quoted (`"value with spaces"`, `*"endswith"`).

## Output formats

Pick with `-f <format>`. Two formats:

### `default`

Full query including the index prefix and the `search` keyword:

```text
FROM main | search CommandLine=*whoami*
FROM main | search EventID=4625
FROM security_logs | search User="Administrator" AND ProcessName=*explorer*
```

### `minimal`

Just the search expression, no index prefix or `search` keyword. Useful when feeding the expression into LynxDB's REST API as a `q=` parameter:

```text
CommandLine=*whoami*
EventID=4625
User="Administrator" AND ProcessName=*explorer*
```

`minimal` output strips the leading `FROM <index> | search ` from the corresponding `default` query. Use it as the value of LynxDB's saved-query `q` field or any context that expects only the search expression.

## Boolean precedence

LynxDB's parser evaluates Boolean operators in the order `NOT > OR > AND`, which is the reverse of standard SQL (and most programming languages) for `AND` and `OR`. The backend groups by that precedence, so the same Sigma `condition:` produces the same set of matches as `engine eval`:

- An `AND` nested under an `OR` is parenthesized: `(A and B) or C` becomes `(A AND B) OR C`.
- An `OR` nested under an `AND` stays bare, because it already binds tighter: `(A or B) and C` becomes `A OR B AND C`.
- A compound operand of `NOT` is always parenthesized: `A and not 1 of filter_*` becomes `A AND NOT (filter_1 OR filter_2)`. {{ added "unreleased" }}

## Examples

### Plain string match

```yaml
title: Whoami
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
```

```text
FROM main | search CommandLine=*whoami*
```

### Integer field

```yaml
detection:
    sel:
        EventID: 4688
    condition: sel
```

```text
FROM main | search EventID=4688
```

### Custom index via pipeline

```yaml
# pipeline.yml
transformations:
  - type: set_state
    key: index
    value: security_logs
```

```bash
rsigma backend convert rules/ -t lynxdb -p pipeline.yml
```

```text
FROM security_logs | search CommandLine=*whoami*
```

### Deferred regex

```yaml
detection:
    sel:
        CommandLine|re: '^cmd.*whoami'
    condition: sel
```

```text
FROM main | search * | where CommandLine=~"^cmd.*whoami"
```

The leading `search *` matches every event in the index; the `where` stage applies the regex. This is intentionally less efficient than a native search term, hence "deferred"; rules that lean heavily on regex are slower on LynxDB than on PostgreSQL.

### CIDR with combination

```yaml
detection:
    sel:
        Action: 'allow'
        DestinationIp|cidr: '10.0.0.0/8'
    condition: sel
```

```text
FROM main | search Action="allow" | where cidrmatch("10.0.0.0/8", DestinationIp)
```

The `Action` literal stays in the `search` stage; the CIDR check defers to `where cidrmatch(...)`.

## Limitations

| Feature | Status |
|---------|--------|
| Multi-table correlations | Not yet implemented. Single-table correlations work via SPL2 `stats`. |
| Continuous aggregates | LynxDB-equivalent (scheduled saved queries) lives on the LynxDB side. RSigma emits the SPL2; LynxDB schedules it. |
| `temporal_ordered` correlation | Not yet implemented. |

## See also

- [Rule Conversion](../../guide/rule-conversion.md#lynxdb) for the workflow walkthrough.
- [LynxDB's own Sigma guide](https://docs.lynxdb.org/docs/sigma/) for the operator-facing tutorials, the SPL2 mapping reference, scheduled detection, and the drift runbook.
- [`backend convert`](../../cli/backend/convert.md) for the CLI flag table.
- [PostgreSQL backend reference](postgres.md) for the alternate target.
- [`crates/rsigma-convert/src/backends/lynxdb`](https://github.com/timescale/rsigma/tree/main/crates/rsigma-convert/src/backends/lynxdb) for the implementation.
