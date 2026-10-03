# Value Modifiers

{{ added "unreleased" }}

This page describes how the evaluator and the converters interpret Sigma value modifiers where the specification leaves room for interpretation. The behavior follows the [Sigma specification](https://github.com/SigmaHQ/sigma-specification) and matches pySigma unless a section says otherwise. For keywords and modifiers without a field name, see [Keywords and Conditions](conditions.md).

## Modifier chains

A detection key is a field name followed by a pipe-separated modifier chain, such as `CommandLine|windash|contains`. Each modifier may appear once per key: `Field|neq|neq` and `Field|base64|base64` are parse errors. Contradictory combinations, such as `|contains|startswith` or `|base64|base64offset`, are rejected when the rule is compiled.

## Wildcards

`*` matches any run of characters and `?` matches exactly one, including newlines, so `foo*bar` matches a multi-line value that starts with `foo` and ends with `bar`. The string operator decides which ends of the value are anchored:

| Modifier | Wildcard value | Matches |
|----------|----------------|---------|
| none | `net*user` | The whole value starts with `net` and ends with `user`. |
| `startswith` | `net*user` | The value starts with `net` and contains `user` anywhere after it. |
| `endswith` | `sys*.exe` | The value ends with `.exe` and contains `sys` anywhere before it. |
| `contains` | `net*user` | `net` appears somewhere before `user`. |

A backslash escapes `*`, `?`, and itself, so `\*` is a literal asterisk.

## Case sensitivity

String matching is case-insensitive unless the key has `|cased`. Case folding uses Unicode lowercase, so `Ä` matches `ä`. Lowercasing the dotted capital `İ` (U+0130) produces `i` followed by a combining dot, so `İ` does not match a plain `i`.

`|fieldref|cased` compares the two fields case-sensitively. This is an rsigma extension that pySigma rejects; the PostgreSQL and Fibratus backends convert it, and the `test` backend, which mirrors pySigma's text output, rejects it with `UnsupportedModifier`. {{ added "unreleased" }}

## Encodings

The encoding modifiers transform the value before it is matched. When several apply, they run in a fixed order regardless of their position in the key: `windash`, then one of `wide` (alias `utf16le`), `utf16be`, or `utf16`, then one of `base64` or `base64offset`.

- `windash` makes every `-`, `/`, `–` (en dash), `—` (em dash), and `―` (horizontal bar) in the value interchangeable with the others. A value may contain at most 8 such characters, because each one multiplies the number of variants by 5. Wildcards keep their meaning, so `dir*-s` matches `dir C:\ /s`.
- `wide` encodes the value as UTF-16LE, `utf16be` as UTF-16BE, and `utf16` as UTF-16LE with a byte-order mark. Without a following base64 modifier, the encoded value is matched against the event field as text, so the field must carry the NUL bytes of the UTF-16 encoding. Only ASCII values can be matched this way.
- `base64` encodes the value. `base64offset` produces the three encodings of the value at each byte alignment inside a larger base64 string, and drops the leading and trailing characters that depend on the surrounding bytes, as pySigma does.

A value with a wildcard cannot be combined with `base64` or `base64offset`, because a base64 encoding has no way to represent "any characters". Such a rule is rejected when it is compiled.

Backends convert encoding modifiers as pySigma does: each variant becomes a plain string match, and the variants are ORed together. The windash limit applies to conversion too. Without a base64 step, a UTF-16 variant contains NUL characters, which the PostgreSQL and Fibratus backends reject with `UnsupportedValue`. {{ added "unreleased" }}

## Placeholders and `expand`

With `|expand`, `%name%` in a value is a placeholder. A backslash escapes `%` as well as `*`, `?`, and itself: `100\%` is a literal percent sign, and `C:\Users\\%user%` is a backslash followed by the `user` placeholder. A placeholder name is non-empty and contains no `*`, `?`, or backslash.

A processing pipeline with a [`value_placeholders`](../guide/processing-pipelines.md) transformation replaces placeholders with the values of its `vars:`. Several multi-value variables in one value expand to their Cartesian product. Every referenced variable must exist; an unresolved variable is a pipeline error unless the transformation sets `allow_unresolved: true` to opt into runtime substitution. When every placeholder is resolved this way, the value is an ordinary string match: wildcards and string modifiers such as `|contains` apply, and backends convert it like any other value. `wildcard_placeholders` replaces every handled placeholder with `*`, whether or not a variable is defined. Pipeline placeholder transformations ignore values without `|expand`. {{ added "unreleased" }}

A placeholder that is not passed through a placeholder transformation is filled in from the event at match time: `%user%` takes the value of the event's `user` field, or an empty string when that field is missing or not a string. Runtime placeholders are an rsigma extension. Backends cannot convert them, and a value with a runtime placeholder cannot use wildcards or encoding modifiers.

## `re`

A regex is case-sensitive unless the key has `|i`. `|m` makes `^` and `$` match at line breaks, and `|s` lets `.` match a line break. Backends render the flags rather than dropping them: the `test`, LynxDB, and Fibratus backends prepend an inline group such as `(?im)`, and PostgreSQL uses `~*` for `|i` and the `(?w)` embedded option for `|m`. `|cased` has no effect on a regex; pySigma and the `test` backend reject it. {{ added "unreleased" }}

## `cidr`

A `cidr` value is an IPv4 or IPv6 network written as `address/prefix`, such as `10.0.0.0/8` or `2001:db8::/32`. As in pySigma, a value with host bits set, such as `10.1.2.3/8`, is rejected when the rule is compiled or converted, because the address would silently stand for a different network. {{ added "unreleased" }}

## `exists`

`Field|exists: true` matches when the field is present in the event, including when its value is `null`. `Field|exists: false` matches only when the field is absent.

## `neq`

`neq` negates the whole detection item. `Field|neq: [a, b]` matches when the field is neither `a` nor `b`, and it also matches when the field is missing or `null`. The same applies to `|fieldref|neq`: the item matches unless both fields are present and equal.

To require the field to be present, add a separate `Field|exists: true` item to the same selection.

## Empty value lists

`Field: []` is a null check: it matches when the field is missing or `null`, as in pySigma. `Field|neq: []` matches when the field has a non-null value. An empty value list without a field name is rejected, and so is `|all` with fewer than two values, including `Field|contains|all: []`, which pySigma accepts.
