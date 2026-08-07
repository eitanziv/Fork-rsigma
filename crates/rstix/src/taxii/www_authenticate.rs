//! `WWW-Authenticate` challenge parsing (RFC 7235, spec section 1.6.9).

/// Parsed HTTP authentication challenge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthChallenge {
    /// Scheme name (e.g. `Basic`, `Bearer`).
    pub scheme: String,
    /// Remaining challenge parameters (e.g. `realm="TAXII"`).
    pub params: String,
}

/// Parse a `WWW-Authenticate` header value into challenges.
pub fn parse_www_authenticate(value: &str) -> Vec<AuthChallenge> {
    let mut challenges = Vec::new();
    for part in split_challenges(value) {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let Some((scheme, params)) = part.split_once(' ') else {
            challenges.push(AuthChallenge {
                scheme: part.to_owned(),
                params: String::new(),
            });
            continue;
        };
        challenges.push(AuthChallenge {
            scheme: scheme.to_owned(),
            params: params.trim().to_owned(),
        });
    }
    challenges
}

fn split_challenges(value: &str) -> Vec<String> {
    // RFC 7235 challenges are comma-separated, but auth-params within a challenge are
    // also comma-separated. A new challenge starts only when the token after a comma is
    // a scheme name (no `=`), not another auth-param (`key=value`).
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let chars: Vec<char> = value.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let ch = chars[i];
        match ch {
            '\\' if in_quotes && i + 1 < chars.len() => {
                // Keep escaped pairs intact so `\"` does not flip quote parity.
                current.push('\\');
                current.push(chars[i + 1]);
                i += 2;
            }
            '"' => {
                in_quotes = !in_quotes;
                current.push(ch);
                i += 1;
            }
            ',' if !in_quotes => {
                let rest = &chars[i + 1..];
                if starts_new_challenge_chars(rest) {
                    parts.push(std::mem::take(&mut current));
                } else {
                    current.push(',');
                }
                i += 1;
            }
            _ => {
                current.push(ch);
                i += 1;
            }
        }
    }
    if !current.is_empty() {
        parts.push(current);
    }
    parts
}

fn starts_new_challenge_chars(rest: &[char]) -> bool {
    let mut start = 0;
    while start < rest.len() && rest[start].is_whitespace() {
        start += 1;
    }
    if start >= rest.len() {
        return false;
    }
    let mut end = start;
    while end < rest.len() && !rest[end].is_whitespace() && rest[end] != ',' {
        end += 1;
    }
    let token = &rest[start..end];
    !token.is_empty()
        && !token.contains(&'=')
        && token
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '+' | '.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_challenge() {
        let challenges = parse_www_authenticate(r#"Basic realm="TAXII Server""#);
        assert_eq!(challenges.len(), 1);
        assert_eq!(challenges[0].scheme, "Basic");
        assert!(challenges[0].params.contains("realm=\"TAXII Server\""));
    }

    #[test]
    fn parses_csd01_table2_multi_challenge() {
        // TAXII 2.1 Interop CSD01 Table 2 — auth-params must not split into fake schemes.
        let challenges = parse_www_authenticate(
            r#"Basic realm="taxii", type=1, title="Login to \"apps\"", Basic realm="simple""#,
        );
        assert_eq!(challenges.len(), 2);
        assert_eq!(challenges[0].scheme, "Basic");
        assert!(challenges[0].params.contains("realm=\"taxii\""));
        assert!(challenges[0].params.contains("type=1"));
        assert_eq!(challenges[1].scheme, "Basic");
        assert!(challenges[1].params.contains("realm=\"simple\""));
    }

    #[test]
    fn escaped_quote_inside_param_does_not_split_challenge() {
        // Escaped `\"` must not desync quote parity into a false challenge boundary.
        let challenges = parse_www_authenticate(r#"Basic realm="a\",Basic b", Bearer realm="x""#);
        assert_eq!(challenges.len(), 2);
        assert_eq!(challenges[0].scheme, "Basic");
        assert!(challenges[0].params.contains(r#"realm="a\",Basic b""#));
        assert_eq!(challenges[1].scheme, "Bearer");
        assert!(challenges[1].params.contains("realm=\"x\""));
    }
}
