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
            '"' => {
                in_quotes = !in_quotes;
                current.push(ch);
                i += 1;
            }
            ',' if !in_quotes => {
                let rest: String = chars[i + 1..].iter().collect();
                if starts_new_challenge(rest.trim_start()) {
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

fn starts_new_challenge(rest: &str) -> bool {
    let token = rest
        .split(|c: char| c.is_whitespace() || c == ',')
        .next()
        .unwrap_or("");
    !token.is_empty()
        && !token.contains('=')
        && token
            .chars()
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
}
