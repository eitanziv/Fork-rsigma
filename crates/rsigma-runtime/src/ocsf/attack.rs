//! ATT&CK tag parsing for the `finding_info.attacks[]` array.
//!
//! Sigma carries ATT&CK references as flat tags: `attack.t1059.001` for a
//! (sub-)technique and `attack.credential_access` for a tactic. Techniques
//! keep their dotted sub-technique form and are uppercased; tactics resolve
//! through the shipped [`MITRE_TACTICS`] table so their display names and
//! `TA####` ids match the spelling the rest of rsigma uses.
//!
//! Tags a rule carries for other taxonomies (`cve.2023.1`, ATT&CK groups and
//! software, custom namespaces) are not ATT&CK references and are skipped;
//! they still reach the consumer under `unmapped.tags`.

use rsigma_parser::reference::MITRE_TACTICS;
use serde_json::{Map, Value, json};

/// Build the `attacks[]` array from a rule's tags.
///
/// Emits one entry per technique tag and one per tactic tag, in tag order and
/// without duplicates. A tag naming a technique cannot say which tactic it was
/// used for, so techniques and tactics stay in separate entries rather than
/// being paired by guesswork. Returns `None` when no tag is an ATT&CK
/// reference, so the key is omitted rather than emitted empty.
pub(super) fn attacks_from_tags(tags: &[String]) -> Option<Value> {
    let mut out: Vec<Value> = Vec::new();
    for tag in tags {
        let lower = tag.to_ascii_lowercase();
        let Some(short) = lower.strip_prefix("attack.") else {
            continue;
        };
        let entry = if let Some((kind, uid)) = technique_uid(short) {
            let mut attack = Map::new();
            attack.insert(kind.to_string(), json!({ "uid": uid }));
            Value::Object(attack)
        } else if let Some((name, uid)) = tactic(short) {
            json!({ "tactic": { "name": name, "uid": uid } })
        } else {
            continue;
        };
        if !out.contains(&entry) {
            out.push(entry);
        }
    }
    (!out.is_empty()).then_some(Value::Array(out))
}

/// Build the `attacks[]` array from canonical tactic slugs, as the risk layer
/// records them on a risk incident (`credential-access`).
pub(super) fn attacks_from_tactics(tactics: &[String]) -> Option<Value> {
    let mut out: Vec<Value> = Vec::new();
    for slug in tactics {
        if let Some((name, uid)) = tactic(&slug.to_ascii_lowercase()) {
            let entry = json!({ "tactic": { "name": name, "uid": uid } });
            if !out.contains(&entry) {
                out.push(entry);
            }
        }
    }
    (!out.is_empty()).then_some(Value::Array(out))
}

/// `t1059` / `t1059.001` to the corresponding OCSF member and ATT&CK uid.
///
/// The technique number must be four digits and the optional sub-technique
/// three, so an ATT&CK group (`g0016`) or a malformed tag is not mistaken for
/// a technique.
fn technique_uid(short: &str) -> Option<(&'static str, String)> {
    let rest = short.strip_prefix('t')?;
    let (technique, sub) = match rest.split_once('.') {
        Some((technique, sub)) => (technique, Some(sub)),
        None => (rest, None),
    };
    if technique.len() != 4 || !technique.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    match sub {
        Some(sub) if sub.len() == 3 && sub.chars().all(|c| c.is_ascii_digit()) => {
            Some(("sub_technique", format!("T{technique}.{sub}")))
        }
        Some(_) => None,
        None => Some(("technique", format!("T{technique}"))),
    }
}

/// Resolve a tactic short name to its `(display name, TA#### uid)` pair,
/// accepting both the underscore spelling Sigma uses and the hyphenated
/// Navigator slug the risk layer canonicalizes to.
fn tactic(short: &str) -> Option<(&'static str, &'static str)> {
    let key = format!("attack.{}", short.replace('-', "_"));
    let text = MITRE_TACTICS
        .iter()
        .find(|(tag, _)| *tag == key)
        .map(|(_, text)| *text)?;
    // `Credential Access (TA0006)` splits into name and uid.
    let (name, uid) = text.split_once(" (")?;
    Some((name, uid.strip_suffix(')')?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tags(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn techniques_and_sub_techniques_keep_their_uid_shape() {
        let out = attacks_from_tags(&tags(&["attack.t1059", "attack.t1059.001"])).unwrap();
        assert_eq!(
            out,
            json!([
                { "technique": { "uid": "T1059" } },
                    { "sub_technique": { "uid": "T1059.001" } },
            ])
        );
    }

    #[test]
    fn tactics_resolve_through_the_shipped_table() {
        let out = attacks_from_tags(&tags(&["attack.credential_access"])).unwrap();
        assert_eq!(
            out,
            json!([{ "tactic": { "name": "Credential Access", "uid": "TA0006" } }])
        );
    }

    #[test]
    fn hyphenated_risk_layer_slugs_resolve_to_the_same_tactic() {
        let out = attacks_from_tactics(&tags(&["credential-access"])).unwrap();
        assert_eq!(
            out,
            json!([{ "tactic": { "name": "Credential Access", "uid": "TA0006" } }])
        );
    }

    #[test]
    fn duplicate_tags_collapse() {
        let out = attacks_from_tags(&tags(&[
            "attack.t1059",
            "attack.T1059",
            "attack.privilege_escalation",
            "attack.privilege-escalation",
        ]))
        .unwrap();
        assert_eq!(out.as_array().unwrap().len(), 2);
    }

    #[test]
    fn non_attack_and_malformed_tags_are_skipped() {
        assert!(attacks_from_tags(&tags(&["cve.2023.1"])).is_none());
        assert!(attacks_from_tags(&tags(&["attack.g0016"])).is_none());
        assert!(attacks_from_tags(&tags(&["attack.t105"])).is_none());
        assert!(attacks_from_tags(&tags(&["attack.t1059.1"])).is_none());
        assert!(attacks_from_tags(&tags(&["attack."])).is_none());
        assert!(attacks_from_tags(&tags(&["attack.stealth"])).is_none());
    }
}
