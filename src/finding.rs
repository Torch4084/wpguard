use crate::severity::{Confidence, Severity};
use serde::{Deserialize, Serialize};

/// A single issue discovered in the scanned sources.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Stable rule identifier, e.g. `WP001`.
    pub rule_id: String,
    /// Short human readable title.
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    /// CWE identifier, when the rule maps to one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwe: Option<u32>,
    /// Path relative to the scan root, using forward slashes.
    pub file: String,
    /// 1-based line number.
    pub line: u32,
    /// 1-based column number.
    pub column: u32,
    /// Enclosing function or method, when the rule could determine it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    /// The offending source line, trimmed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
    /// Why this is a problem.
    pub message: String,
    /// What to do about it.
    pub remediation: String,
    /// Links to further reading.
    #[serde(default)]
    pub references: Vec<String>,
    /// Stable identity of this finding, used for baselining.
    pub fingerprint: String,
}

impl Finding {
    /// Compute a fingerprint that survives line-number churn.
    ///
    /// Baselines must keep matching when unrelated edits shift code around, so
    /// the fingerprint is built from the rule, the file, the enclosing symbol
    /// and a normalised snippet rather than the line number.
    pub fn fingerprint(
        rule_id: &str,
        file: &str,
        symbol: Option<&str>,
        snippet: Option<&str>,
    ) -> String {
        let mut key = String::new();
        key.push_str(rule_id);
        key.push('\u{1}');
        key.push_str(file);
        key.push('\u{1}');
        key.push_str(symbol.unwrap_or(""));
        key.push('\u{1}');
        if let Some(s) = snippet {
            key.push_str(&normalize_snippet(s));
        }
        format!("{:016x}", fnv1a64(key.as_bytes()))
    }
}

/// Collapse whitespace so that reformatting does not change a fingerprint.
fn normalize_snippet(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut last_space = true;
    for ch in s.chars() {
        if ch.is_whitespace() {
            if !last_space {
                out.push(' ');
                last_space = true;
            }
        } else {
            out.push(ch);
            last_space = false;
        }
    }
    while out.ends_with(' ') {
        out.pop();
    }
    out
}

/// FNV-1a, 64 bit. Small, dependency free, and stable across runs and
/// platforms, which is exactly what a baseline file needs.
pub fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_stable_across_whitespace_changes() {
        let a = Finding::fingerprint("WP001", "a.php", Some("f"), Some("$x = 1;"));
        let b = Finding::fingerprint("WP001", "a.php", Some("f"), Some("$x   =   1;"));
        assert_eq!(a, b);
    }

    #[test]
    fn fingerprint_changes_with_rule_and_file() {
        let a = Finding::fingerprint("WP001", "a.php", None, None);
        let b = Finding::fingerprint("WP002", "a.php", None, None);
        let c = Finding::fingerprint("WP001", "b.php", None, None);
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn fingerprint_is_sixteen_hex_digits() {
        let a = Finding::fingerprint("WP001", "a.php", None, None);
        assert_eq!(a.len(), 16);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
