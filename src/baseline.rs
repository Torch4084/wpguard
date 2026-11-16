use crate::finding::Finding;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// A record of findings that are already known and accepted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    /// Baseline format version.
    pub version: u32,
    /// When the baseline was written.
    #[serde(default)]
    pub generated_at: String,
    /// The recorded findings.
    #[serde(default)]
    pub findings: Vec<BaselineEntry>,
}

/// One recorded finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineEntry {
    /// The fingerprint that identifies the finding.
    pub fingerprint: String,
    pub rule_id: String,
    pub file: String,
    pub line: u32,
}

impl Baseline {
    /// The fingerprints present in this baseline.
    pub fn fingerprints(&self) -> Vec<&str> {
        self.findings
            .iter()
            .map(|e| e.fingerprint.as_str())
            .collect()
    }

    /// Build a baseline from a set of findings.
    pub fn from_findings(findings: &[Finding]) -> Baseline {
        Baseline {
            version: 1,
            generated_at: timestamp(),
            findings: findings
                .iter()
                .map(|f| BaselineEntry {
                    fingerprint: f.fingerprint.clone(),
                    rule_id: f.rule_id.clone(),
                    file: f.file.clone(),
                    line: f.line,
                })
                .collect(),
        }
    }

    /// Read a baseline file.
    pub fn load(path: &Path) -> Result<Baseline> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("could not read baseline {}", path.display()))?;
        let baseline: Baseline = serde_json::from_str(&text)
            .with_context(|| format!("could not parse baseline {}", path.display()))?;
        Ok(baseline)
    }

    /// Write a baseline file.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).ok();
            }
        }
        let text = serde_json::to_string_pretty(self)?;
        std::fs::write(path, format!("{text}\n"))
            .with_context(|| format!("could not write baseline {}", path.display()))?;
        Ok(())
    }
}

/// Drop the findings that are already recorded in the baseline.
pub fn filter(findings: Vec<Finding>, baseline: &Baseline) -> Vec<Finding> {
    let known = baseline.fingerprints();
    findings
        .into_iter()
        .filter(|f| !known.contains(&f.fingerprint.as_str()))
        .collect()
}

/// A UTC timestamp, without pulling in a date time crate.
fn timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("unix:{secs}")
}
