pub mod console;
pub mod json;
pub mod markdown;
pub mod sarif;

use crate::finding::Finding;
use std::path::PathBuf;
use std::time::Duration;

/// Everything a reporter needs to know about a completed scan.
pub struct ScanSummary {
    /// The directory the paths were scanned relative to.
    pub root: PathBuf,
    /// How many PHP files were parsed.
    pub files_scanned: usize,
    /// How many files were skipped because of a parse error.
    pub files_skipped: usize,
    /// The findings, most severe first.
    pub findings: Vec<Finding>,
    /// How long the scan took.
    pub elapsed: Duration,
}

impl ScanSummary {
    /// Count of findings per severity.
    pub fn severity_counts(&self) -> Vec<(&'static str, usize)> {
        use crate::severity::Severity;
        let mut counts = Vec::new();
        for severity in Severity::ALL.iter().rev() {
            let n = self
                .findings
                .iter()
                .filter(|f| f.severity == *severity)
                .count();
            if n > 0 {
                counts.push((severity.as_str(), n));
            }
        }
        counts
    }
}
