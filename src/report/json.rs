use crate::report::ScanSummary;
use serde_json::json;
use std::io::Write;

/// Render the findings as JSON, for tooling that wants to consume them.
pub fn write(out: &mut impl Write, summary: &ScanSummary) -> std::io::Result<()> {
    let findings: Vec<_> = summary
        .findings
        .iter()
        .map(|f| serde_json::to_value(f).unwrap())
        .collect();
    let severities: serde_json::Map<String, serde_json::Value> = summary
        .severity_counts()
        .into_iter()
        .map(|(name, n)| (name.to_string(), json!(n)))
        .collect();

    let document = json!({
        "tool": "wpguard",
        "version": env!("CARGO_PKG_VERSION"),
        "root": summary.root.display().to_string(),
        "files_scanned": summary.files_scanned,
        "files_skipped": summary.files_skipped,
        "elapsed_ms": summary.elapsed.as_millis() as u64,
        "severity_counts": severities,
        "finding_count": summary.findings.len(),
        "findings": findings,
    });

    let rendered = serde_json::to_string_pretty(&document).unwrap_or_else(|_| "{}".to_string());
    writeln!(out, "{rendered}")
}
