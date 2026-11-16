use crate::report::ScanSummary;
use std::io::Write;

const RESET: &str = "\x1b[0m";
const DIM: &str = "\x1b[2m";
const BOLD: &str = "\x1b[1m";

/// Render the findings for a terminal.
pub fn write(out: &mut impl Write, summary: &ScanSummary) -> std::io::Result<()> {
    writeln!(
        out,
        "{BOLD}wpguard{RESET} {DIM}· scanned {} file(s) in {} ms{RESET}",
        summary.files_scanned,
        summary.elapsed.as_millis()
    )?;

    if summary.findings.is_empty() {
        writeln!(out, "\n\x1b[32mNo issues found.\x1b[0m")?;
        return Ok(());
    }

    let mut current_file = String::new();
    for finding in &summary.findings {
        if finding.file != current_file {
            current_file = finding.file.clone();
            writeln!(out, "\n{BOLD}{current_file}{RESET}")?;
        }
        let severity = finding.severity;
        writeln!(
            out,
            "  {}:{} {:<8} {}  {DIM}{}{RESET}",
            finding.line,
            finding.column,
            format!("{}{}", severity.color(), severity.label()),
            finding.rule_id,
            finding.title,
        )?;
        if let Some(snippet) = &finding.snippet {
            writeln!(out, "    {DIM}{snippet}{RESET}")?;
        }
        writeln!(out, "    {DIM}{}{RESET}", finding.message)?;
        if let Some(symbol) = &finding.symbol {
            writeln!(out, "    {DIM}in {symbol}{RESET}")?;
        }
        let cwe = finding
            .cwe
            .map(|c| format!("CWE-{c}"))
            .unwrap_or_else(|| "no CWE".to_string());
        writeln!(
            out,
            "    {DIM}{cwe} · confidence {}{RESET}",
            finding.confidence
        )?;
        writeln!(out, "    {DIM}fix:{RESET} {}", finding.remediation)?;
    }

    writeln!(out)?;
    let total = summary.findings.len();
    let parts: Vec<String> = summary
        .severity_counts()
        .into_iter()
        .map(|(name, n)| format!("{n} {name}"))
        .collect();
    let breakdown = if parts.is_empty() {
        String::new()
    } else {
        format!(" ({})", parts.join(", "))
    };
    writeln!(out, "{BOLD}{total} finding(s){RESET}{breakdown}",)?;

    Ok(())
}
