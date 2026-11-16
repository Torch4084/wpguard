use crate::report::ScanSummary;
use std::io::Write;

/// Render the findings as a Markdown report, suitable for a pull request
/// comment or a CI job summary.
pub fn write(out: &mut impl Write, summary: &ScanSummary) -> std::io::Result<()> {
    writeln!(out, "# wpguard report")?;
    writeln!(out)?;
    writeln!(
        out,
        "Scanned **{}** PHP file(s) in {} ms.",
        summary.files_scanned,
        summary.elapsed.as_millis()
    )?;
    writeln!(out)?;

    if summary.findings.is_empty() {
        writeln!(out, "No issues found.")?;
        return Ok(());
    }

    let counts = summary.severity_counts();
    if !counts.is_empty() {
        let mut parts = Vec::new();
        for (name, n) in counts {
            parts.push(format!("**{n}** {name}"));
        }
        writeln!(out, "Found: {}.", parts.join(", "))?;
        writeln!(out)?;
    }

    writeln!(out, "| Location | Severity | Rule | Issue |")?;
    writeln!(out, "|---|---|---|---|")?;
    for finding in &summary.findings {
        writeln!(
            out,
            "| `{}:{}` | {} | {} | {} |",
            finding.file,
            finding.line,
            finding.severity.label(),
            finding.rule_id,
            finding.title
        )?;
    }
    writeln!(out)?;

    writeln!(out, "## Details")?;
    for finding in &summary.findings {
        writeln!(out)?;
        writeln!(
            out,
            "### {} — `{}:{}`",
            finding.rule_id, finding.file, finding.line
        )?;
        writeln!(out)?;
        writeln!(out, "**{}**", finding.title)?;
        writeln!(out)?;
        writeln!(out, "{}", finding.message)?;
        writeln!(out)?;
        if let Some(snippet) = &finding.snippet {
            writeln!(out, "```php")?;
            writeln!(out, "{snippet}")?;
            writeln!(out, "```")?;
            writeln!(out)?;
        }
        writeln!(
            out,
            "- Severity: **{}** (confidence: {})",
            finding.severity.label(),
            finding.confidence
        )?;
        if let Some(cwe) = finding.cwe {
            writeln!(out, "- CWE: CWE-{cwe}")?;
        }
        if let Some(symbol) = &finding.symbol {
            writeln!(out, "- Location: `{symbol}`")?;
        }
        writeln!(out)?;
        writeln!(out, "**How to fix:** {}", finding.remediation)?;
        if !finding.references.is_empty() {
            writeln!(out)?;
            writeln!(out, "**Further reading:**")?;
            for reference in &finding.references {
                writeln!(out, "- {reference}")?;
            }
        }
    }

    Ok(())
}
