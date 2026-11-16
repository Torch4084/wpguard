use crate::report::ScanSummary;
use crate::rule::Rule;
use crate::severity::Severity;
use serde_json::json;
use std::io::Write;

/// Render the findings as SARIF 2.1.0, so that GitHub code scanning can
/// display them straight on a pull request.
pub fn write(
    out: &mut impl Write,
    summary: &ScanSummary,
    rules: &[Box<dyn Rule>],
) -> std::io::Result<()> {
    let mut rule_descriptors = Vec::new();
    for rule in rules {
        let meta = rule.meta();
        let mut tags = vec!["security".to_string(), format!("wpguard/{}", meta.id)];
        if let Some(cwe) = meta.cwe {
            tags.push(format!("CWE-{cwe}"));
        }
        tags.push(format!("external/cwe/{}", meta.cwe.unwrap_or(0)));
        rule_descriptors.push(json!({
            "id": meta.id,
            "name": meta.title,
            "shortDescription": { "text": meta.title },
            "fullDescription": { "text": meta.description },
            "help": { "text": meta.remediation },
            "helpUri": meta.references.first().copied().unwrap_or("https://github.com/Torch4084/wpguard"),
            "defaultConfiguration": {
                "level": sarif_level(meta.severity),
                "rank": sarif_rank(meta.severity),
            },
            "properties": {
                "tags": tags,
                "precision": meta.confidence.as_str(),
                "security-severity": security_severity(meta.severity).to_string(),
                "problem.severity": meta.severity.as_str(),
            },
        }));
    }

    let results: Vec<_> = summary
        .findings
        .iter()
        .map(|finding| {
            json!({
                "ruleId": finding.rule_id,
                "level": sarif_level(finding.severity),
                "message": { "text": format!("{}: {}", finding.title, finding.message) },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": { "uri": finding.file },
                            "region": {
                                "startLine": finding.line,
                                "startColumn": finding.column,
                            }
                        }
                    }
                ],
                "partialFingerprints": {
                    "wpguard/v1": finding.fingerprint,
                },
                "properties": {
                    "confidence": finding.confidence.as_str(),
                    "security-severity": security_severity(finding.severity).to_string(),
                }
            })
        })
        .collect();

    let document = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "wpguard",
                        "version": env!("CARGO_PKG_VERSION"),
                        "semanticVersion": env!("CARGO_PKG_VERSION"),
                        "informationUri": "https://github.com/Torch4084/wpguard",
                        "rules": rule_descriptors,
                    }
                },
                "results": results,
            }
        ]
    });

    let rendered = serde_json::to_string_pretty(&document).unwrap_or_else(|_| "{}".to_string());
    writeln!(out, "{rendered}")
}

fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

fn sarif_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Critical => 100,
        Severity::High => 80,
        Severity::Medium => 50,
        Severity::Low => 20,
    }
}

/// A rough CVSS-like number so that GitHub can sort the findings.
fn security_severity(severity: Severity) -> f64 {
    match severity {
        Severity::Critical => 9.5,
        Severity::High => 7.5,
        Severity::Medium => 5.0,
        Severity::Low => 2.5,
    }
}
