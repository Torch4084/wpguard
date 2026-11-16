use crate::finding::Finding;
use crate::severity::{Confidence, Severity};

/// Static description of a rule. Used by `wpguard rules`, `wpguard explain`
/// and by the SARIF reporter.
#[derive(Debug, Clone)]
pub struct RuleMeta {
    pub id: &'static str,
    pub title: &'static str,
    pub severity: Severity,
    pub confidence: Confidence,
    pub cwe: Option<u32>,
    pub description: &'static str,
    pub remediation: &'static str,
    pub references: &'static [&'static str],
}

/// A check that runs over the analysed project.
pub trait Rule: Send + Sync {
    fn meta(&self) -> &RuleMeta;

    /// Inspect the project and return any issues found.
    fn check(&self, ctx: &crate::analyze::Context<'_>) -> Vec<Finding>;
}

/// Helper for building a `Finding` from a rule's metadata.
pub(crate) fn finding_from_meta(
    meta: &RuleMeta,
    ctx: &crate::analyze::Context<'_>,
    file_idx: usize,
    node: tree_sitter::Node<'_>,
    message: String,
) -> Finding {
    let file = &ctx.files[file_idx];
    let snippet = ctx.snippet_at(file_idx, node);
    let symbol = ctx.enclosing_symbol(file_idx, node);
    let line = node.start_position().row as u32 + 1;
    let column = node.start_position().column as u32 + 1;
    let fingerprint =
        Finding::fingerprint(meta.id, &file.rel, symbol.as_deref(), snippet.as_deref());

    Finding {
        rule_id: meta.id.to_string(),
        title: meta.title.to_string(),
        severity: meta.severity,
        confidence: meta.confidence,
        cwe: meta.cwe,
        file: file.rel.clone(),
        line,
        column,
        symbol,
        snippet,
        message,
        remediation: meta.remediation.to_string(),
        references: meta.references.iter().map(|s| s.to_string()).collect(),
        fingerprint,
    }
}
