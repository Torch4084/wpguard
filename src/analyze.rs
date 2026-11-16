use crate::finding::Finding;
use crate::php::ast::{self, CallTarget};
use crate::php::{Callback, PhpFile, ProjectIndex, Span};
use crate::rule::Rule;
use std::collections::HashSet;
use tree_sitter::Node;

/// Calls that indicate a handler checks who is allowed to run it.
pub const AUTHZ_MARKERS: &[&str] = &[
    "current_user_can",
    "is_user_logged_in",
    "get_current_user_id",
    "wp_get_current_user",
    "is_admin",
    "check_admin_referer",
    "has_cap",
    "is_super_admin",
    "user_can",
];

/// Calls that verify a request actually came from this site.
pub const NONCE_MARKERS: &[&str] = &[
    "check_ajax_referer",
    "wp_verify_nonce",
    "verify_nonce",
    "check_admin_referer",
];

/// Read-only view of the analysed project that rules query.
pub struct Context<'a> {
    pub files: &'a [PhpFile],
    pub index: &'a ProjectIndex,
}

impl<'a> Context<'a> {
    /// Re-acquire a node from a byte span.
    pub fn node_at(&self, file_idx: usize, span: Span) -> Option<Node<'a>> {
        let file = self.files.get(file_idx)?;
        file.tree
            .root_node()
            .descendant_for_byte_range(span.start, span.end)
    }

    /// The source lines a node covers, trimmed. A node that spans several
    /// lines keeps the first few so the report shows enough context to
    /// recognise the code.
    pub fn snippet_at(&self, file_idx: usize, node: Node<'_>) -> Option<String> {
        let file = self.files.get(file_idx)?;
        let start = node.start_position().row;
        let end = node.end_position().row.min(start + 2);
        let mut lines = Vec::new();
        for row in start..=end {
            let Some(line) = file.source.lines().nth(row) else {
                break;
            };
            lines.push(line.trim().to_string());
        }
        let snippet = lines.join("\n").trim().to_string();
        if snippet.is_empty() {
            None
        } else {
            Some(snippet)
        }
    }

    /// The function or method a node sits inside.
    pub fn enclosing_symbol(&self, file_idx: usize, node: Node<'_>) -> Option<String> {
        let file = self.files.get(file_idx)?;
        ast::enclosing_function(node, &file.source).map(|(name, _)| name)
    }

    /// The source of a file.
    pub fn source(&self, file_idx: usize) -> &'a str {
        self.files
            .get(file_idx)
            .map(|f| f.source.as_str())
            .unwrap_or("")
    }
}

/// Does the handler behind this callback perform any authorization or CSRF
/// check?
///
/// The check looks at the handler body and, one level deeper, at any global
/// function it delegates to. Anything beyond that is left alone rather than
/// guessed at.
pub fn handler_is_protected(ctx: &Context<'_>, callback: &Callback, file: usize) -> bool {
    let mut visited = HashSet::new();
    handler_contains(
        ctx,
        callback,
        file,
        AUTHZ_MARKERS,
        NONCE_MARKERS,
        2,
        &mut visited,
    )
}

/// Does the handler behind this callback verify a nonce?
pub fn handler_has_nonce(ctx: &Context<'_>, callback: &Callback, file: usize) -> bool {
    let mut visited = HashSet::new();
    handler_contains(ctx, callback, file, NONCE_MARKERS, &[], 2, &mut visited)
}

fn handler_contains(
    ctx: &Context<'_>,
    callback: &Callback,
    file: usize,
    primary: &[&str],
    secondary: &[&str],
    depth: u32,
    visited: &mut HashSet<String>,
) -> bool {
    let Some((file_idx, span)) = ctx.index.resolve_body(callback, file) else {
        return false;
    };
    let Some(node) = ctx.node_at(file_idx, span) else {
        return false;
    };
    let src = ctx.source(file_idx);

    let mut delegated: Vec<String> = Vec::new();
    for call in ast::walk_calls_in_scope(node) {
        let Some(target) = ast::call_target(call, src) else {
            continue;
        };
        let name = target.name();
        if primary.contains(&name.as_str()) || secondary.contains(&name.as_str()) {
            return true;
        }
        if let CallTarget::Function(fname) = target {
            delegated.push(fname);
        }
    }

    if depth == 0 {
        return false;
    }
    for fname in delegated {
        let key = fname.to_lowercase();
        if primary.contains(&key.as_str()) || secondary.contains(&key.as_str()) {
            continue;
        }
        if !visited.insert(key) {
            continue;
        }
        if handler_contains(
            ctx,
            &Callback::Function(fname),
            file_idx,
            primary,
            secondary,
            depth - 1,
            visited,
        ) {
            return true;
        }
    }
    false
}

/// Run every rule over the project.
pub fn analyze(files: &[PhpFile], rules: &[Box<dyn Rule>]) -> Vec<Finding> {
    let index = crate::php::build_index(files);
    let ctx = Context {
        files,
        index: &index,
    };
    let mut findings = Vec::new();
    for rule in rules {
        findings.extend(rule.check(&ctx));
    }
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.rule_id.cmp(&b.rule_id))
    });
    findings
}
