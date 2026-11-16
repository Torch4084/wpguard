use crate::analyze::Context;
use crate::finding::Finding;
use crate::php::ast::{self, CallTarget};
use crate::rule::{finding_from_meta, Rule, RuleMeta};
use crate::severity::{Confidence, Severity};
use crate::taint;
use std::collections::HashSet;
use tree_sitter::Node;

const COMMAND_FUNCTIONS: &[&str] = &[
    "exec",
    "shell_exec",
    "system",
    "passthru",
    "popen",
    "proc_open",
    "pcntl_exec",
];

/// A shell command built at runtime.
pub struct CommandExecution;

static META_COMMAND: RuleMeta = RuleMeta {
    id: "PHP001",
    title: "Shell command built at runtime",
    severity: Severity::High,
    confidence: Confidence::Medium,
    cwe: Some(78),
    description: "The command is built at runtime and passed to a shell. When part of it comes \
                  from the request, a shell metacharacter is enough to run another command.",
    remediation: "Avoid the shell. Use `escapeshellarg()` on every value that goes into the \
                  command, and prefer a library function over shelling out.",
    references: &[
        "https://owasp.org/www-community/attacks/command_injection",
        "https://www.php.net/manual/en/function.escapeshellarg.php",
    ],
};

impl Rule for CommandExecution {
    fn meta(&self) -> &RuleMeta {
        &META_COMMAND
    }

    fn check(&self, ctx: &Context<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for (file_idx, file) in ctx.files.iter().enumerate() {
            let src = file.source.as_str();
            let root = file.tree.root_node();

            for call in ast::walk_calls(root) {
                let Some(CallTarget::Function(name)) = ast::call_target(call, src) else {
                    continue;
                };
                let name = name.to_lowercase();
                if !COMMAND_FUNCTIONS.contains(&name.as_str()) {
                    continue;
                }
                let Some(arg) = ast::arg(call, src, 0) else {
                    continue;
                };
                let scope = scope_tainted(ctx, file_idx, call, src);
                let tainted = taint::is_tainted(arg, src, &scope);
                let mut finding = finding_from_meta(
                    &META_COMMAND,
                    ctx,
                    file_idx,
                    call,
                    format!("`{name}()` runs a command that is built at runtime."),
                );
                if !tainted {
                    finding.severity = Severity::Medium;
                    finding.confidence = Confidence::Low;
                }
                out.push(finding);
            }
        }
        out
    }
}

/// TLS verification switched off.
pub struct TlsVerificationDisabled;

static META_TLS: RuleMeta = RuleMeta {
    id: "PHP002",
    title: "TLS certificate verification disabled",
    severity: Severity::High,
    confidence: Confidence::High,
    cwe: Some(295),
    description: "Certificate verification is switched off, so any machine on the network can \
                  present itself as the remote host and read or change the traffic.",
    remediation: "Leave `CURLOPT_SSL_VERIFYPEER` and `CURLOPT_SSL_VERIFYHOST` at their defaults. \
                  If a certificate is misconfigured, fix the certificate or point cURL at the \
                  right CA bundle.",
    references: &[
        "https://curl.se/libcurl/c/CURLOPT_SSL_VERIFYPEER.html",
        "https://curl.se/libcurl/c/CURLOPT_SSL_VERIFYHOST.html",
    ],
};

impl Rule for TlsVerificationDisabled {
    fn meta(&self) -> &RuleMeta {
        &META_TLS
    }

    fn check(&self, ctx: &Context<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for (file_idx, file) in ctx.files.iter().enumerate() {
            let src = file.source.as_str();
            let root = file.tree.root_node();

            for call in ast::walk_calls(root) {
                let Some(CallTarget::Function(name)) = ast::call_target(call, src) else {
                    continue;
                };
                if !name.eq_ignore_ascii_case("curl_setopt") {
                    continue;
                }
                let Some(option) = ast::arg(call, src, 1) else {
                    continue;
                };
                let Some(value) = ast::arg(call, src, 2) else {
                    continue;
                };
                let option = ast::text(option, src).to_uppercase();
                let disabled = match option.as_str() {
                    "CURLOPT_SSL_VERIFYPEER" => is_falsey(value, src),
                    "CURLOPT_SSL_VERIFYHOST" => is_zero(value, src),
                    _ => false,
                };
                if !disabled {
                    continue;
                }
                out.push(finding_from_meta(
                    &META_TLS,
                    ctx,
                    file_idx,
                    call,
                    format!("`{option}` is set to a value that disables certificate checks."),
                ));
            }
        }
        out
    }
}

fn is_falsey(value: Node<'_>, src: &str) -> bool {
    let text = ast::text(value, src).trim().to_lowercase();
    matches!(text.as_str(), "false" | "0" | "''" | "\"\"" | "null")
}

fn is_zero(value: Node<'_>, src: &str) -> bool {
    ast::text(value, src).trim() == "0"
}

fn scope_tainted(ctx: &Context<'_>, file_idx: usize, node: Node<'_>, src: &str) -> HashSet<String> {
    match ast::enclosing_function(node, src) {
        Some((_, span)) => match ctx.node_at(file_idx, span) {
            Some(body) => taint::tainted_variables(src, body),
            None => HashSet::new(),
        },
        None => HashSet::new(),
    }
}
