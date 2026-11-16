use crate::analyze::Context;
use crate::finding::Finding;
use crate::php::ast::{self, CallTarget};
use crate::rule::{finding_from_meta, Rule, RuleMeta};
use crate::severity::{Confidence, Severity};
use crate::taint;
use std::collections::HashSet;
use tree_sitter::Node;

/// Calls that confirm an uploaded file is an acceptable type.
const TYPE_CHECKS: &[&str] = &[
    "wp_check_filetype",
    "wp_check_filetype_and_ext",
    "get_allowed_mime_types",
    "wp_get_mime_types",
    "wp_handle_upload",
    "media_handle_upload",
];

/// Functions that fetch a URL.
const FETCH_FUNCTIONS: &[&str] = &[
    "file_get_contents",
    "fopen",
    "readfile",
    "file",
    "wp_remote_get",
    "wp_remote_post",
    "wp_remote_request",
    "wp_safe_remote_get",
    "wp_safe_remote_post",
    "wp_remote_head",
];

/// An uploaded file that is stored without checking its type.
pub struct UploadWithoutTypeCheck;

static META_UPLOAD: RuleMeta = RuleMeta {
    id: "WP020",
    title: "Uploaded file stored without a type check",
    severity: Severity::High,
    confidence: Confidence::Medium,
    cwe: Some(434),
    description: "The file is moved into place without first confirming that it is an allowed \
                  type. A name that ends in `.jpg` proves nothing about the bytes behind it, and \
                  a web shell disguised as an image ends up inside the web root.",
    remediation: "Check the file type with `wp_check_filetype_and_ext()` before moving it, keep \
                  the extension and the MIME type in agreement, and store uploads outside the \
                  web root when possible.",
    references: &[
        "https://developer.wordpress.org/reference/functions/wp_check_filetype_and_ext/",
        "https://owasp.org/www-community/attacks/Unrestricted_File_Upload",
    ],
};

impl Rule for UploadWithoutTypeCheck {
    fn meta(&self) -> &RuleMeta {
        &META_UPLOAD
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
                if name.to_lowercase() != "move_uploaded_file" {
                    continue;
                }
                if scope_validates_type(ctx, file_idx, call, src) {
                    continue;
                }
                out.push(finding_from_meta(
                    &META_UPLOAD,
                    ctx,
                    file_idx,
                    call,
                    "The uploaded file is moved into place without any check on its type."
                        .to_string(),
                ));
            }
        }
        out
    }
}

fn scope_validates_type(ctx: &Context<'_>, file_idx: usize, node: Node<'_>, src: &str) -> bool {
    let Some((_, span)) = ast::enclosing_function(node, src) else {
        return false;
    };
    let Some(body) = ctx.node_at(file_idx, span) else {
        return false;
    };
    ast::walk_calls_in_scope(body).iter().any(|call| {
        ast::call_target(*call, src)
            .map(|t| TYPE_CHECKS.contains(&t.name().as_str()))
            .unwrap_or(false)
    })
}

/// A URL built from request data and fetched by the server.
pub struct RequestControlledUrlFetch;

static META_SSRF: RuleMeta = RuleMeta {
    id: "WP021",
    title: "Server side request to a request controlled URL",
    severity: Severity::Medium,
    confidence: Confidence::Medium,
    cwe: Some(918),
    description: "The URL the server fetches is taken from the request. An attacker can point \
                  the server at internal addresses such as `169.254.169.254` or at services that \
                  are only reachable from the server itself.",
    remediation: "Validate the host against an allow list before fetching, and reject anything \
                  that resolves to a private or link local address.",
    references: &[
        "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
        "https://developer.wordpress.org/reference/functions/wp_safe_remote_get/",
    ],
};

impl Rule for RequestControlledUrlFetch {
    fn meta(&self) -> &RuleMeta {
        &META_SSRF
    }

    fn check(&self, ctx: &Context<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for (file_idx, file) in ctx.files.iter().enumerate() {
            let src = file.source.as_str();
            let root = file.tree.root_node();

            for call in ast::walk_calls(root) {
                let Some(target) = ast::call_target(call, src) else {
                    continue;
                };
                let (arg_index, label) = match &target {
                    CallTarget::Function(name) => {
                        let lower = name.to_lowercase();
                        if !FETCH_FUNCTIONS.contains(&lower.as_str()) {
                            continue;
                        }
                        (0, lower)
                    }
                    CallTarget::Method { method, .. } => {
                        if !method.eq_ignore_ascii_case("setopt") {
                            continue;
                        }
                        let Some(option) = ast::arg(call, src, 1) else {
                            continue;
                        };
                        if !ast::text(option, src)
                            .to_uppercase()
                            .contains("CURLOPT_URL")
                        {
                            continue;
                        }
                        (2, "curl_setopt".to_string())
                    }
                    CallTarget::Scoped { .. } => continue,
                };

                let Some(arg) = ast::arg(call, src, arg_index) else {
                    continue;
                };
                let scope = scope_tainted(ctx, file_idx, call, src);
                if !taint::is_tainted(arg, src, &scope) {
                    continue;
                }
                out.push(finding_from_meta(
                    &META_SSRF,
                    ctx,
                    file_idx,
                    call,
                    format!("`{label}` fetches a URL that comes from the request."),
                ));
            }
        }
        out
    }
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
