use crate::analyze::Context;
use crate::finding::Finding;
use crate::php::ast::{self, CallTarget};
use crate::rule::{finding_from_meta, Rule, RuleMeta};
use crate::severity::{Confidence, Severity};
use crate::taint;
use std::collections::HashSet;
use tree_sitter::Node;

const WPDB_METHODS: &[&str] = &["query", "get_results", "get_var", "get_row", "get_col"];

/// `$wpdb->query()` and friends, called without `prepare()`.
pub struct UnpreparedDatabaseQuery;

static META_SQL: RuleMeta = RuleMeta {
    id: "WP010",
    title: "Database query built without prepared statements",
    severity: Severity::High,
    confidence: Confidence::High,
    cwe: Some(89),
    description: "A value is concatenated into a SQL statement instead of being bound as a \
                  parameter. When the value comes from the request this is SQL injection.",
    remediation: "Use `$wpdb->prepare( 'SELECT ... WHERE id = %d', $id )` so that every value is \
                  escaped and bound separately from the query text.",
    references: &[
        "https://developer.wordpress.org/reference/classes/wpdb/prepare/",
        "https://developer.wordpress.org/apis/security/checking-user-data/",
        "https://owasp.org/www-community/attacks/SQL_Injection",
    ],
};

impl Rule for UnpreparedDatabaseQuery {
    fn meta(&self) -> &RuleMeta {
        &META_SQL
    }

    fn check(&self, ctx: &Context<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for (file_idx, file) in ctx.files.iter().enumerate() {
            let src = file.source.as_str();
            let root = file.tree.root_node();

            for call in ast::walk_calls(root) {
                let Some(CallTarget::Method { object, method }) = ast::call_target(call, src)
                else {
                    continue;
                };
                if !object.to_lowercase().ends_with("wpdb") {
                    continue;
                }
                let method = method.to_lowercase();
                if !WPDB_METHODS.contains(&method.as_str()) {
                    continue;
                }
                let Some(arg) = ast::arg(call, src, 0) else {
                    continue;
                };
                let scope = scope_tainted(ctx, file_idx, call, src);
                let prepared = scope_prepared(ctx, file_idx, call, src);
                if is_prepared(arg, src, &prepared) {
                    continue;
                }
                let is_tainted = taint::is_tainted(arg, src, &scope);
                let mut finding = finding_from_meta(
                    &META_SQL,
                    ctx,
                    file_idx,
                    call,
                    format!(
                        "`{}` is called with a value that is not bound through `prepare()`.",
                        method
                    ),
                );
                if !is_tainted {
                    finding.severity = Severity::Medium;
                    finding.confidence = Confidence::Medium;
                }
                out.push(finding);
            }
        }
        out
    }
}

/// Is this argument already a safely prepared query?
fn is_prepared(arg: Node<'_>, src: &str, prepared: &HashSet<String>) -> bool {
    if ast::is_literal_string(arg, src) {
        return true;
    }
    if ast::is_call(arg) {
        if let Some(CallTarget::Method { method, .. }) = ast::call_target(arg, src) {
            if method.eq_ignore_ascii_case("prepare") {
                return true;
            }
        }
    }
    arg.kind() == "variable_name" && prepared.contains(ast::text(arg, src))
}

/// `unserialize()` on data that came from the request.
pub struct UnserializeOfUserInput;

static META_UNSERIALIZE: RuleMeta = RuleMeta {
    id: "WP011",
    title: "unserialize() applied to request data",
    severity: Severity::High,
    confidence: Confidence::High,
    cwe: Some(502),
    description: "`unserialize()` turns a string back into a PHP object. When the string came \
                  from the request, an attacker controls the class that gets instantiated, which \
                  can lead to object injection and remote code execution.",
    remediation: "Use `json_decode()` instead. If a PHP object graph really is required, use \
                  `unserialize( $value, [ 'allowed_classes' => false ] )` and never feed it \
                  untrusted input.",
    references: &[
        "https://www.php.net/manual/en/function.unserialize.php",
        "https://owasp.org/www-community/attacks/InsecureDeserialization",
    ],
};

impl Rule for UnserializeOfUserInput {
    fn meta(&self) -> &RuleMeta {
        &META_UNSERIALIZE
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
                if name.to_lowercase() != "unserialize" {
                    continue;
                }
                let Some(arg) = ast::arg(call, src, 0) else {
                    continue;
                };
                let scope = scope_tainted(ctx, file_idx, call, src);
                if !taint::is_tainted(arg, src, &scope) {
                    continue;
                }
                out.push(finding_from_meta(
                    &META_UNSERIALIZE,
                    ctx,
                    file_idx,
                    call,
                    "Request data is passed to `unserialize()`, which lets the caller choose the \
                     class that gets instantiated."
                        .to_string(),
                ));
            }
        }
        out
    }
}

/// `eval()` and friends.
pub struct DynamicCodeEvaluation;

static META_EVAL: RuleMeta = RuleMeta {
    id: "WP012",
    title: "Dynamic code evaluation",
    severity: Severity::High,
    confidence: Confidence::High,
    cwe: Some(95),
    description: "`eval()`, `assert()` and `create_function()` execute PHP code that is built at \
                  runtime. If any part of that code comes from the request, the request becomes \
                  remote code execution.",
    remediation: "Replace the dynamic code with an explicit dispatch table, for example a match \
                  on a whitelist of allowed action names.",
    references: &[
        "https://www.php.net/manual/en/function.eval.php",
        "https://owasp.org/www-community/attacks/Remote_Code_Execution",
    ],
};

impl Rule for DynamicCodeEvaluation {
    fn meta(&self) -> &RuleMeta {
        &META_EVAL
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
                let arg = ast::arg(call, src, 0);
                match name.as_str() {
                    "eval" => {
                        let is_literal = arg.map(|a| a.kind() == "string").unwrap_or(false);
                        let mut finding = finding_from_meta(
                            &META_EVAL,
                            ctx,
                            file_idx,
                            call,
                            "`eval()` executes a string as PHP code.".to_string(),
                        );
                        if is_literal {
                            finding.severity = Severity::Medium;
                        }
                        out.push(finding);
                    }
                    "create_function" => {
                        let mut finding = finding_from_meta(
                            &META_EVAL,
                            ctx,
                            file_idx,
                            call,
                            "`create_function()` builds a function from a string and is deprecated \
                             in favour of anonymous functions."
                                .to_string(),
                        );
                        finding.severity = Severity::Medium;
                        out.push(finding);
                    }
                    "assert" => {
                        let Some(arg) = arg else { continue };
                        if arg.kind() != "string" {
                            continue;
                        }
                        let mut finding = finding_from_meta(
                            &META_EVAL,
                            ctx,
                            file_idx,
                            call,
                            "`assert()` evaluates a string as PHP when it is not a boolean \
                             expression."
                                .to_string(),
                        );
                        finding.severity = Severity::Medium;
                        out.push(finding);
                    }
                    _ => {}
                }
            }
        }
        out
    }
}

/// `include` / `require` with a path that is not known at parse time.
pub struct DynamicFileInclusion;

static META_INCLUDE: RuleMeta = RuleMeta {
    id: "WP013",
    title: "File inclusion with a dynamic path",
    severity: Severity::High,
    confidence: Confidence::Medium,
    cwe: Some(98),
    description: "The path handed to `include` or `require` is only known at runtime. If any part \
                  of it can be influenced, an attacker can make the server load a file of their \
                  choosing, which is remote file inclusion and often remote code execution.",
    remediation: "Build the path from a fixed set of known files, and check the result with \
                  `realpath()` against a directory you control before including it.",
    references: &[
        "https://www.php.net/manual/en/function.include.php",
        "https://owasp.org/www-community/attacks/Remote_File_Include",
    ],
};

impl Rule for DynamicFileInclusion {
    fn meta(&self) -> &RuleMeta {
        &META_INCLUDE
    }

    fn check(&self, ctx: &Context<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for (file_idx, file) in ctx.files.iter().enumerate() {
            let src = file.source.as_str();
            let root = file.tree.root_node();
            let mut stack = vec![root];
            while let Some(node) = stack.pop() {
                if is_inclusion(node) {
                    let mut cursor = node.walk();
                    let target = node.named_children(&mut cursor).next();
                    if let Some(target) = target {
                        if ast::contains_variable(target, src) {
                            out.push(finding_from_meta(
                                &META_INCLUDE,
                                ctx,
                                file_idx,
                                node,
                                "The included path is only known at runtime.".to_string(),
                            ));
                        }
                    }
                }
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    stack.push(child);
                }
            }
        }
        out
    }
}

fn is_inclusion(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "include_expression"
            | "require_expression"
            | "include_once_expression"
            | "require_once_expression"
    )
}

/// Output that echoes request data without escaping it.
pub struct UnescapedOutput;

static META_XSS: RuleMeta = RuleMeta {
    id: "WP014",
    title: "Request data echoed without escaping",
    severity: Severity::Medium,
    confidence: Confidence::High,
    cwe: Some(79),
    description: "A value from the request is written straight into the response. Without an \
                  escaping function the value can carry HTML or JavaScript, which turns the page \
                  into a cross-site scripting vector.",
    remediation: "Wrap the value in `esc_html()`, `esc_attr()`, `esc_url()` or `wp_kses()` \
                  depending on where it is printed.",
    references: &[
        "https://developer.wordpress.org/apis/security/escaping/",
        "https://owasp.org/www-community/attacks/xss/",
    ],
};

impl Rule for UnescapedOutput {
    fn meta(&self) -> &RuleMeta {
        &META_XSS
    }

    fn check(&self, ctx: &Context<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for (file_idx, file) in ctx.files.iter().enumerate() {
            let src = file.source.as_str();
            let root = file.tree.root_node();
            let mut stack = vec![root];
            while let Some(node) = stack.pop() {
                if matches!(node.kind(), "echo_statement" | "print_statement") {
                    let mut cursor = node.walk();
                    let values: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
                    for value in values {
                        if !ast::contains_superglobal(value, src) {
                            continue;
                        }
                        if taint::is_escaped(value, src) {
                            continue;
                        }
                        out.push(finding_from_meta(
                            &META_XSS,
                            ctx,
                            file_idx,
                            node,
                            "Request data is printed without an escaping function.".to_string(),
                        ));
                        break;
                    }
                }
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    stack.push(child);
                }
            }
        }
        out
    }
}

/// A redirect whose destination is taken from the request.
pub struct OpenRedirect;

static META_REDIRECT: RuleMeta = RuleMeta {
    id: "WP015",
    title: "Redirect to a request controlled URL",
    severity: Severity::Medium,
    confidence: Confidence::High,
    cwe: Some(601),
    description: "The redirect target is taken from the request, so an attacker can send a \
                  visitor to a page of their choosing using a link that looks like it belongs to \
                  the site.",
    remediation: "Use `wp_safe_redirect()`, which only redirects to hosts on the allow list, or \
                  compare the target against a list of permitted paths first.",
    references: &[
        "https://developer.wordpress.org/reference/functions/wp_safe_redirect/",
        "https://owasp.org/www-community/attacks/Redirect_Server_Side_Request_Forgery",
    ],
};

impl Rule for OpenRedirect {
    fn meta(&self) -> &RuleMeta {
        &META_REDIRECT
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
                let is_redirect = matches!(name.as_str(), "wp_redirect" | "header");
                if !is_redirect {
                    continue;
                }
                let Some(arg) = ast::arg(call, src, 0) else {
                    continue;
                };
                if name == "header" && !ast::text(arg, src).to_lowercase().contains("location") {
                    continue;
                }
                let scope = scope_tainted(ctx, file_idx, call, src);
                if !taint::is_tainted(arg, src, &scope) {
                    continue;
                }
                out.push(finding_from_meta(
                    &META_REDIRECT,
                    ctx,
                    file_idx,
                    call,
                    "The redirect target comes from the request.".to_string(),
                ));
            }
        }
        out
    }
}

/// The tainted variables of the function scope a node belongs to.
fn scope_tainted(ctx: &Context<'_>, file_idx: usize, node: Node<'_>, src: &str) -> HashSet<String> {
    scope_variables(ctx, file_idx, node, src, taint::tainted_variables)
}

/// The prepared-query variables of the function scope a node belongs to.
fn scope_prepared(
    ctx: &Context<'_>,
    file_idx: usize,
    node: Node<'_>,
    src: &str,
) -> HashSet<String> {
    scope_variables(ctx, file_idx, node, src, taint::prepared_variables)
}

fn scope_variables(
    ctx: &Context<'_>,
    file_idx: usize,
    node: Node<'_>,
    src: &str,
    collect: fn(&str, Node<'_>) -> HashSet<String>,
) -> HashSet<String> {
    match ast::enclosing_function(node, src) {
        Some((_, span)) => match ctx.node_at(file_idx, span) {
            Some(body) => collect(src, body),
            None => HashSet::new(),
        },
        None => HashSet::new(),
    }
}
