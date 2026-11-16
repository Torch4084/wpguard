use crate::php::ast;
use std::collections::HashSet;
use tree_sitter::Node;

/// Names that indicate a value is security sensitive.
pub const SENSITIVE_WORDS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "nonce",
    "salt",
    "passphrase",
    "session_id",
    "api_key",
];

/// Variables in a scope that were assigned straight from a superglobal.
///
/// This is a deliberately shallow analysis: one assignment hop. It catches the
/// common `$x = $_POST['id'];` shape without pretending to be a dataflow
/// engine.
pub fn tainted_variables(src: &str, root: Node<'_>) -> HashSet<String> {
    let mut out = HashSet::new();
    let mut stack = vec![root];
    while let Some(n) = stack.pop() {
        if n.kind() == "assignment_expression" {
            if let (Some(left), Some(right)) = (
                n.child_by_field_name("left"),
                n.child_by_field_name("right"),
            ) {
                if left.kind() == "variable_name" && ast::contains_superglobal(right, src) {
                    out.insert(ast::text(left, src).to_string());
                }
            }
        }
        let mut cursor = n.walk();
        for child in n.children(&mut cursor) {
            stack.push(child);
        }
    }
    out
}

/// Does this expression carry attacker controlled data?
pub fn is_tainted(node: Node<'_>, src: &str, tainted: &HashSet<String>) -> bool {
    if ast::contains_superglobal(node, src) {
        return true;
    }
    let mut stack = vec![node];
    while let Some(n) = stack.pop() {
        if n.kind() == "variable_name" && tainted.contains(ast::text(n, src)) {
            return true;
        }
        let mut cursor = n.walk();
        for child in n.children(&mut cursor) {
            stack.push(child);
        }
    }
    false
}

/// Is the tainted part of an expression routed through an escaping function?
///
/// Only the arguments of the escaping call count. `esc_html($_GET['x']) . $_GET['y']`
/// is therefore still reported, because the second value is not escaped.
pub fn is_escaped(node: Node<'_>, src: &str) -> bool {
    for call in ast::walk_calls(node) {
        let Some(target) = ast::call_target(call, src) else {
            continue;
        };
        let name = target.name();
        let safe = name.starts_with("esc_")
            || name.starts_with("wp_kses")
            || name.starts_with("sanitize_")
            || matches!(
                name.as_str(),
                "absint"
                    | "intval"
                    | "floatval"
                    | "boolval"
                    | "number_format"
                    | "json_encode"
                    | "wp_json_encode"
            );
        if !safe {
            continue;
        }
        if ast::args(call, src)
            .iter()
            .any(|arg| ast::contains_superglobal(*arg, src))
        {
            return true;
        }
    }
    false
}

/// Variables in a scope that were assigned from a `prepare()` call. Those
/// queries are already safely bound.
pub fn prepared_variables(src: &str, root: Node<'_>) -> HashSet<String> {
    let mut out = HashSet::new();
    let mut stack = vec![root];
    while let Some(n) = stack.pop() {
        if n.kind() == "assignment_expression" {
            if let (Some(left), Some(right)) = (
                n.child_by_field_name("left"),
                n.child_by_field_name("right"),
            ) {
                if left.kind() == "variable_name" && is_prepare_call(right, src) {
                    out.insert(ast::text(left, src).to_string());
                }
            }
        }
        let mut cursor = n.walk();
        for child in n.children(&mut cursor) {
            stack.push(child);
        }
    }
    out
}

/// Is this expression a call to `$wpdb->prepare()`?
pub fn is_prepare_call(node: Node<'_>, src: &str) -> bool {
    if !ast::is_call(node) {
        return false;
    }
    match ast::call_target(node, src) {
        Some(ast::CallTarget::Method { method, .. }) => method.eq_ignore_ascii_case("prepare"),
        _ => false,
    }
}

/// Does the text of a scope mention any security sensitive word?
pub fn mentions_sensitive_word(text: &str) -> bool {
    let lowered = text.to_lowercase();
    SENSITIVE_WORDS.iter().any(|w| lowered.contains(w))
}
