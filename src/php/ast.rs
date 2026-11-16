use crate::php::Span;
use tree_sitter::Node;

/// PHP superglobals. Reading any of these means the value came from the
/// client, which is the starting point for most web vulnerabilities.
pub const SUPERGLOBALS: &[&str] = &[
    "_GET", "_POST", "_REQUEST", "_COOKIE", "_SERVER", "_FILES", "_ENV", "_SESSION", "GLOBALS",
];

/// Source text of a node.
pub fn text<'a>(node: Node<'_>, src: &'a str) -> &'a str {
    node.utf8_text(src.as_bytes()).unwrap_or("")
}

/// Byte span of a node.
pub fn span(node: Node<'_>) -> Span {
    Span::of(node)
}

/// The callee of a call expression.
#[derive(Debug, Clone)]
pub enum CallTarget {
    /// `foo(...)`
    Function(String),
    /// `$obj->foo(...)`
    Method { object: String, method: String },
    /// `Cls::foo(...)`
    Scoped { method: String },
}

impl CallTarget {
    /// The bare callee name, lowercased.
    pub fn name(&self) -> String {
        match self {
            CallTarget::Function(n) => n.to_lowercase(),
            CallTarget::Method { method, .. } => method.to_lowercase(),
            CallTarget::Scoped { method, .. } => method.to_lowercase(),
        }
    }
}

/// Is this node a call expression of any flavour?
pub fn is_call(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "function_call_expression"
            | "member_call_expression"
            | "nullsafe_member_call_expression"
            | "scoped_call_expression"
    )
}

/// Resolve the callee of a call expression.
pub fn call_target(node: Node<'_>, src: &str) -> Option<CallTarget> {
    match node.kind() {
        "function_call_expression" => {
            let f = node.child_by_field_name("function")?;
            Some(CallTarget::Function(text(f, src).to_string()))
        }
        "member_call_expression" | "nullsafe_member_call_expression" => {
            let obj = node.child_by_field_name("object")?;
            let name = node.child_by_field_name("name")?;
            Some(CallTarget::Method {
                object: text(obj, src).to_string(),
                method: text(name, src).to_string(),
            })
        }
        "scoped_call_expression" => {
            let name = node.child_by_field_name("name")?;
            Some(CallTarget::Scoped {
                method: text(name, src).to_string(),
            })
        }
        _ => None,
    }
}

/// The argument expressions of a call expression, in order.
///
/// The tree-sitter grammar wraps every argument in an `argument` node. The
/// wrapper is stripped here so that callers get the expression itself, which
/// is what they actually want to inspect.
pub fn args<'t>(call: Node<'t>, _src: &str) -> Vec<Node<'t>> {
    match call.child_by_field_name("arguments") {
        Some(a) => {
            let mut c = a.walk();
            a.named_children(&mut c)
                .filter(|ch| ch.kind() == "argument")
                .map(|argument| {
                    let mut inner = argument.walk();
                    let expression = argument.named_children(&mut inner).next();
                    expression.unwrap_or(argument)
                })
                .collect()
        }
        None => Vec::new(),
    }
}

/// The `n`-th argument of a call, counting from zero.
pub fn arg<'t>(call: Node<'t>, src: &str, n: usize) -> Option<Node<'t>> {
    args(call, src).into_iter().nth(n)
}

/// Every call expression anywhere below `root`.
pub fn walk_calls<'t>(root: Node<'t>) -> Vec<Node<'t>> {
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(n) = stack.pop() {
        if is_call(n) {
            out.push(n);
        }
        let mut c = n.walk();
        for ch in n.children(&mut c) {
            stack.push(ch);
        }
    }
    out
}

/// Every call expression inside a function body, ignoring calls that belong to
/// a *nested* named function or method. Those are separate scopes and must not
/// be credited to the outer handler.
pub fn walk_calls_in_scope<'t>(root: Node<'t>) -> Vec<Node<'t>> {
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(n) = stack.pop() {
        if n.id() != root.id() && matches!(n.kind(), "function_definition" | "method_declaration") {
            continue;
        }
        if is_call(n) {
            out.push(n);
        }
        let mut c = n.walk();
        for ch in n.children(&mut c) {
            stack.push(ch);
        }
    }
    out
}

/// Is this node a superglobal variable such as `$_GET`?
pub fn is_superglobal(node: Node<'_>, src: &str) -> bool {
    if node.kind() != "variable_name" {
        return false;
    }
    let name = text(node, src);
    let name = name.strip_prefix('$').unwrap_or(name);
    SUPERGLOBALS.contains(&name)
}

/// Does this expression read from any superglobal?
pub fn contains_superglobal(node: Node<'_>, src: &str) -> bool {
    let mut stack = vec![node];
    while let Some(n) = stack.pop() {
        if is_superglobal(n, src) {
            return true;
        }
        let mut c = n.walk();
        for ch in n.children(&mut c) {
            stack.push(ch);
        }
    }
    false
}

/// Does this expression mention any ordinary (non superglobal) variable?
pub fn contains_variable(node: Node<'_>, src: &str) -> bool {
    let mut stack = vec![node];
    while let Some(n) = stack.pop() {
        if n.kind() == "variable_name" && !is_superglobal(n, src) {
            return true;
        }
        let mut c = n.walk();
        for ch in n.children(&mut c) {
            stack.push(ch);
        }
    }
    false
}

/// The value of a string literal, with the surrounding quotes removed.
///
/// Single quoted strings are always literals. Double quoted strings are only
/// literals when nothing is interpolated into them.
pub fn string_value(node: Node<'_>, src: &str) -> Option<String> {
    match node.kind() {
        "string" => {
            let raw = text(node, src).trim();
            let inner = raw
                .strip_prefix('\'')
                .or_else(|| raw.strip_prefix('"'))
                .unwrap_or(raw);
            let inner = inner
                .strip_suffix('\'')
                .or_else(|| inner.strip_suffix('"'))
                .unwrap_or(inner);
            Some(inner.replace("\\'", "'").replace("\\\"", "\""))
        }
        "encapsed_string" => {
            if contains_variable(node, src) {
                return None;
            }
            let raw = text(node, src).trim();
            let inner = raw.strip_prefix('"').unwrap_or(raw);
            let inner = inner.strip_suffix('"').unwrap_or(inner);
            Some(inner.replace("\\\"", "\""))
        }
        _ => None,
    }
}

/// Is this expression a string literal with nothing interpolated into it?
pub fn is_literal_string(node: Node<'_>, src: &str) -> bool {
    match node.kind() {
        "string" => true,
        "encapsed_string" => !contains_variable(node, src),
        _ => false,
    }
}

/// The value of an array element.
///
/// The grammar wraps every array entry in an `array_element_initializer`. That
/// wrapper holds either a single value (`[ 'a' ]`) or a key and a value
/// (`[ 'a' => 'b' ]`).
pub fn array_element_value(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() != "array_element_initializer" {
        return Some(node);
    }
    let mut cursor = node.walk();
    let named: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
    match named.len() {
        0 => None,
        1 => Some(named[0]),
        _ => Some(named[named.len() - 1]),
    }
}

/// The key of an array element, when it has one.
pub fn array_element_key(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() != "array_element_initializer" {
        return None;
    }
    let mut cursor = node.walk();
    let named: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
    if named.len() >= 2 {
        Some(named[0])
    } else {
        None
    }
}

/// The body of a function or method declaration.
pub fn body_span(node: Node<'_>) -> Span {
    match node.child_by_field_name("body") {
        Some(b) => Span::of(b),
        None => Span::of(node),
    }
}

/// The class a node is lexically inside of, if any.
pub fn enclosing_class(node: Node<'_>, src: &str) -> Option<String> {
    let mut cur = node.parent();
    while let Some(n) = cur {
        if n.kind() == "class_declaration" {
            return n
                .child_by_field_name("name")
                .map(|x| text(x, src).to_string());
        }
        cur = n.parent();
    }
    None
}

/// The function or method a node sits inside, as `(name, body span)`.
pub fn enclosing_function(node: Node<'_>, src: &str) -> Option<(String, Span)> {
    let mut cur = node.parent();
    while let Some(n) = cur {
        match n.kind() {
            "function_definition" => {
                let name = n
                    .child_by_field_name("name")
                    .map(|x| text(x, src).to_string())?;
                return Some((name, body_span(n)));
            }
            "method_declaration" => {
                let name = n
                    .child_by_field_name("name")
                    .map(|x| text(x, src).to_string())?;
                let cls = enclosing_class(n, src).unwrap_or_default();
                let label = if cls.is_empty() {
                    name
                } else {
                    format!("{cls}::{name}")
                };
                return Some((label, body_span(n)));
            }
            _ => {}
        }
        cur = n.parent();
    }
    None
}

/// Is the node an anonymous function or arrow function?
pub fn is_closure(node: Node<'_>) -> bool {
    node.kind().contains("anonymous_function") || node.kind() == "arrow_function"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::php::parse_source;
    use crate::php::PhpFile;

    fn parse(src: &str) -> PhpFile {
        parse_source(src.to_string(), "t.php".to_string()).unwrap()
    }

    #[test]
    fn reads_superglobal_values() {
        let f = parse("<?php $x = $_GET['id'];");
        let root = f.tree.root_node();
        let mut found = false;
        let mut stack = vec![root];
        while let Some(n) = stack.pop() {
            if n.kind() == "variable_name" && is_superglobal(n, &f.source) {
                found = true;
            }
            let mut c = n.walk();
            for ch in n.children(&mut c) {
                stack.push(ch);
            }
        }
        assert!(found);
    }

    #[test]
    fn strips_quotes_from_string_literals() {
        let f = parse("<?php add_action('wp_ajax_x', 'cb');");
        let root = f.tree.root_node();
        let call = walk_calls(root).remove(0);
        assert_eq!(
            arg(call, &f.source, 0).and_then(|n| string_value(n, &f.source)),
            Some("wp_ajax_x".to_string())
        );
        assert_eq!(
            arg(call, &f.source, 1).and_then(|n| string_value(n, &f.source)),
            Some("cb".to_string())
        );
    }

    #[test]
    fn reads_double_quoted_strings_without_interpolation() {
        let f = parse(r#"<?php $x = "hello";"#);
        let root = f.tree.root_node();
        let mut found = false;
        let mut stack = vec![root];
        while let Some(n) = stack.pop() {
            if n.kind() == "encapsed_string" && string_value(n, &f.source).is_some() {
                found = true;
            }
            let mut c = n.walk();
            for ch in n.children(&mut c) {
                stack.push(ch);
            }
        }
        assert!(
            found,
            "a double quoted string without interpolation is a literal"
        );
    }

    #[test]
    fn a_double_quoted_string_with_interpolation_is_not_a_literal() {
        let f = parse(r#"<?php $x = "hello $name";"#);
        let root = f.tree.root_node();
        let mut stack = vec![root];
        while let Some(n) = stack.pop() {
            if n.kind() == "encapsed_string" {
                assert!(string_value(n, &f.source).is_none());
                assert!(!is_literal_string(n, &f.source));
            }
            let mut c = n.walk();
            for ch in n.children(&mut c) {
                stack.push(ch);
            }
        }
    }

    #[test]
    fn identifies_member_calls() {
        let f = parse("<?php $wpdb->query('x');");
        let root = f.tree.root_node();
        let call = walk_calls(root).remove(0);
        match call_target(call, &f.source).unwrap() {
            CallTarget::Method { object, method } => {
                assert_eq!(object, "$wpdb");
                assert_eq!(method, "query");
            }
            other => panic!("expected a method call, got {other:?}"),
        }
    }
}
