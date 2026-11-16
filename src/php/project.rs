use crate::php::ast::{self, CallTarget};
use crate::php::{PhpFile, Span};
use std::collections::HashMap;
use tree_sitter::Node;

/// How a WordPress hook is wired up.
#[derive(Debug, Clone)]
pub enum Callback {
    /// A global function, by name.
    Function(String),
    /// A method. `class` is `None` when the receiver was not `$this` and not
    /// a literal class name.
    Method {
        class: Option<String>,
        method: String,
    },
    /// An inline closure.
    Inline(Span),
    /// Something the analyzer could not work out.
    Unknown,
}

/// A hook registration.
#[derive(Debug, Clone)]
pub struct HookReg {
    /// The hook name, e.g. `wp_ajax_nopriv_import`.
    pub name: String,
    pub callback: Callback,
    /// Index into the analysed file list.
    pub file: usize,
    /// Span of the registration call.
    pub span: Span,
}

/// The permission model of a REST route.
#[derive(Debug, Clone)]
pub enum Permission {
    /// No `permission_callback` was supplied at all.
    Missing,
    /// `permission_callback => '__return_true'` — open to everyone.
    AlwaysTrue,
    /// `permission_callback => '__return_false'` — closed to everyone.
    AlwaysFalse,
    /// A real callback.
    Callback(Callback),
}

/// A REST route registration.
#[derive(Debug, Clone)]
pub struct RestRouteReg {
    pub namespace: String,
    pub route: String,
    pub permission: Permission,
    pub file: usize,
    pub span: Span,
}

impl RestRouteReg {
    /// The full route path, for example `acme/v1/items`.
    pub fn path(&self) -> String {
        let namespace = self.namespace.trim_end_matches('/');
        let route = self.route.trim_start_matches('/');
        if namespace.is_empty() {
            format!("/{route}")
        } else {
            format!("{namespace}/{route}")
        }
    }
}

/// An admin menu page registration.
#[derive(Debug, Clone)]
pub struct AdminPageReg {
    pub capability: String,
    pub function: String,
    pub file: usize,
    pub span: Span,
}

/// Everything the analyzer learned about the project before running rules.
#[derive(Debug, Default)]
pub struct ProjectIndex {
    /// Global functions, keyed by lowercase name.
    pub functions: HashMap<String, (usize, Span)>,
    /// Methods, keyed by `(lowercase class, lowercase method)`.
    pub methods: HashMap<(String, String), (usize, Span)>,
    pub hooks: Vec<HookReg>,
    pub rest_routes: Vec<RestRouteReg>,
    pub admin_pages: Vec<AdminPageReg>,
}

impl ProjectIndex {
    /// Find the body of whatever a callback points at.
    pub fn resolve_body(&self, callback: &Callback, file: usize) -> Option<(usize, Span)> {
        match callback {
            Callback::Function(name) => self.functions.get(&name.to_lowercase()).copied(),
            Callback::Method { class, method } => {
                if let Some(class) = class {
                    let key = (class.to_lowercase(), method.to_lowercase());
                    if let Some(hit) = self.methods.get(&key) {
                        return Some(*hit);
                    }
                }
                // The receiver was neither `$this` nor a literal class name, so
                // the class is unknown. Fall back to any method of that name.
                let key = method.to_lowercase();
                self.methods
                    .iter()
                    .find(|((_, m), _)| *m == key)
                    .map(|(_, v)| *v)
            }
            Callback::Inline(span) => Some((file, *span)),
            Callback::Unknown => None,
        }
    }
}

/// Admin page registration functions and the index of their capability
/// argument. `add_submenu_page` takes an extra parent argument up front.
const ADMIN_PAGE_FUNCTIONS: &[(&str, usize)] = &[
    ("add_menu_page", 2),
    ("add_submenu_page", 3),
    ("add_management_page", 2),
    ("add_options_page", 2),
    ("add_plugins_page", 2),
    ("add_theme_page", 2),
    ("add_users_page", 2),
    ("add_dashboard_page", 2),
    ("add_media_page", 2),
    ("add_comments_page", 2),
    ("add_edit_page", 2),
    ("add_posts_page", 2),
    ("add_pages_page", 2),
    ("add_privacy_policy_page", 2),
];

/// Build the project index from the parsed files.
pub fn build_index(files: &[PhpFile]) -> ProjectIndex {
    let mut index = ProjectIndex::default();
    for (i, file) in files.iter().enumerate() {
        index_file(&mut index, i, file);
    }
    index
}

fn index_file(index: &mut ProjectIndex, file_idx: usize, file: &PhpFile) {
    let root = file.tree.root_node();
    let mut stack: Vec<(Node<'_>, Option<String>)> = vec![(root, None)];

    while let Some((node, class)) = stack.pop() {
        match node.kind() {
            "class_declaration" => {
                let name = node
                    .child_by_field_name("name")
                    .map(|n| ast::text(n, &file.source).to_string());
                let scope = name.or_else(|| class.clone());
                push_children(&mut stack, node, scope);
            }
            "method_declaration" => {
                if let (Some(class), Some(name)) = (class.clone(), node.child_by_field_name("name"))
                {
                    let method = ast::text(name, &file.source).to_string();
                    index
                        .methods
                        .entry((class.to_lowercase(), method.to_lowercase()))
                        .or_insert((file_idx, ast::body_span(node)));
                }
                push_children(&mut stack, node, class);
            }
            "function_definition" => {
                if let Some(name) = node.child_by_field_name("name") {
                    let fname = ast::text(name, &file.source).to_string();
                    index
                        .functions
                        .entry(fname.to_lowercase())
                        .or_insert((file_idx, ast::body_span(node)));
                }
                push_children(&mut stack, node, class);
            }
            "function_call_expression" => {
                handle_call(index, file_idx, file, node, class.as_deref());
                push_children(&mut stack, node, class);
            }
            _ => push_children(&mut stack, node, class),
        }
    }
}

fn push_children<'t>(
    stack: &mut Vec<(Node<'t>, Option<String>)>,
    node: Node<'t>,
    class: Option<String>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        stack.push((child, class.clone()));
    }
}

fn handle_call(
    index: &mut ProjectIndex,
    file_idx: usize,
    file: &PhpFile,
    node: Node<'_>,
    class: Option<&str>,
) {
    let Some(CallTarget::Function(name)) = ast::call_target(node, &file.source) else {
        return;
    };
    let arguments = ast::args(node, &file.source);

    match name.as_str() {
        "add_action" | "add_filter" => {
            let hook_name = arguments
                .first()
                .and_then(|n| ast::string_value(*n, &file.source))
                .unwrap_or_default();
            let callback = arguments
                .get(1)
                .map(|n| parse_callback(*n, &file.source, class))
                .unwrap_or(Callback::Unknown);
            index.hooks.push(HookReg {
                name: hook_name,
                callback,
                file: file_idx,
                span: ast::span(node),
            });
        }
        "register_rest_route" => {
            let namespace = arguments
                .first()
                .and_then(|n| ast::string_value(*n, &file.source))
                .unwrap_or_default();
            let route = arguments
                .get(1)
                .and_then(|n| ast::string_value(*n, &file.source))
                .unwrap_or_default();
            let permission = arguments
                .get(2)
                .map(|n| parse_permission(*n, &file.source, class))
                .unwrap_or(Permission::Missing);
            index.rest_routes.push(RestRouteReg {
                namespace,
                route,
                permission,
                file: file_idx,
                span: ast::span(node),
            });
        }
        other => {
            if let Some((_, cap_index)) = ADMIN_PAGE_FUNCTIONS.iter().find(|(f, _)| *f == other) {
                let capability = arguments
                    .get(*cap_index)
                    .and_then(|n| ast::string_value(*n, &file.source))
                    .unwrap_or_default();
                index.admin_pages.push(AdminPageReg {
                    capability,
                    function: other.to_string(),
                    file: file_idx,
                    span: ast::span(node),
                });
            }
        }
    }
}

fn parse_callback(node: Node<'_>, src: &str, class: Option<&str>) -> Callback {
    match node.kind() {
        "string" => match ast::string_value(node, src) {
            Some(name) => Callback::Function(name),
            None => Callback::Unknown,
        },
        "array_creation_expression" => {
            let mut cursor = node.walk();
            let elements: Vec<Node<'_>> = node
                .named_children(&mut cursor)
                .filter(|e| e.kind() == "array_element_initializer")
                .collect();
            if elements.len() < 2 {
                return Callback::Unknown;
            }
            let Some(receiver) = ast::array_element_value(elements[0]) else {
                return Callback::Unknown;
            };
            let Some(method_node) = ast::array_element_value(elements[1]) else {
                return Callback::Unknown;
            };
            let method = match ast::string_value(method_node, src) {
                Some(m) if !m.is_empty() => m,
                _ => return Callback::Unknown,
            };
            let owner = match receiver.kind() {
                "variable_name" => {
                    if ast::text(receiver, src) == "$this" {
                        class.map(|c| c.to_string())
                    } else {
                        None
                    }
                }
                "string" => ast::string_value(receiver, src),
                _ => None,
            };
            Callback::Method {
                class: owner,
                method,
            }
        }
        kind if ast::is_closure(node) => {
            let _ = kind;
            Callback::Inline(ast::span(node))
        }
        _ => Callback::Unknown,
    }
}

fn parse_permission(node: Node<'_>, src: &str, class: Option<&str>) -> Permission {
    if node.kind() != "array_creation_expression" {
        return Permission::Missing;
    }
    let mut cursor = node.walk();
    for element in node
        .named_children(&mut cursor)
        .filter(|e| e.kind() == "array_element_initializer")
    {
        let Some(key) = ast::array_element_key(element) else {
            continue;
        };
        if ast::string_value(key, src).as_deref() != Some("permission_callback") {
            continue;
        }
        let Some(value) = ast::array_element_value(element) else {
            return Permission::Missing;
        };
        return match value.kind() {
            "string" => match ast::string_value(value, src).as_deref() {
                Some("__return_true") => Permission::AlwaysTrue,
                Some("__return_false") => Permission::AlwaysFalse,
                Some(other) => Permission::Callback(Callback::Function(other.to_string())),
                None => Permission::Missing,
            },
            "array_creation_expression" => Permission::Callback(parse_callback(value, src, class)),
            kind if ast::is_closure(value) => {
                let _ = kind;
                Permission::Callback(Callback::Inline(ast::span(value)))
            }
            _ => Permission::Callback(Callback::Unknown),
        };
    }
    Permission::Missing
}
