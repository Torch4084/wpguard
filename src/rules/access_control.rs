use crate::analyze::{self, Context};
use crate::finding::Finding;
use crate::php::Permission;
use crate::rule::{finding_from_meta, Rule, RuleMeta};
use crate::severity::{Confidence, Severity};

const NOPRIV_PREFIX: &str = "wp_ajax_nopriv_";
const PRIV_PREFIX: &str = "wp_ajax_";

/// `wp_ajax_nopriv_*` actions are reachable by logged out visitors.
pub struct UnauthenticatedAjaxAction;

static META_NOPRIV: RuleMeta = RuleMeta {
    id: "WP001",
    title: "Unauthenticated AJAX action without a nonce check",
    severity: Severity::High,
    confidence: Confidence::Medium,
    cwe: Some(352),
    description: "An action registered under `wp_ajax_nopriv_` can be triggered by any visitor \
                  who is not logged in. When the handler does not verify a nonce, the request is \
                  not tied to a legitimate visit to the site, so a third party can trigger the \
                  action from the user's browser.",
    remediation:
        "Call `check_ajax_referer( 'my-action', 'nonce' )` at the top of the handler, and \
                  require a capability with `current_user_can()` if the action should only be \
                  available to logged in users.",
    references: &[
        "https://developer.wordpress.org/reference/functions/check_ajax_referer/",
        "https://developer.wordpress.org/reference/functions/add_action/",
        "https://owasp.org/www-community/attacks/csrf",
    ],
};

impl Rule for UnauthenticatedAjaxAction {
    fn meta(&self) -> &RuleMeta {
        &META_NOPRIV
    }

    fn check(&self, ctx: &Context<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for hook in &ctx.index.hooks {
            if !hook.name.starts_with(NOPRIV_PREFIX) {
                continue;
            }
            let action = hook.name.trim_start_matches(NOPRIV_PREFIX);
            if action.is_empty() {
                continue;
            }
            if analyze::handler_has_nonce(ctx, &hook.callback, hook.file) {
                continue;
            }
            let Some(node) = ctx.node_at(hook.file, hook.span) else {
                continue;
            };
            let message = format!(
                "`{action}` is registered for unauthenticated visitors and its handler does not \
                 verify a nonce, so any third party site can trigger it."
            );
            out.push(finding_from_meta(
                &META_NOPRIV,
                ctx,
                hook.file,
                node,
                message,
            ));
        }
        out
    }
}

/// `wp_ajax_*` actions are reachable by any logged in user.
pub struct AuthenticatedAjaxAction;

static META_PRIV: RuleMeta = RuleMeta {
    id: "WP002",
    title: "Authenticated AJAX action without a nonce check",
    severity: Severity::Medium,
    confidence: Confidence::Medium,
    cwe: Some(352),
    description: "An action registered under `wp_ajax_` can be triggered by any logged in user. \
                  A capability check stops unprivileged users, but it does not stop a third party \
                  website from replaying the request with the victim's cookies.",
    remediation: "Verify a nonce with `check_ajax_referer( 'my-action', 'nonce' )` in addition to \
                  the capability check.",
    references: &[
        "https://developer.wordpress.org/reference/functions/check_ajax_referer/",
        "https://owasp.org/www-community/attacks/csrf",
    ],
};

impl Rule for AuthenticatedAjaxAction {
    fn meta(&self) -> &RuleMeta {
        &META_PRIV
    }

    fn check(&self, ctx: &Context<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for hook in &ctx.index.hooks {
            if !hook.name.starts_with(PRIV_PREFIX) || hook.name.starts_with(NOPRIV_PREFIX) {
                continue;
            }
            let action = hook.name.trim_start_matches(PRIV_PREFIX);
            if action.is_empty() {
                continue;
            }
            if analyze::handler_has_nonce(ctx, &hook.callback, hook.file) {
                continue;
            }
            let Some(node) = ctx.node_at(hook.file, hook.span) else {
                continue;
            };
            let message = format!(
                "`{action}` is registered for logged in users and its handler does not verify a \
                 nonce, so the request can be forged from another site."
            );
            out.push(finding_from_meta(&META_PRIV, ctx, hook.file, node, message));
        }
        out
    }
}

/// A REST route that anybody may call.
pub struct OpenRestRoute;

static META_OPEN_ROUTE: RuleMeta = RuleMeta {
    id: "WP003",
    title: "REST route is open to everyone",
    severity: Severity::High,
    confidence: Confidence::Medium,
    cwe: Some(862),
    description: "`permission_callback` is set to `__return_true`, which tells WordPress that \
                  anybody may call the route. If the route reads or writes sensitive data, the \
                  endpoint is an unauthenticated data leak.",
    remediation: "Replace `__return_true` with a callback that checks a capability, for example \
                  `function ( $request ) { return current_user_can( 'edit_posts' ); }`.",
    references: &[
        "https://developer.wordpress.org/rest-api/extending-the-rest-api/routes-and-endpoints/",
        "https://developer.wordpress.org/reference/functions/register_rest_route/",
    ],
};

impl Rule for OpenRestRoute {
    fn meta(&self) -> &RuleMeta {
        &META_OPEN_ROUTE
    }

    fn check(&self, ctx: &Context<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for route in &ctx.index.rest_routes {
            if !matches!(route.permission, Permission::AlwaysTrue) {
                continue;
            }
            let Some(node) = ctx.node_at(route.file, route.span) else {
                continue;
            };
            let path = route.path();
            let message = format!(
                "The REST route `{path}` uses `__return_true` as its permission callback, so it \
                 accepts requests from anybody."
            );
            out.push(finding_from_meta(
                &META_OPEN_ROUTE,
                ctx,
                route.file,
                node,
                message,
            ));
        }
        out
    }
}

/// A REST route registered without a permission callback at all.
pub struct RestRouteWithoutPermission;

static META_MISSING_ROUTE: RuleMeta = RuleMeta {
    id: "WP004",
    title: "REST route registered without a permission callback",
    severity: Severity::Medium,
    confidence: Confidence::High,
    cwe: Some(862),
    description: "`register_rest_route()` was called without a `permission_callback`. Modern \
                  WordPress versions reject the registration outright, older ones fall back to \
                  allowing the request, and either way the route is not protected by design.",
    remediation: "Add a `permission_callback` entry to the route arguments and check a capability \
                  inside it.",
    references: &[
        "https://developer.wordpress.org/reference/functions/register_rest_route/",
        "https://developer.wordpress.org/rest-api/extending-the-rest-api/routes-and-endpoints/",
    ],
};

impl Rule for RestRouteWithoutPermission {
    fn meta(&self) -> &RuleMeta {
        &META_MISSING_ROUTE
    }

    fn check(&self, ctx: &Context<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for route in &ctx.index.rest_routes {
            if !matches!(route.permission, Permission::Missing) {
                continue;
            }
            let Some(node) = ctx.node_at(route.file, route.span) else {
                continue;
            };
            let path = route.path();
            let message =
                format!("The REST route `{path}` was registered without a `permission_callback`.");
            out.push(finding_from_meta(
                &META_MISSING_ROUTE,
                ctx,
                route.file,
                node,
                message,
            ));
        }
        out
    }
}

/// A REST route whose permission callback never checks a capability.
pub struct RestPermissionWithoutCheck;

static META_ROUTE_CHECK: RuleMeta = RuleMeta {
    id: "WP007",
    title: "REST route permission callback does not check a capability",
    severity: Severity::Medium,
    confidence: Confidence::Low,
    cwe: Some(862),
    description: "The route has a permission callback, but the callback does not contain a \
                  capability check. A callback that always returns true behaves exactly like no \
                  callback at all, and one that only inspects the request may still let \
                  unprivileged callers through.",
    remediation: "Check a capability inside the callback, for example \
                  `return current_user_can( 'edit_posts' );`, and return a `WP_Error` when the \
                  caller is not allowed.",
    references: &[
        "https://developer.wordpress.org/rest-api/extending-the-rest-api/routes-and-endpoints/",
        "https://developer.wordpress.org/plugins/users/roles-and-capabilities/",
    ],
};

impl Rule for RestPermissionWithoutCheck {
    fn meta(&self) -> &RuleMeta {
        &META_ROUTE_CHECK
    }

    fn check(&self, ctx: &Context<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for route in &ctx.index.rest_routes {
            let Permission::Callback(callback) = &route.permission else {
                continue;
            };
            if analyze::handler_is_protected(ctx, callback, route.file) {
                continue;
            }
            let Some(node) = ctx.node_at(route.file, route.span) else {
                continue;
            };
            let path = route.path();
            let message = format!(
                "The permission callback of the REST route `{path}` does not check any \
                 capability."
            );
            out.push(finding_from_meta(
                &META_ROUTE_CHECK,
                ctx,
                route.file,
                node,
                message,
            ));
        }
        out
    }
}

/// An admin page that every logged in user can open.
pub struct WeakAdminCapability;

static META_WEAK_CAP: RuleMeta = RuleMeta {
    id: "WP005",
    title: "Admin page registered with a weak capability",
    severity: Severity::Low,
    confidence: Confidence::High,
    cwe: Some(862),
    description: "The admin page is registered with the `read` capability or with no capability \
                  at all. Every logged in subscriber can open it, which is rarely the intent for a \
                  page that lives under an administrative menu.",
    remediation: "Register the page with a capability that matches what the page does, such as \
                  `manage_options` or `edit_posts`.",
    references: &[
        "https://developer.wordpress.org/reference/functions/add_menu_page/",
        "https://developer.wordpress.org/plugins/users/roles-and-capabilities/",
    ],
};

impl Rule for WeakAdminCapability {
    fn meta(&self) -> &RuleMeta {
        &META_WEAK_CAP
    }

    fn check(&self, ctx: &Context<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for page in &ctx.index.admin_pages {
            let capability = page.capability.trim();
            if !capability.is_empty() && capability != "read" {
                continue;
            }
            let Some(node) = ctx.node_at(page.file, page.span) else {
                continue;
            };
            let shown = if capability.is_empty() {
                "no capability at all".to_string()
            } else {
                "the `read` capability".to_string()
            };
            let message = format!(
                "`{}` is registered with {shown}, so any logged in subscriber can open it.",
                page.function
            );
            out.push(finding_from_meta(
                &META_WEAK_CAP,
                ctx,
                page.file,
                node,
                message,
            ));
        }
        out
    }
}

/// An `admin_post` handler that does not check who is calling it.
pub struct AdminPostWithoutCapability;

static META_ADMIN_POST: RuleMeta = RuleMeta {
    id: "WP006",
    title: "admin_post handler without a capability check",
    severity: Severity::High,
    confidence: Confidence::Medium,
    cwe: Some(862),
    description: "`admin_post` handlers are reached by ordinary page requests. Without a \
                  capability check, the action runs for anyone who can trigger a request to the \
                  admin, which for `admin_post_nopriv_` means any visitor at all.",
    remediation:
        "Check `current_user_can()` inside the handler and abort with `wp_die()` when the \
                  capability is missing.",
    references: &[
        "https://developer.wordpress.org/reference/functions/admin-post/",
        "https://developer.wordpress.org/plugins/users/roles-and-capabilities/",
    ],
};

impl Rule for AdminPostWithoutCapability {
    fn meta(&self) -> &RuleMeta {
        &META_ADMIN_POST
    }

    fn check(&self, ctx: &Context<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for hook in &ctx.index.hooks {
            let is_nopriv = hook.name.starts_with("admin_post_nopriv_");
            let is_priv = hook.name.starts_with("admin_post_") && !is_nopriv;
            if !is_nopriv && !is_priv {
                continue;
            }
            if analyze::handler_is_protected(ctx, &hook.callback, hook.file) {
                continue;
            }
            let Some(node) = ctx.node_at(hook.file, hook.span) else {
                continue;
            };
            let reach = if is_nopriv {
                "any visitor, including logged out ones"
            } else {
                "any logged in user"
            };
            let message = format!(
                "`{}` is registered for {reach} and its handler performs no capability check.",
                hook.name
            );
            let mut finding = finding_from_meta(&META_ADMIN_POST, ctx, hook.file, node, message);
            if is_priv {
                finding.severity = Severity::Medium;
            }
            out.push(finding);
        }
        out
    }
}
