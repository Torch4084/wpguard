use crate::analyze::Context;
use crate::finding::Finding;
use crate::php::ast::{self, CallTarget};
use crate::rule::{finding_from_meta, Rule, RuleMeta};
use crate::severity::{Confidence, Severity};
use crate::taint;
use tree_sitter::Node;

const FAST_HASHES: &[&str] = &["md5", "sha1", "md5_file", "sha1_file"];

const WEAK_RANDOM: &[&str] = &["rand", "mt_rand", "array_rand", "shuffle"];

/// A password hashed with a fast, unsalted hash.
pub struct FastHashForPasswords;

static META_HASH: RuleMeta = RuleMeta {
    id: "WP030",
    title: "Password hashed with a fast, unsalted algorithm",
    severity: Severity::Medium,
    confidence: Confidence::Medium,
    cwe: Some(328),
    description: "`md5()` and `sha1()` are designed to be fast, which is exactly wrong for \
                  passwords: a stolen hash table can be cracked at billions of guesses per second. \
                  They are also unsalted, so identical passwords produce identical hashes.",
    remediation: "Use `wp_hash_password()` to create the hash and `wp_check_password()` to verify \
                  it. Both use bcrypt, which is slow on purpose and salts each password.",
    references: &[
        "https://developer.wordpress.org/reference/functions/wp_hash_password/",
        "https://developer.wordpress.org/reference/functions/wp_check_password/",
        "https://owasp.org/www-community/attacks/Weak_password_hash",
    ],
};

impl Rule for FastHashForPasswords {
    fn meta(&self) -> &RuleMeta {
        &META_HASH
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
                if !FAST_HASHES.contains(&name.to_lowercase().as_str()) {
                    continue;
                }
                if !scope_is_about_passwords(ctx, file_idx, call, src) {
                    continue;
                }
                out.push(finding_from_meta(
                    &META_HASH,
                    ctx,
                    file_idx,
                    call,
                    format!(
                        "`{name}()` is used in code that deals with passwords. Passwords need a \
                         slow, salted hash."
                    ),
                ));
            }
        }
        out
    }
}

fn scope_is_about_passwords(ctx: &Context<'_>, file_idx: usize, node: Node<'_>, src: &str) -> bool {
    let Some((name, span)) = ast::enclosing_function(node, src) else {
        return false;
    };
    if name.to_lowercase().contains("pass") {
        return true;
    }
    let Some(body) = ctx.node_at(file_idx, span) else {
        return false;
    };
    let text = body.utf8_text(src.as_bytes()).unwrap_or("").to_lowercase();
    text.contains("password") || text.contains("passwd")
}

/// A security token generated with a predictable random source.
pub struct WeakRandomnessForSecrets;

static META_RANDOM: RuleMeta = RuleMeta {
    id: "WP031",
    title: "Security sensitive value generated with a weak random source",
    severity: Severity::Medium,
    confidence: Confidence::Low,
    cwe: Some(338),
    description: "`rand()` and `mt_rand()` use a linear congruential generator. The sequence is \
                  predictable, so a secret built from it can be guessed once a few outputs are \
                  observed.",
    remediation: "Use `random_bytes()`, `wp_generate_password()` or `wp_generate_uuid4()` for \
                  tokens, nonces, salts and keys.",
    references: &[
        "https://developer.wordpress.org/reference/functions/wp_generate_password/",
        "https://www.php.net/manual/en/function.random-bytes.php",
    ],
};

impl Rule for WeakRandomnessForSecrets {
    fn meta(&self) -> &RuleMeta {
        &META_RANDOM
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
                if !WEAK_RANDOM.contains(&name.to_lowercase().as_str()) {
                    continue;
                }
                if !scope_mentions_secret(ctx, file_idx, call, src) {
                    continue;
                }
                let mut finding = finding_from_meta(
                    &META_RANDOM,
                    ctx,
                    file_idx,
                    call,
                    format!("`{name}()` is used to build a security sensitive value."),
                );
                finding.confidence = Confidence::Low;
                out.push(finding);
            }
        }
        out
    }
}

fn scope_mentions_secret(ctx: &Context<'_>, file_idx: usize, node: Node<'_>, src: &str) -> bool {
    let Some((name, span)) = ast::enclosing_function(node, src) else {
        return false;
    };
    if taint::mentions_sensitive_word(&name) {
        return true;
    }
    let Some(body) = ctx.node_at(file_idx, span) else {
        return false;
    };
    let text = body.utf8_text(src.as_bytes()).unwrap_or("");
    taint::mentions_sensitive_word(text)
}
