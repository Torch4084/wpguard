//! Rule level tests.
//!
//! Every rule gets a positive case and, where it matters, a negative case
//! that proves the rule stays quiet on the correct way of doing things.

use wpguard::analyze::analyze;
use wpguard::php::parse_source;
use wpguard::rules::all_rules;

/// Run every rule over a snippet and return the rule identifiers that fired.
fn scan(source: &str) -> Vec<String> {
    let files = vec![parse_source(source.to_string(), "snippet.php".to_string()).unwrap()];
    let rules = all_rules();
    analyze(&files, &rules)
        .into_iter()
        .map(|f| f.rule_id)
        .collect()
}

fn assert_fires(rule: &str, source: &str) {
    let ids = scan(source);
    assert!(
        ids.iter().any(|id| id == rule),
        "expected {rule} to fire, got {ids:?}\n--- source ---\n{source}"
    );
}

fn assert_quiet(rules: &[&str], source: &str) {
    let ids = scan(source);
    for rule in rules {
        assert!(
            !ids.iter().any(|id| id == rule),
            "expected {rule} to stay quiet, got {ids:?}\n--- source ---\n{source}"
        );
    }
}

#[test]
fn flags_an_unauthenticated_ajax_action_without_a_nonce() {
    assert_fires(
        "WP001",
        r#"<?php
add_action( 'wp_ajax_nopriv_acme_import', 'acme_import' );
function acme_import() { echo 'ok'; }
"#,
    );
}

#[test]
fn accepts_an_unauthenticated_ajax_action_with_a_nonce() {
    assert_quiet(
        &["WP001"],
        r#"<?php
add_action( 'wp_ajax_nopriv_acme_import', 'acme_import' );
function acme_import() { check_ajax_referer( 'acme', 'nonce' ); }
"#,
    );
}

#[test]
fn accepts_an_ajax_action_that_delegates_to_a_guarded_helper() {
    assert_quiet(
        &["WP001", "WP002"],
        r#"<?php
add_action( 'wp_ajax_acme_private', 'acme_private' );
function acme_private() { acme_guard(); }
function acme_guard() { check_ajax_referer( 'acme', 'nonce' ); }
"#,
    );
}

#[test]
fn a_capability_check_alone_does_not_satisfy_the_nonce_rules() {
    // A capability check stops unprivileged callers but it does not stop a
    // third party site from replaying the request with the victim's cookies,
    // so the nonce rules must still report this.
    assert_fires(
        "WP002",
        r#"<?php
add_action( 'wp_ajax_acme_private', 'acme_private' );
function acme_private() { current_user_can( 'edit_posts' ); }
"#,
    );
}

#[test]
fn flags_an_authenticated_ajax_action_without_a_nonce() {
    assert_fires(
        "WP002",
        r#"<?php
add_action( 'wp_ajax_acme_export', 'acme_export' );
function acme_export() { echo 'ok'; }
"#,
    );
}

#[test]
fn flags_a_rest_route_that_is_open_to_everyone() {
    assert_fires(
        "WP003",
        r#"<?php
register_rest_route( 'acme/v1', '/items', array(
    'methods' => 'GET',
    'permission_callback' => '__return_true',
    'callback' => 'acme_items',
) );
"#,
    );
}

#[test]
fn accepts_a_rest_route_with_a_capability_check() {
    assert_quiet(
        &["WP003", "WP004", "WP007"],
        r#"<?php
register_rest_route( 'acme/v1', '/items', array(
    'methods' => 'GET',
    'permission_callback' => 'acme_permission',
    'callback' => 'acme_items',
) );
function acme_permission( $request ) { return current_user_can( 'edit_posts' ); }
"#,
    );
}

#[test]
fn flags_a_rest_route_without_a_permission_callback() {
    assert_fires(
        "WP004",
        r#"<?php
register_rest_route( 'acme/v1', '/items', array(
    'methods' => 'GET',
    'callback' => 'acme_items',
) );
"#,
    );
}

#[test]
fn flags_an_admin_post_handler_without_a_capability_check() {
    assert_fires(
        "WP006",
        r#"<?php
add_action( 'admin_post_nopriv_acme_save', 'acme_save' );
function acme_save() { echo 'ok'; }
"#,
    );
}

#[test]
fn accepts_an_admin_post_handler_with_a_capability_check() {
    assert_quiet(
        &["WP006"],
        r#"<?php
add_action( 'admin_post_acme_save', 'acme_save' );
function acme_save() { if ( ! current_user_can( 'edit_posts' ) ) { wp_die(); } }
"#,
    );
}

#[test]
fn flags_an_admin_page_with_a_weak_capability() {
    assert_fires(
        "WP005",
        r#"<?php
add_menu_page( 'Acme', 'Acme', 'read', 'acme', 'acme_render' );
"#,
    );
}

#[test]
fn accepts_an_admin_page_with_a_real_capability() {
    assert_quiet(
        &["WP005"],
        r#"<?php
add_menu_page( 'Acme', 'Acme', 'manage_options', 'acme', 'acme_render' );
"#,
    );
}

#[test]
fn flags_an_unprepared_database_query() {
    assert_fires(
        "WP010",
        r#"<?php
function acme_query( $id ) {
    global $wpdb;
    $wpdb->query( "SELECT * FROM forms WHERE id = " . $id );
}
"#,
    );
}

#[test]
fn accepts_a_prepared_database_query() {
    assert_quiet(
        &["WP010"],
        r#"<?php
function acme_query( $id ) {
    global $wpdb;
    $wpdb->query( $wpdb->prepare( "SELECT * FROM forms WHERE id = %d", $id ) );
}
"#,
    );
}

#[test]
fn accepts_a_literal_database_query() {
    assert_quiet(
        &["WP010"],
        r#"<?php
function acme_query() {
    global $wpdb;
    $wpdb->query( "SELECT * FROM forms" );
}
"#,
    );
}

#[test]
fn flags_unserialize_of_request_data() {
    assert_fires(
        "WP011",
        r#"<?php
function acme_load() {
    $value = unserialize( $_POST['payload'] );
}
"#,
    );
}

#[test]
fn flags_unserialize_of_a_variable_that_came_from_the_request() {
    assert_fires(
        "WP011",
        r#"<?php
function acme_load() {
    $raw = $_POST['payload'];
    $value = unserialize( $raw );
}
"#,
    );
}

#[test]
fn accepts_unserialize_of_a_value_that_did_not_come_from_the_request() {
    assert_quiet(
        &["WP011"],
        r#"<?php
function acme_load( $raw ) {
    $value = unserialize( $raw );
}
"#,
    );
}

#[test]
fn flags_dynamic_code_evaluation() {
    assert_fires(
        "WP012",
        r#"<?php
function acme_run( $code ) { eval( $code ); }
"#,
    );
}

#[test]
fn flags_a_dynamic_file_inclusion() {
    assert_fires(
        "WP013",
        r#"<?php
function acme_include( $file ) { include $file; }
"#,
    );
}

#[test]
fn accepts_an_inclusion_with_a_constant_path() {
    assert_quiet(
        &["WP013"],
        r#"<?php
function acme_include() { include ABSPATH . 'acme/file.php'; }
"#,
    );
}

#[test]
fn flags_unescaped_output() {
    assert_fires(
        "WP014",
        r#"<?php
function acme_echo() { echo $_GET['message']; }
"#,
    );
}

#[test]
fn accepts_escaped_output() {
    assert_quiet(
        &["WP014"],
        r#"<?php
function acme_echo() { echo esc_html( $_GET['message'] ); }
"#,
    );
}

#[test]
fn flags_an_open_redirect() {
    assert_fires(
        "WP015",
        r#"<?php
function acme_go() { wp_redirect( $_GET['url'] ); }
"#,
    );
}

#[test]
fn accepts_a_safe_redirect() {
    assert_quiet(
        &["WP015"],
        r#"<?php
function acme_go() { wp_safe_redirect( home_url( '/' ) ); }
"#,
    );
}

#[test]
fn flags_an_upload_without_a_type_check() {
    assert_fires(
        "WP020",
        r#"<?php
function acme_upload( $file ) {
    move_uploaded_file( $file['tmp_name'], '/var/www/uploads/' . $file['name'] );
}
"#,
    );
}

#[test]
fn accepts_an_upload_with_a_type_check() {
    assert_quiet(
        &["WP020"],
        r#"<?php
function acme_upload( $file ) {
    $type = wp_check_filetype_and_ext( $file['tmp_name'], $file['name'] );
    move_uploaded_file( $file['tmp_name'], '/var/www/uploads/' . $file['name'] );
}
"#,
    );
}

#[test]
fn flags_a_request_controlled_url_fetch() {
    assert_fires(
        "WP021",
        r#"<?php
function acme_fetch() {
    $body = file_get_contents( $_GET['url'] );
}
"#,
    );
}

#[test]
fn flags_a_fast_hash_used_for_a_password() {
    assert_fires(
        "WP030",
        r#"<?php
function acme_hash_password( $password ) {
    return md5( $password );
}
"#,
    );
}

#[test]
fn accepts_a_slow_hash_for_a_password() {
    assert_quiet(
        &["WP030"],
        r#"<?php
function acme_hash_password( $password ) {
    return wp_hash_password( $password );
}
"#,
    );
}

#[test]
fn flags_weak_randomness_used_for_a_token() {
    assert_fires(
        "WP031",
        r#"<?php
function acme_make_token() {
    return md5( rand() );
}
"#,
    );
}

#[test]
fn flags_command_execution() {
    assert_fires(
        "PHP001",
        r#"<?php
function acme_run( $cmd ) { exec( $cmd ); }
"#,
    );
}

#[test]
fn flags_disabled_tls_verification() {
    assert_fires(
        "PHP002",
        r#"<?php
function acme_fetch( $url ) {
    $ch = curl_init();
    curl_setopt( $ch, CURLOPT_SSL_VERIFYPEER, false );
}
"#,
    );
}

#[test]
fn accepts_enabled_tls_verification() {
    assert_quiet(
        &["PHP002"],
        r#"<?php
function acme_fetch( $url ) {
    $ch = curl_init();
    curl_setopt( $ch, CURLOPT_SSL_VERIFYPEER, true );
}
"#,
    );
}

#[test]
fn a_clean_plugin_produces_no_findings_at_all() {
    let source = std::fs::read_to_string("tests/fixtures/clean-plugin/acme-safe.php").unwrap();
    assert!(
        scan(&source).is_empty(),
        "the clean fixture must not produce findings"
    );
}
