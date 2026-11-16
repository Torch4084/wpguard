<?php
/**
 * Plugin Name: Acme Safe
 * Description: A fixture that shows the correct way to do everything wpguard checks.
 * Version: 1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Acme_Safe {

	const NONCE = 'acme_safe_action';

	public function register() {
		add_action( 'wp_ajax_nopriv_acme_public', array( $this, 'handle_public' ) );
		add_action( 'wp_ajax_acme_private', array( $this, 'handle_private' ) );
		add_action( 'admin_post_acme_save', array( $this, 'handle_save' ) );
		add_action( 'admin_menu', array( $this, 'menu' ) );
	}

	public function menu() {
		add_menu_page(
			'Acme',
			'Acme',
			'manage_options',
			'acme',
			array( $this, 'render' )
		);
	}

	public function handle_public() {
		check_ajax_referer( self::NONCE, 'nonce' );
		wp_send_json_success( array( 'ok' => true ) );
	}

	public function handle_private() {
		check_ajax_referer( self::NONCE, 'nonce' );
		if ( ! current_user_can( 'edit_posts' ) ) {
			wp_die( 'Not allowed.', 403 );
		}
		wp_send_json_success( array( 'ok' => true ) );
	}

	public function handle_save() {
		if ( ! current_user_can( 'edit_posts' ) ) {
			wp_die( 'Not allowed.', 403 );
		}
		check_admin_referer( self::NONCE );
		$name = sanitize_text_field( wp_unslash( $_POST['name'] ) );
		wp_update_post( array( 'ID' => (int) $_POST['id'], 'post_title' => $name ) );
		wp_safe_redirect( admin_url( 'admin.php?page=acme' ) );
		exit;
	}

	public function render() {
		global $wpdb;
		$id   = isset( $_GET['id'] ) ? absint( $_GET['id'] ) : 0;
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}forms WHERE id = %d", $id ) );
		foreach ( $rows as $row ) {
			echo esc_html( $row->name );
		}
	}
}

function acme_safe_upload() {
	if ( ! current_user_can( 'upload_files' ) ) {
		wp_die( 'Not allowed.', 403 );
	}
	check_admin_referer( 'acme_upload' );
	$file = $_FILES['file'];
	$type = wp_check_filetype_and_ext( $file['tmp_name'], $file['name'] );
	if ( empty( $type['type'] ) || ! in_array( $type['type'], array( 'image/jpeg', 'image/png' ), true ) ) {
		wp_die( 'Not allowed.', 403 );
	}
	wp_handle_upload( $file );
}

function acme_safe_hash( $password ) {
	return wp_hash_password( $password );
}

function acme_safe_token() {
	return bin2hex( random_bytes( 16 ) );
}

function acme_safe_routes() {
	register_rest_route(
		'acme/v1',
		'/items',
		array(
			'methods'             => 'GET',
			'permission_callback' => 'acme_safe_permission',
			'callback'            => 'acme_safe_items',
		)
	);
}

function acme_safe_permission( $request ) {
	return current_user_can( 'edit_posts' );
}

function acme_safe_items( $request ) {
	return array( 'ok' => true );
}

add_action( 'rest_api_init', 'acme_safe_routes' );
