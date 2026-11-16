<?php
/**
 * Plugin Name: Acme Forms
 * Description: A fixture that contains a range of security defects.
 * Version: 1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Acme_Forms {

	public function register() {
		// Reachable by logged out visitors, and nothing ties the request to
		// this site.
		add_action( 'wp_ajax_nopriv_acme_import', array( $this, 'handle_import' ) );

		// Reachable by any logged in user, and no nonce is verified.
		add_action( 'wp_ajax_acme_export', 'acme_export' );

		// Only administrators should be able to trigger this.
		add_action( 'admin_post_nopriv_acme_save', array( $this, 'handle_save' ) );

		add_action( 'admin_menu', array( $this, 'menu' ) );
	}

	public function menu() {
		add_menu_page(
			'Acme',
			'Acme',
			'read',
			'acme',
			array( $this, 'render' )
		);
	}

	public function handle_import() {
		global $wpdb;
		$id = $_GET['id'];
		$wpdb->query( "SELECT * FROM {$wpdb->prefix}forms WHERE id = " . $id );
		wp_send_json_success( array( 'imported' => true ) );
	}

	public function handle_save() {
		$payload = unserialize( $_POST['payload'] );
		$wpdb->query( "INSERT INTO {$wpdb->prefix}forms (name) VALUES ('" . $payload . "')" );
		echo "saved";
	}

	public function render() {
		$message = $_GET['message'];
		echo $message;
	}
}

function acme_export() {
	$target = $_GET['url'];
	$body = file_get_contents( $target );
	wp_send_json( array( 'data' => $body ) );
}

function acme_register_routes() {
	register_rest_route(
		'acme/v1',
		'/items',
		array(
			'methods'             => 'GET',
			'permission_callback' => '__return_true',
			'callback'            => 'acme_items',
		)
	);

	register_rest_route(
		'acme/v1',
		'/secret',
		array(
			'methods'  => 'GET',
			'callback' => 'acme_secret',
		)
	);
}

function acme_items() {
	return array( 'ok' => true );
}

function acme_secret() {
	return array( 'secret' => get_option( 'acme_secret' ) );
}

add_action( 'rest_api_init', 'acme_register_routes' );
