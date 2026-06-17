<?php
/**
 * WritersProof
 *
 * @package           WritersProof
 * @author            WritersLogic
 * @copyright         2024 WritersLogic
 * @license           GPL-2.0-or-later
 *
 * @wordpress-plugin
 * Plugin Name:       WritersProof
 * Plugin URI:        https://writerslogic.com
 * Description:       Cryptographic authorship attestation for WordPress content.
 * Version:           1.0.0
 * Requires at least: 6.0
 * Requires PHP:      8.0
 * Author:            WritersLogic
 * Author URI:        https://writerslogic.com
 * Text Domain:       writersproof
 * Domain Path:       /languages
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 */

declare( strict_types = 1 );

defined( 'ABSPATH' ) || exit;

define( 'WRITERSPROOF_VERSION', '1.0.0' );
define( 'WRITERSPROOF_PLUGIN_FILE', __FILE__ );
define( 'WRITERSPROOF_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'WRITERSPROOF_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'WRITERSPROOF_API_BASE', 'https://api.writerslogic.com/v1' );

/**
 * Load plugin text domain for translations.
 */
function writersproof_load_textdomain(): void {
	load_plugin_textdomain(
		'writersproof',
		false,
		dirname( plugin_basename( __FILE__ ) ) . '/languages'
	);
}
add_action( 'plugins_loaded', 'writersproof_load_textdomain' );

/**
 * Autoload plugin classes.
 *
 * @param string $class_name The class name to load.
 */
function writersproof_autoload( string $class_name ): void {
	if ( strpos( $class_name, 'WritersProof_' ) !== 0 ) {
		return;
	}

	$file = WRITERSPROOF_PLUGIN_DIR . 'includes/class-' . strtolower(
		str_replace( '_', '-', $class_name )
	) . '.php';

	if ( file_exists( $file ) ) {
		require_once $file;
	}
}
spl_autoload_register( 'writersproof_autoload' );

/**
 * Plugin activation: create database tables and set default options.
 */
function writersproof_activate(): void {
	global $wpdb;

	$charset_collate = $wpdb->get_charset_collate();
	$table_name      = $wpdb->prefix . 'writersproof_sessions';

	$sql = "CREATE TABLE {$table_name} (
		id             bigint(20) unsigned NOT NULL AUTO_INCREMENT,
		post_id        bigint(20) unsigned NOT NULL,
		session_id     varchar(128)        NOT NULL DEFAULT '',
		status         varchar(32)         NOT NULL DEFAULT 'active',
		started_at     datetime            NOT NULL DEFAULT CURRENT_TIMESTAMP,
		finalized_at   datetime                     DEFAULT NULL,
		evidence_score tinyint(3) unsigned          DEFAULT NULL,
		PRIMARY KEY  (id),
		KEY post_id   (post_id),
		KEY session_id (session_id)
	) {$charset_collate};";

	require_once ABSPATH . 'wp-admin/includes/upgrade.php';
	dbDelta( $sql );

	// Default settings.
	add_option( 'writersproof_api_key', '' );
	add_option( 'writersproof_auto_start', '1' );
	add_option( 'writersproof_checkpoint_interval', '60' );
	add_option( 'writersproof_post_types', array( 'post', 'page' ) );

	flush_rewrite_rules();
}
register_activation_hook( __FILE__, 'writersproof_activate' );

/**
 * Plugin deactivation: flush rewrite rules.
 */
function writersproof_deactivate(): void {
	flush_rewrite_rules();
}
register_deactivation_hook( __FILE__, 'writersproof_deactivate' );

/**
 * Enqueue admin scripts and styles for the block editor and classic editor.
 *
 * @param string $hook_suffix The current admin page hook suffix.
 */
function writersproof_enqueue_admin_assets( string $hook_suffix ): void {
	$screen = get_current_screen();

	if ( ! $screen ) {
		return;
	}

	// Only load on post edit screens.
	if ( ! in_array( $hook_suffix, array( 'post.php', 'post-new.php' ), true ) ) {
		return;
	}

	$monitored_types = get_option( 'writersproof_post_types', array( 'post', 'page' ) );
	if ( ! in_array( $screen->post_type, (array) $monitored_types, true ) ) {
		return;
	}

	$api_key = get_option( 'writersproof_api_key', '' );

	// Common admin styles.
	wp_enqueue_style(
		'writersproof-admin',
		WRITERSPROOF_PLUGIN_URL . 'assets/css/admin.css',
		array(),
		WRITERSPROOF_VERSION
	);

	// Block editor (Gutenberg) script.
	if ( $screen->is_block_editor() ) {
		wp_enqueue_script(
			'writersproof-editor',
			WRITERSPROOF_PLUGIN_URL . 'assets/js/editor-hooks.js',
			array( 'wp-plugins', 'wp-edit-post', 'wp-data', 'wp-element', 'wp-components', 'wp-i18n' ),
			WRITERSPROOF_VERSION,
			true
		);

		wp_localize_script(
			'writersproof-editor',
			'writersProofData',
			array(
				'restUrl'             => esc_url_raw( rest_url( 'writersproof/v1' ) ),
				'nonce'               => wp_create_nonce( 'wp_rest' ),
				'postId'              => (int) get_the_ID(),
				'autoStart'           => (bool) get_option( 'writersproof_auto_start', '1' ),
				'checkpointInterval'  => max( 10, min( 300, (int) get_option( 'writersproof_checkpoint_interval', '60' ) ) ),
				'hasApiKey'           => ! empty( $api_key ),
				'version'             => WRITERSPROOF_VERSION,
			)
		);

		wp_set_script_translations( 'writersproof-editor', 'writersproof' );
	}
}
add_action( 'admin_enqueue_scripts', 'writersproof_enqueue_admin_assets' );

/**
 * Initialize plugin components after all plugins are loaded.
 */
function writersproof_init(): void {
	// REST API routes.
	$rest = new WritersProof_Rest();
	add_action( 'rest_api_init', array( $rest, 'register_routes' ) );

	// Admin UI.
	if ( is_admin() ) {
		$admin = new WritersProof_Admin();
		$admin->init();
	}
}
add_action( 'plugins_loaded', 'writersproof_init', 20 );

/**
 * Register post meta fields for block editor compatibility.
 */
function writersproof_register_post_meta(): void {
	$post_types = (array) get_option( 'writersproof_post_types', array( 'post', 'page' ) );

	foreach ( $post_types as $post_type ) {
		register_post_meta(
			$post_type,
			'_writersproof_session_id',
			array(
				'type'              => 'string',
				'description'       => __( 'Active WritersProof session ID.', 'writersproof' ),
				'single'            => true,
				'show_in_rest'      => true,
				'sanitize_callback' => 'sanitize_text_field',
				'auth_callback'     => function () {
					return current_user_can( 'edit_posts' );
				},
			)
		);

		register_post_meta(
			$post_type,
			'_writersproof_evidence_score',
			array(
				'type'         => 'integer',
				'description'  => __( 'WritersProof evidence quality score (0-100).', 'writersproof' ),
				'single'       => true,
				'show_in_rest' => true,
				'auth_callback' => function () {
					return current_user_can( 'edit_posts' );
				},
			)
		);

		register_post_meta(
			$post_type,
			'_writersproof_status',
			array(
				'type'              => 'string',
				'description'       => __( 'WritersProof witnessing status.', 'writersproof' ),
				'single'            => true,
				'show_in_rest'      => true,
				'sanitize_callback' => 'sanitize_text_field',
				'auth_callback'     => function () {
					return current_user_can( 'edit_posts' );
				},
			)
		);

		register_post_meta(
			$post_type,
			'_writersproof_last_snapshot',
			array(
				'type'         => 'string',
				'description'  => __( 'JSON snapshot of last captured content state.', 'writersproof' ),
				'single'       => true,
				'show_in_rest' => false,
				'auth_callback' => function () {
					return current_user_can( 'edit_posts' );
				},
			)
		);
	}
}
add_action( 'init', 'writersproof_register_post_meta' );

/**
 * Hook into save_post to capture a checkpoint when a post is saved outside the editor.
 *
 * @param int     $post_id The post ID.
 * @param WP_Post $post    The post object.
 * @param bool    $update  Whether this is an update.
 */
function writersproof_on_save_post( int $post_id, WP_Post $post, bool $update ): void {
	// Skip autosaves, revisions, and non-monitored statuses.
	if ( defined( 'DOING_AUTOSAVE' ) && DOING_AUTOSAVE ) {
		return;
	}
	if ( wp_is_post_revision( $post_id ) ) {
		return;
	}
	if ( ! in_array( $post->post_status, array( 'publish', 'draft', 'private' ), true ) ) {
		return;
	}

	$monitored_types = (array) get_option( 'writersproof_post_types', array( 'post', 'page' ) );
	if ( ! in_array( $post->post_type, $monitored_types, true ) ) {
		return;
	}

	// Only act when there is an active session.
	$session_id = get_post_meta( $post_id, '_writersproof_session_id', true );
	if ( empty( $session_id ) ) {
		return;
	}

	$monitor    = new WritersProof_Monitor();
	$snapshot   = $monitor->capture_snapshot( $post_id );
	$client     = new WritersProof_Client();

	$result = $client->create_checkpoint(
		$session_id,
		array(
			'contentHash' => $snapshot['content_hash'],
			'wordCount'   => $snapshot['word_count'],
			'charCount'   => $snapshot['char_count'],
			'metadata'    => array(
				'paragraphCount' => $snapshot['paragraph_count'],
				'trigger'        => 'save_post',
			),
		)
	);
	if ( is_wp_error( $result ) ) {
		return;
	}

	$monitor->save_snapshot( $post_id, $snapshot );
}
add_action( 'save_post', 'writersproof_on_save_post', 10, 3 );

/**
 * Finalize the WritersProof session when a post is published.
 *
 * @param string  $new_status New post status.
 * @param string  $old_status Previous post status.
 * @param WP_Post $post       Post object.
 */
function writersproof_on_publish( string $new_status, string $old_status, WP_Post $post ): void {
	if ( 'publish' !== $new_status || 'publish' === $old_status ) {
		return;
	}

	$monitored_types = (array) get_option( 'writersproof_post_types', array( 'post', 'page' ) );
	if ( ! in_array( $post->post_type, $monitored_types, true ) ) {
		return;
	}

	$session_id = get_post_meta( $post->ID, '_writersproof_session_id', true );
	if ( empty( $session_id ) ) {
		return;
	}

	$monitor  = new WritersProof_Monitor();
	$snapshot = $monitor->capture_snapshot( $post->ID );
	$client   = new WritersProof_Client();

	$result = $client->finalize_session(
		$session_id,
		array(
			'contentHash'   => $snapshot['content_hash'],
			'wordCount'     => $snapshot['word_count'],
			'finalSnapshot' => array(
				'charCount'      => $snapshot['char_count'],
				'paragraphCount' => $snapshot['paragraph_count'],
			),
		)
	);

	if ( ! is_wp_error( $result ) ) {
		update_post_meta( $post->ID, '_writersproof_status', 'finalized' );

		// Fetch and store the evidence score if available.
		$evidence = $client->get_evidence( $session_id );
		if ( ! is_wp_error( $evidence ) && isset( $evidence['score'] ) ) {
			update_post_meta( $post->ID, '_writersproof_evidence_score', (int) $evidence['score'] );
		}
	}
}
add_action( 'transition_post_status', 'writersproof_on_publish', 10, 3 );
