<?php
/**
 * WritersProof admin UI: settings page and post-edit meta box.
 *
 * @package WritersProof
 * @since   1.0.0
 */

declare( strict_types = 1 );

defined( 'ABSPATH' ) || exit;

/**
 * Manages the WordPress admin interface for the WritersProof plugin.
 */
class WritersProof_Admin {

	/**
	 * Options group name used with register_setting().
	 */
	private const OPTIONS_GROUP = 'writersproof_settings';

	/**
	 * Settings page slug.
	 */
	private const PAGE_SLUG = 'writersproof-settings';

	/**
	 * Hook suffix returned by add_options_page(), stored for asset scoping.
	 */
	private string $settings_hook = '';

	// -------------------------------------------------------------------------
	// Bootstrap
	// -------------------------------------------------------------------------

	/**
	 * Register all admin hooks.
	 */
	public function init(): void {
		add_action( 'admin_menu', array( $this, 'add_menu_page' ) );
		add_action( 'admin_init', array( $this, 'register_settings' ) );
		add_action( 'add_meta_boxes', array( $this, 'add_meta_boxes' ) );
		add_action( 'admin_notices', array( $this, 'maybe_show_setup_notice' ) );
	}

	// -------------------------------------------------------------------------
	// Menu & page
	// -------------------------------------------------------------------------

	/**
	 * Register the plugin's settings page under Settings > WritersProof.
	 */
	public function add_menu_page(): void {
		$this->settings_hook = (string) add_options_page(
			__( 'WritersProof Settings', 'writersproof' ),
			__( 'WritersProof', 'writersproof' ),
			'manage_options',
			self::PAGE_SLUG,
			array( $this, 'render_settings_page' )
		);
	}

	/**
	 * Register settings, sections, and fields.
	 */
	public function register_settings(): void {
		// ----- API section -----
		add_settings_section(
			'writersproof_api',
			__( 'API Connection', 'writersproof' ),
			array( $this, 'render_api_section_intro' ),
			self::PAGE_SLUG
		);

		register_setting(
			self::OPTIONS_GROUP,
			'writersproof_api_key',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_api_key' ),
				'default'           => '',
			)
		);

		add_settings_field(
			'writersproof_api_key',
			__( 'API Key', 'writersproof' ),
			array( $this, 'render_api_key_field' ),
			self::PAGE_SLUG,
			'writersproof_api'
		);

		// ----- Behaviour section -----
		add_settings_section(
			'writersproof_behaviour',
			__( 'Witnessing Behaviour', 'writersproof' ),
			'__return_false',
			self::PAGE_SLUG
		);

		register_setting(
			self::OPTIONS_GROUP,
			'writersproof_auto_start',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => 'rest_sanitize_boolean',
				'default'           => true,
			)
		);

		add_settings_field(
			'writersproof_auto_start',
			__( 'Auto-start Witnessing', 'writersproof' ),
			array( $this, 'render_auto_start_field' ),
			self::PAGE_SLUG,
			'writersproof_behaviour'
		);

		register_setting(
			self::OPTIONS_GROUP,
			'writersproof_checkpoint_interval',
			array(
				'type'              => 'integer',
				'sanitize_callback' => array( $this, 'sanitize_checkpoint_interval' ),
				'default'           => 60,
			)
		);

		add_settings_field(
			'writersproof_checkpoint_interval',
			__( 'Checkpoint Interval (seconds)', 'writersproof' ),
			array( $this, 'render_checkpoint_interval_field' ),
			self::PAGE_SLUG,
			'writersproof_behaviour'
		);

		// ----- Post types section -----
		add_settings_section(
			'writersproof_post_types',
			__( 'Monitored Post Types', 'writersproof' ),
			array( $this, 'render_post_types_section_intro' ),
			self::PAGE_SLUG
		);

		register_setting(
			self::OPTIONS_GROUP,
			'writersproof_post_types',
			array(
				'type'              => 'array',
				'sanitize_callback' => array( $this, 'sanitize_post_types' ),
				'default'           => array( 'post', 'page' ),
			)
		);

		add_settings_field(
			'writersproof_post_types',
			__( 'Enable for', 'writersproof' ),
			array( $this, 'render_post_types_field' ),
			self::PAGE_SLUG,
			'writersproof_post_types'
		);
	}

	// -------------------------------------------------------------------------
	// Settings page rendering
	// -------------------------------------------------------------------------

	/**
	 * Output the full settings page HTML.
	 */
	public function render_settings_page(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		?>
		<div class="wrap writersproof-settings-wrap">
			<h1>
				<span class="writersproof-logo-inline">&#9997;</span>
				<?php esc_html_e( 'WritersProof Settings', 'writersproof' ); ?>
			</h1>

			<?php settings_errors( self::OPTIONS_GROUP ); ?>

			<form method="post" action="options.php" novalidate>
				<?php
				settings_fields( self::OPTIONS_GROUP );
				do_settings_sections( self::PAGE_SLUG );
				submit_button( __( 'Save Settings', 'writersproof' ) );
				?>
			</form>

			<hr />

			<h2><?php esc_html_e( 'Connection Test', 'writersproof' ); ?></h2>
			<p><?php esc_html_e( 'Test whether your API key is valid and the WritersProof API is reachable.', 'writersproof' ); ?></p>
			<button type="button" id="writersproof-test-connection" class="button button-secondary">
				<?php esc_html_e( 'Test Connection', 'writersproof' ); ?>
			</button>
			<span id="writersproof-test-result" class="writersproof-test-result" style="display:none;"></span>

			<script>
			( function () {
				document.getElementById( 'writersproof-test-connection' )
					.addEventListener( 'click', function () {
						var btn    = this;
						var result = document.getElementById( 'writersproof-test-result' );
						btn.disabled = true;
						result.textContent = '<?php echo esc_js( __( 'Testing…', 'writersproof' ) ); ?>';
						result.className   = 'writersproof-test-result writersproof-status-gray';
						result.style.display = 'inline-block';

						fetch( '<?php echo esc_url( rest_url( 'writersproof/v1/test' ) ); ?>', {
							method: 'GET',
							headers: {
								'X-WP-Nonce': '<?php echo esc_js( wp_create_nonce( 'wp_rest' ) ); ?>'
							}
						} )
						.then( function ( res ) { return res.json(); } )
						.then( function ( data ) {
							if ( data && data.ok ) {
								result.textContent = '<?php echo esc_js( __( 'Connected successfully.', 'writersproof' ) ); ?>';
								result.className   = 'writersproof-test-result writersproof-status-green';
							} else {
								result.textContent = ( data && data.message )
									? data.message
									: '<?php echo esc_js( __( 'Connection failed.', 'writersproof' ) ); ?>';
								result.className = 'writersproof-test-result writersproof-status-red';
							}
						} )
						.catch( function ( err ) {
							result.textContent = '<?php echo esc_js( __( 'Request error.', 'writersproof' ) ); ?>';
							result.className   = 'writersproof-test-result writersproof-status-red';
						} )
						.finally( function () {
							btn.disabled = false;
						} );
					} );
			} () );
			</script>
		</div>
		<?php
	}

	/**
	 * Render the API section description.
	 */
	public function render_api_section_intro(): void {
		echo '<p>' . wp_kses(
			sprintf(
				/* translators: %s: link to WritersLogic dashboard */
				__( 'Enter your API key from the <a href="%s" target="_blank" rel="noopener noreferrer">WritersLogic dashboard</a>.', 'writersproof' ),
				'https://writerslogic.com/dashboard'
			),
			array( 'a' => array( 'href' => array(), 'target' => array(), 'rel' => array() ) )
		) . '</p>';
	}

	/**
	 * Render the API key field.
	 */
	public function render_api_key_field(): void {
		$value = (string) get_option( 'writersproof_api_key', '' );
		// Show only the last 4 characters for security.
		$display = '' !== $value ? str_repeat( '*', max( 0, strlen( $value ) - 4 ) ) . substr( $value, -4 ) : '';
		?>
		<input
			type="password"
			id="writersproof_api_key"
			name="writersproof_api_key"
			value="<?php echo esc_attr( $value ); ?>"
			class="regular-text"
			autocomplete="new-password"
			placeholder="<?php esc_attr_e( 'wp_xxxxxxxxxxxxxxxx', 'writersproof' ); ?>"
		/>
		<?php if ( '' !== $display ) : ?>
			<p class="description">
				<?php
				echo esc_html(
					sprintf(
						/* translators: %s: masked API key suffix */
						__( 'Current key: %s', 'writersproof' ),
						$display
					)
				);
				?>
			</p>
		<?php endif; ?>
		<?php
	}

	/**
	 * Render the auto-start checkbox.
	 */
	public function render_auto_start_field(): void {
		$checked = (bool) get_option( 'writersproof_auto_start', true );
		?>
		<label for="writersproof_auto_start">
			<input
				type="checkbox"
				id="writersproof_auto_start"
				name="writersproof_auto_start"
				value="1"
				<?php checked( $checked ); ?>
			/>
			<?php esc_html_e( 'Automatically begin witnessing when the editor opens', 'writersproof' ); ?>
		</label>
		<p class="description">
			<?php esc_html_e( 'When enabled, WritersProof starts capturing timing metadata as soon as you open a post for editing.', 'writersproof' ); ?>
		</p>
		<?php
	}

	/**
	 * Render the checkpoint interval number input.
	 */
	public function render_checkpoint_interval_field(): void {
		$value = (int) get_option( 'writersproof_checkpoint_interval', 60 );
		?>
		<input
			type="number"
			id="writersproof_checkpoint_interval"
			name="writersproof_checkpoint_interval"
			value="<?php echo esc_attr( (string) $value ); ?>"
			min="10"
			max="3600"
			step="5"
			class="small-text"
		/>
		<p class="description">
			<?php esc_html_e( 'How often (in seconds) WritersProof sends a checkpoint to the API. Minimum 10, maximum 3600.', 'writersproof' ); ?>
		</p>
		<?php
	}

	/**
	 * Render the post types section description.
	 */
	public function render_post_types_section_intro(): void {
		echo '<p>' . esc_html__( 'Choose which post types WritersProof should monitor for authorship evidence.', 'writersproof' ) . '</p>';
	}

	/**
	 * Render the post types checkbox list.
	 */
	public function render_post_types_field(): void {
		$selected = (array) get_option( 'writersproof_post_types', array( 'post', 'page' ) );
		$types    = get_post_types( array( 'public' => true ), 'objects' );

		foreach ( $types as $type ) {
			$checked = in_array( $type->name, $selected, true );
			?>
			<label style="display:block; margin-bottom:4px;">
				<input
					type="checkbox"
					name="writersproof_post_types[]"
					value="<?php echo esc_attr( $type->name ); ?>"
					<?php checked( $checked ); ?>
				/>
				<?php echo esc_html( $type->label ); ?>
				<code style="color:#666; font-size:0.85em;">(<?php echo esc_html( $type->name ); ?>)</code>
			</label>
			<?php
		}
	}

	// -------------------------------------------------------------------------
	// Meta box
	// -------------------------------------------------------------------------

	/**
	 * Register the WritersProof meta box on monitored post types.
	 */
	public function add_meta_boxes(): void {
		$types = (array) get_option( 'writersproof_post_types', array( 'post', 'page' ) );

		foreach ( $types as $type ) {
			add_meta_box(
				'writersproof_status',
				__( 'WritersProof Attestation', 'writersproof' ),
				array( $this, 'render_meta_box' ),
				$type,
				'side',
				'default'
			);
		}
	}

	/**
	 * Render the WritersProof status meta box.
	 *
	 * @param WP_Post $post Current post object.
	 */
	public function render_meta_box( WP_Post $post ): void {
		$session_id = (string) get_post_meta( $post->ID, '_writersproof_session_id', true );
		$status     = (string) get_post_meta( $post->ID, '_writersproof_status', true );
		$score      = get_post_meta( $post->ID, '_writersproof_evidence_score', true );
		$api_key    = get_option( 'writersproof_api_key', '' );

		$status_label = match ( $status ) {
			'active'    => __( 'Active', 'writersproof' ),
			'finalized' => __( 'Finalized', 'writersproof' ),
			'stopped'   => __( 'Stopped', 'writersproof' ),
			default     => __( 'Not started', 'writersproof' ),
		};
		$status_class = match ( $status ) {
			'active'    => 'writersproof-status-green',
			'finalized' => 'writersproof-status-green',
			'stopped'   => 'writersproof-status-gray',
			default     => 'writersproof-status-gray',
		};
		?>
		<div class="writersproof-meta-box">
			<?php if ( empty( $api_key ) ) : ?>
				<div class="writersproof-notice writersproof-notice-warning">
					<?php
					echo wp_kses(
						sprintf(
							/* translators: %s: settings page URL */
							__( '<strong>WritersProof:</strong> No API key configured. <a href="%s">Add your API key</a> to enable attestation.', 'writersproof' ),
							esc_url( admin_url( 'options-general.php?page=writersproof-settings' ) )
						),
						array(
							'strong' => array(),
							'a'      => array( 'href' => array() ),
						)
					);
					?>
				</div>
			<?php else : ?>
				<table class="writersproof-meta-table">
					<tr>
						<th><?php esc_html_e( 'Status', 'writersproof' ); ?></th>
						<td>
							<span class="writersproof-status-badge <?php echo esc_attr( $status_class ); ?>">
								<?php echo esc_html( $status_label ); ?>
							</span>
						</td>
					</tr>
					<?php if ( '' !== $session_id ) : ?>
					<tr>
						<th><?php esc_html_e( 'Session', 'writersproof' ); ?></th>
						<td><code class="writersproof-session-id"><?php echo esc_html( $this->truncate_id( $session_id ) ); ?></code></td>
					</tr>
					<?php endif; ?>
					<?php if ( null !== $score && '' !== $score ) : ?>
					<tr>
						<th><?php esc_html_e( 'Evidence Score', 'writersproof' ); ?></th>
						<td>
							<span class="writersproof-score"><?php echo esc_html( (string) $score ); ?>/100</span>
						</td>
					</tr>
					<?php endif; ?>
				</table>

				<div class="writersproof-meta-actions" id="writersproof-meta-actions" data-post-id="<?php echo esc_attr( (string) $post->ID ); ?>">
					<?php if ( 'active' === $status ) : ?>
						<button type="button" class="button button-secondary writersproof-action" data-action="stop">
							<?php esc_html_e( 'Stop Witnessing', 'writersproof' ); ?>
						</button>
					<?php elseif ( 'finalized' !== $status ) : ?>
						<button type="button" class="button button-primary writersproof-action" data-action="start">
							<?php esc_html_e( 'Start Witnessing', 'writersproof' ); ?>
						</button>
					<?php endif; ?>

					<?php if ( '' !== $session_id ) : ?>
						<a
							href="<?php echo esc_url( rest_url( 'writersproof/v1/evidence/' . $post->ID ) ); ?>"
							class="button button-secondary"
							target="_blank"
							rel="noopener noreferrer"
						>
							<?php esc_html_e( 'View Evidence', 'writersproof' ); ?>
						</a>
					<?php endif; ?>
				</div>

				<div id="writersproof-meta-message" class="writersproof-meta-message" style="display:none;"></div>

				<script>
				( function () {
					var container = document.getElementById( 'writersproof-meta-actions' );
					if ( ! container ) return;

					container.addEventListener( 'click', function ( e ) {
						var btn = e.target.closest( '.writersproof-action' );
						if ( ! btn ) return;

						var action  = btn.dataset.action;
						var postId  = container.dataset.postId;
						var msg     = document.getElementById( 'writersproof-meta-message' );
						var nonce   = '<?php echo esc_js( wp_create_nonce( 'wp_rest' ) ); ?>';
						var restUrl = '<?php echo esc_js( rest_url( 'writersproof/v1' ) ); ?>';

						btn.disabled = true;
						msg.style.display = 'none';

						var endpoint = restUrl + '/session/' + ( 'start' === action ? 'start' : 'stop' );

						fetch( endpoint, {
							method: 'POST',
							headers: {
								'Content-Type':  'application/json',
								'X-WP-Nonce':    nonce
							},
							body: JSON.stringify( { post_id: parseInt( postId, 10 ) } )
						} )
						.then( function ( res ) { return res.json(); } )
						.then( function ( data ) {
							msg.style.display = 'block';
							if ( data && data.success ) {
								msg.className = 'writersproof-meta-message writersproof-msg-ok';
								msg.textContent = data.message || '<?php echo esc_js( __( 'Done.', 'writersproof' ) ); ?>';
								// Reload after a short delay to refresh meta box state.
								setTimeout( function () { location.reload(); }, 1200 );
							} else {
								msg.className = 'writersproof-meta-message writersproof-msg-error';
								msg.textContent = ( data && data.message )
									? data.message
									: '<?php echo esc_js( __( 'An error occurred.', 'writersproof' ) ); ?>';
								btn.disabled = false;
							}
						} )
						.catch( function () {
							msg.style.display = 'block';
							msg.className = 'writersproof-meta-message writersproof-msg-error';
							msg.textContent = '<?php echo esc_js( __( 'Request failed.', 'writersproof' ) ); ?>';
							btn.disabled = false;
						} );
					} );
				} () );
				</script>
			<?php endif; ?>
		</div>
		<?php
	}

	// -------------------------------------------------------------------------
	// Admin notices
	// -------------------------------------------------------------------------

	/**
	 * Show a notice prompting users to configure the API key after activation.
	 */
	public function maybe_show_setup_notice(): void {
		$screen = get_current_screen();
		if ( ! $screen || 'settings_page_writersproof-settings' === $screen->id ) {
			return;
		}

		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$api_key = get_option( 'writersproof_api_key', '' );
		if ( '' !== $api_key ) {
			return;
		}

		// Only show once per session (transient).
		if ( get_transient( 'writersproof_setup_notice_dismissed' ) ) {
			return;
		}
		?>
		<div class="notice notice-info is-dismissible writersproof-setup-notice">
			<p>
				<?php
				echo wp_kses(
					sprintf(
						/* translators: %s: settings page URL */
						__( '<strong>WritersProof</strong> is active but not configured. <a href="%s">Add your API key</a> to begin authorship attestation.', 'writersproof' ),
						esc_url( admin_url( 'options-general.php?page=writersproof-settings' ) )
					),
					array(
						'strong' => array(),
						'a'      => array( 'href' => array() ),
					)
				);
				?>
			</p>
		</div>
		<?php
	}

	// -------------------------------------------------------------------------
	// Sanitization callbacks
	// -------------------------------------------------------------------------

	/**
	 * Sanitize the API key setting.
	 *
	 * @param mixed $value Raw input value.
	 * @return string Sanitized API key.
	 */
	public function sanitize_api_key( mixed $value ): string {
		$key = sanitize_text_field( (string) $value );

		// Basic structure check: must be non-empty alphanumeric + hyphens/underscores.
		if ( '' !== $key && ! preg_match( '/^[A-Za-z0-9\-_]+$/', $key ) ) {
			add_settings_error(
				'writersproof_api_key',
				'invalid_api_key',
				__( 'API key contains invalid characters. Only letters, numbers, hyphens, and underscores are allowed.', 'writersproof' )
			);
			return (string) get_option( 'writersproof_api_key', '' );
		}

		return $key;
	}

	/**
	 * Sanitize the checkpoint interval setting.
	 *
	 * @param mixed $value Raw input value.
	 * @return int Sanitized interval, clamped to [10, 3600].
	 */
	public function sanitize_checkpoint_interval( mixed $value ): int {
		$int = (int) $value;
		return max( 10, min( 3600, $int ) );
	}

	/**
	 * Sanitize the post types array setting.
	 *
	 * @param mixed $value Raw input value (may be array or null if no checkboxes ticked).
	 * @return array<int, string> Sanitized list of valid post type slugs.
	 */
	public function sanitize_post_types( mixed $value ): array {
		if ( ! is_array( $value ) ) {
			return array();
		}

		$valid = array_keys( get_post_types( array( 'public' => true ) ) );
		$out   = array();

		foreach ( $value as $slug ) {
			$slug = sanitize_key( (string) $slug );
			if ( in_array( $slug, $valid, true ) ) {
				$out[] = $slug;
			}
		}

		return array_values( array_unique( $out ) );
	}

	// -------------------------------------------------------------------------
	// Helpers
	// -------------------------------------------------------------------------

	/**
	 * Truncate a session ID for display (first 8 + last 4 chars).
	 *
	 * @param string $id Session ID string.
	 * @return string Truncated representation.
	 */
	private function truncate_id( string $id ): string {
		if ( strlen( $id ) <= 14 ) {
			return $id;
		}
		return substr( $id, 0, 8 ) . '…' . substr( $id, -4 );
	}
}
