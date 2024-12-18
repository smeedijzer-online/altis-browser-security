<?php

namespace Smeedijzer\Security\Browser;

use Smeedijzer;
use WP_Dependencies;
use WP_Error;
use WP_Http;

const INTEGRITY_DATA_KEY    = 'smeedijzer_integrity_hash';
const INTEGRITY_HASH_ALGO   = 'sha384';
const INTEGRITY_CACHE_GROUP = 'smeedijzer_integrity';

const INTERNAL_SCRIPT_REGEX   = '/<(script)((?:(?!nonce).)*?)>/';
//const INTERNAL_SCRIPT_REGEX = '/<(script)((?:(?!nonce|src).)*?)>/';
const INTERNAL_STYLE_REGEX    = '/<(style)((?:(?!nonce).)*?)>/';

const EVENT_ATTRIBUTE_REGEX = '/<[^>]*\bid\s*=\s*[\'"](?<id>[^\'"]+)[\'"][^>]*(?<event>on(?:click|change|submit|mouseover|mouseout|load|focus|blur|keydown|keyup|keypress|contextmenu))\s*=\s*[\'"](?<script>.*?)[\'"][^>]*>/im';
const INLINE_STYLE_REGEX = '/<(?<tag>[a-zA-Z0-9]+)(?=[^>]*\bstyle\s*=\s*[\'"](?<style>[^\'"]*?)[\'"])(?:[^>]*\bid\s*=\s*[\'"](?<id>[^\'"]+)[\'"])?[^>]*>/im';



$GLOBALS['bs_injected_inline_script'] = '';
$GLOBALS['bs_injected_inline_style']  = '';

/**
 * Bootstrap.
 *
 * @param array $config {
 *   @var bool $automatic-integrity True to enable automatic generation of integrity hashes, false to disable. (True by default.)
 * }
 */
function bootstrap( array $config ) {

	if ( $config['automatic-integrity'] ?? true ) {
        add_filter('script_loader_tag', __NAMESPACE__ . '\\generate_hash_for_script', 0, 3);
        add_filter('style_loader_tag', __NAMESPACE__ . '\\generate_hash_for_style', 0, 3);
	}

	if ( $config['nosniff-header'] ?? true ) {
		add_action( 'template_redirect', 'send_nosniff_header' );
	}

	if ( $config['frame-options-header'] ?? true ) {
		add_action( 'template_redirect', __NAMESPACE__ . '\\maybe_send_frame_options_header' );
	}

	if ( $config['xss-protection-header'] ?? true ) {
        add_action('template_redirect', __NAMESPACE__ . '\\send_xss_protection_header');
	}

    $use_referrer_header = $config['referrer-policy-header'] ?? true;

	if ( $use_referrer_header ) {
		add_action( 'template_redirect', function () use ( $use_referrer_header ) {
            send_referrer_policy_header($use_referrer_header);
		} );
	}

	// ?
	//add_action('send_headers', function ()  {
	//	send_origin_headers();
	//} );

	if ( $config['content-security-policy'] ?? null ) {
		add_filter( 'smeedijzer.security.browser.content_security_policies', function ( $policies ) use ( $config ) {
			return array_merge( $policies, $config['content-security-policy'] );
		}, 0 );
	}

	if ( $config['report-only-content-security-policy'] ?? null ) {
		add_filter( 'smeedijzer.security.browser.report_only_content_security_policies', function ( $policies ) use ( $config ) {
			return array_merge( $policies, $config['report-only-content-security-policy'] );
		}, 0 );
	}

	if ( $config['convert-event-handler-attributes'] ?? null ) {
		add_filter( 'filter_output_final_output', __NAMESPACE__ . '\\convert_event_handler_attributes', 1, 1 );
		add_filter( 'filter_output_final_output', __NAMESPACE__ . '\\inject_dynamic_inline_scripts', 5, 1 );
	}

	if ( $config['convert-inline-style-attributes'] ?? null ) {
		add_filter( 'filter_output_final_output', __NAMESPACE__ . '\\convert_inline_style_attributes', 10, 1 );
		add_filter( 'filter_output_final_output', __NAMESPACE__ . '\\inject_dynamic_inline_styles', 15, 1 );
	}

	if ( $config['nonce-for-inline-script-tags'] ?? null ) {
		add_filter( 'filter_output_final_output', __NAMESPACE__ . '\\inject_nonce_for_inline_script_tags', 20, 1 );
	}

	if ( $config['nonce-for-internal-style-tags'] ?? null ) {
		add_filter( 'filter_output_final_output', __NAMESPACE__ . '\\inject_nonce_for_internal_style_tags', 30, 1 );
	}

	$use_hsts = $config['strict-transport-security'] ?? null;

	// Default to on for HTTPS sites.
	if ( $use_hsts === null ) {
		$use_hsts = is_ssl();
	}

	if ( $use_hsts ) {
		add_action( 'parse_request', function () use ( $use_hsts ) {
			send_hsts_header( $use_hsts );
		}, -1000 );
		add_action( 'admin_init', function () use ( $use_hsts ) {
			send_hsts_header( $use_hsts );
		} );
		add_action( 'login_init', function () use ( $use_hsts ) {
			send_hsts_header( $use_hsts );
		} );
	}

	add_filter( 'script_loader_tag', __NAMESPACE__ . '\\output_integrity_for_script', 0, 2 );
	add_filter( 'style_loader_tag', __NAMESPACE__ . '\\output_integrity_for_style', 0, 3 );
	add_action( 'template_redirect', __NAMESPACE__ . '\\send_enforced_csp_header' );
	add_action( 'template_redirect', __NAMESPACE__ . '\\send_report_only_csp_header' );

	if ( has_filter( 'smeedijzer.security.browser.rest_allow_origin' ) ) {
		add_filter( 'rest_pre_dispatch', __NAMESPACE__ . '\\restrict_cors_origin' );
	}

	// Register cache group as global (as it's path-based rather than data-based).
	wp_cache_add_global_groups( INTEGRITY_CACHE_GROUP );
}

function get_nonce_value(): string
{
	static $nonce = null;

	if ( $nonce === null ) {
		$nonce = bin2hex( openssl_random_pseudo_bytes( 32 ) ); // https://content-security-policy.com/nonce/
	}

	return $nonce;
}

function convert_event_handler_attributes( $buffer )
{
	$replacement = static function ( $matches ) {
		$event_listener = substr( $matches['event'], 2 ) ?? null;
		$script         = $matches['script'] ?? null;
		$tag_id         = $matches['id'] ?? null;

		if ( empty( $event_listener ) || empty( $script ) ) {
			return $matches[0];
		}

		if ( empty( $tag_id ) ) {
			// Generate a unique ID if none exists
			$tag_id = 'csp_safe_' . md5( $script );
			// Add the ID to the tag
			$matches[0] = preg_replace( '/^<([a-zA-Z]+)/', '<$1 id="' . $tag_id . '"', $matches[0] );
		}

		// Remove the inline event handler
		$tag = preg_replace( '/\s*on[a-z]+\s*=\s*(?:\'|")[^\'"]*(?:\'|")/', '', $matches[0] );

		// Create the external script with an event listener
		$inline_script = "document.getElementById(\"$tag_id\").addEventListener(\"$event_listener\", function() {\n\t$script;\n});\n";

		$GLOBALS['bs_injected_inline_script'] .= $inline_script;

		return $tag;
	};

	return preg_replace_callback( EVENT_ATTRIBUTE_REGEX, $replacement, $buffer );
}

function inject_dynamic_inline_scripts( $buffer )
{
	$script_line = $GLOBALS['bs_injected_inline_script'];

	if ( empty( $script_line ) ) {
		return $buffer;
	}

	$script_tag = "<script>\n$script_line\n</script>";

	// Inject the dynamic inline scripts at the end of the body
	$buffer = preg_replace( '/<\/body>/', $script_tag . '</body>', $buffer );

	return $buffer;
}


function convert_inline_style_attributes( $buffer ) {
	$replacement = static function ( $matches ) {
		$tag   = $matches['tag'] ?? null;
		$style = $matches['style'] ?? null;
		$id    = $matches['id'] ?? null;

		if ( empty( $tag ) || empty( $style ) ) {
			return $matches[0];
		}

		if ( empty( $id ) ) {
			// Generate a unique ID if none exists
			$id = 'csp_safe_' . md5( $style );
			// Add the ID to the tag
			$matches[0] = preg_replace( '/^<([a-zA-Z]+)/', '<$1 id="' . $id . '"', $matches[0] );
		}

		// Remove the inline style
		$tag = preg_replace( '/\s*style\s*=\s*(?:\'|")[^\'"]*(?:\'|")/', '', $matches[0] );

		// Create the external style
		$inline_style = "#$id {\n\t$style\n}\n";

		$GLOBALS['bs_injected_inline_style'] .= $inline_style;

		return $tag;
	};

	return preg_replace_callback( INLINE_STYLE_REGEX, $replacement, $buffer );
}

function inject_dynamic_inline_styles( $buffer ) {
	$style_line = $GLOBALS['bs_injected_inline_style'];

	if ( empty( $style_line ) ) {
		return $buffer;
	}

	$style_tag = "<style>\n$style_line\n</style>";

	// Inject the dynamic inline styles at the end of the head
	$buffer = preg_replace( '/<\/head>/', $style_tag . '</head>', $buffer );

	return $buffer;
}

function inject_nonce_for_inline_script_tags( $buffer )
{
	$nonce = get_nonce_value();

	$buffer = preg_replace_callback( INTERNAL_SCRIPT_REGEX, static function ( $matches ) use ( $nonce ) {
		return str_replace( '<script', '<script nonce="' . $nonce . '"', $matches[0] );
	}, $buffer );

	return $buffer;
}

function inject_nonce_for_internal_style_tags( $buffer )
{
	$nonce = get_nonce_value();

	$buffer = preg_replace_callback( INTERNAL_STYLE_REGEX, static function ( $matches ) use ( $nonce ) {
		return str_replace( '<style', '<style nonce="' . $nonce . '"', $matches[0] );
	}, $buffer );

	return $buffer;
}


/**
 * Generate an integrity hash for a given path.
 *
 * Provides the `smeedijzer.security.browser.pre_generate_hash_for_path` filter to
 * allow shortcircuiting hash generation if using external build tools
 * or caching.
 *
 * @param string $path Absolute path to a file to get the hash for.
 * @param string $version Version of the hash, used as part of the cache key.
 * @return string|null Integrity hash (in format "<algo>-<hash>") if available, or null if it could not be generated.
 */
function generate_hash_for_path( string $path, ?string $version = null ) : ?string {
	$hash = apply_filters( 'smeedijzer.security.browser.pre_generate_hash_for_path', null, $path, $version );
	if ( ! empty( $hash ) ) {
		return $hash;
	}

	// Load from cache if possible.
	$cache_key = sha1( sprintf( '%s?%s', $path, $version ) );
	$cached = wp_cache_get( $cache_key, INTEGRITY_CACHE_GROUP );
	if ( ! empty( $cached ) ) {
		return $cached;
	}

	$data = file_get_contents( $path );
	$hash = hash( INTEGRITY_HASH_ALGO, $data, true );
	$value = INTEGRITY_HASH_ALGO . '-' . base64_encode( $hash );
	$value = apply_filters( 'smeedijzer.security.browser.generate_hash_for_path', $value, $path, $version );

	// Cache.
	wp_cache_set( $cache_key, $value, INTEGRITY_CACHE_GROUP, time() + YEAR_IN_SECONDS );

	return $value;
}

/**
 * Automatically generate hash for a stylesheet.
 *
 * Hooked into `style_loader_tag` to automatically generate hashes for
 * stylesheets on the filesystem.
 *
 * @param string $html Stylesheet HTML tag.
 * @param string $handle Unique handle for the stylesheet.
 * @param string $href URL for the stylesheet.
 * @return string Unaltered stylesheet HTML tag.
 */
function generate_hash_for_style( string $html, string $handle, string $href ) : string {
	global $wp_styles;

    $err = generate_hash_for_asset($wp_styles, $handle, $href);
	if ( is_wp_error( $err ) ) {
		trigger_error( sprintf( 'Style %s error [%s]: %s', $handle, $err->get_error_code(), $err->get_error_message() ), E_USER_NOTICE );
	}

	return $html;
}

/**
 * Automatically generate hash for a script.
 *
 * Hooked into `script_loader_tag` to automatically generate hashes for
 * scripts on the filesystem.
 *
 * @param string $html Stylesheet HTML tag.
 * @param string $handle Unique handle for the stylesheet.
 * @param string $href URL for the stylesheet.
 * @return string Unaltered stylesheet HTML tag.
 */
function generate_hash_for_script( string $tag, string $handle, string $src ) : string {
	global $wp_scripts;

    $err = generate_hash_for_asset($wp_scripts, $handle, $src);
	if ( is_wp_error( $err ) ) {
		trigger_error( sprintf( 'Script %s error [%s]: %s', $handle, $err->get_error_code(), $err->get_error_message() ), E_USER_NOTICE );
	}

	return $tag;
}

/**
 * Automatically generate hash for an asset.
 *
 * @param WP_Dependencies $dependencies
 * @param string $handle
 * @return WP_Error|null Error if one occurred, or null if successful.
 */
function generate_hash_for_asset( WP_Dependencies $dependencies, string $handle ) : ?WP_Error {
	$asset = $dependencies->query( $handle );
	if ( ! $asset ) {
		return new WP_Error(
			'smeedijzer.security.browser.invalid_asset_handle',
			sprintf(
				'Invalid asset handle %s',
				$handle
			)
		);
	}

	// Translate the script back to a path if possible.
	$src = $asset->src;
	$site_url = trailingslashit( site_url() );

	$is_core_rel_url = str_starts_with( $src, '/wp-includes/' ) || str_starts_with( $src, '/wp-admin/' );

	if ( $is_core_rel_url ) {
		$src = site_url($src);
	}

	if ( substr( $src, 0, strlen( $site_url ) ) !== $site_url ) {
		// Not a local asset, skip.
		return null;
	}

	$rel_path = substr( $src, strlen( $site_url ) );
	$query = '';
	if ( strpos( $rel_path, '?' ) !== false ) {
		list( $rel_path, $query ) = explode( '?', $rel_path, 2 );
	}

	if ( path_is_absolute( $rel_path ) || strpos( $rel_path, '../' ) !== false ) {
		// Invalid relative path.
		return new WP_Error(
			'smeedijzer.security.browser.invalid_path',
			sprintf(
				'Path "%s" for %s is invalid',
				$src,
				$handle
			),
			compact( 'handle', 'src' )
		);
	}

	// Determine root directory.
	if ( defined( 'Smeedijzer\\ROOT_DIR' ) ) {
		$root = Smeedijzer\ROOT_DIR;
	} else {
		// Either ABSPATH or directory above.
		if ( file_exists( ABSPATH . '/wp-config.php' ) ) {
			$root = ABSPATH;
		} else {
			$root = dirname( ABSPATH );
		}
	}

	if ( $root !== ABSPATH && substr( $rel_path, 0, 3 ) === 'wp-' ) {
		// Core asset, use ABSPATH instead.
		$root = ABSPATH;
	}

	$actual_path = path_join( $root, $rel_path );
	if ( ! file_exists( $actual_path ) ) {
		// Invalid path.
		return new WP_Error(
			'smeedijzer.security.browser.file_not_exists',
			sprintf( 'File for %s does not exist', $handle )
		);
	}

	// Generate the hash.
	$hash = generate_hash_for_path( $actual_path, $asset->ver );
	if ( empty( $hash ) ) {
		// Couldn't generate a hash.
		return new WP_Error(
			'smeedijzer.security.browser.could_not_generate_hash',
			sprintf( 'Could not generate hash for %s', $handle )
		);
	}

	$did_set = set_hash_for_asset( $dependencies, $handle, $hash );
	if ( ! $did_set ) {
		// Couldn't set the hash.
		return new WP_Error(
			'smeedijzer.security.browser.could_not_set_hash',
			sprintf( 'Could not set hash for %s', $handle )
		);
	}

	return null;
}

/**
 * Get the integrity hash for a script.
 *
 * Use `set_hash_for_script()` to set the integrity hash for a script.
 *
 * @param string $handle Unique script handle.
 * @return string|null Integrity hash if set, null otherwise.
 */
function get_hash_for_script( string $handle ) : ?string {
	global $wp_scripts;
	return get_hash_for_asset( $wp_scripts, $handle );
}

/**
 * Get the integrity hash for a style.
 *
 * Use `set_hash_for_style()` to set the integrity hash for a style.
 *
 * @param string $handle Unique style handle.
 * @return string|null Integrity hash if set, null otherwise.
 */
function get_hash_for_style( string $handle ) : ?string {
	global $wp_styles;
	return get_hash_for_asset( $wp_styles, $handle );
}

/**
 * Get the integrity hash for an asset.
 *
 * Use `set_hash_for_asset()` to set the integrity hash for an asset.
 *
 * @param WP_Dependencies $dependencies Dependency registry to use.
 * @param string $handle Unique asset handle.
 * @return string|null Integrity hash if set, null otherwise.
 */
function get_hash_for_asset( WP_Dependencies $dependencies, string $handle ) : ?string {
	return $dependencies->get_data( $handle, INTEGRITY_DATA_KEY ) ?? null;
}

/**
 * Set the integrity hash for a script.
 *
 * @param string $handle Unique script handle.
 * @param string $hash Integrity hash (in format "<algo>-<hash>").
 * @return boolean True if the hash was set correctly, false otherwise.
 */
function set_hash_for_script( string $handle, string $hash ) : bool {
	global $wp_scripts;
	return set_hash_for_asset( $wp_scripts, $handle, $hash );
}

/**
 * Set the integrity hash for a stylesheet.
 *
 * @param string $handle Unique style handle.
 * @param string $hash Integrity hash (in format "<algo>-<hash>").
 * @return boolean True if the hash was set correctly, false otherwise.
 */
function set_hash_for_style( string $handle, string $hash ) : bool {
	global $wp_styles;
	return set_hash_for_asset( $wp_styles, $handle, $hash );
}

/**
 * Set the integrity hash for an asset.
 *
 * @param WP_Dependencies $dependencies Dependency registry to use.
 * @param string $handle Unique asset handle.
 * @param string $hash Integrity hash (in format "<algo>-<hash>").
 * @return boolean True if the hash was set correctly, false otherwise.
 */
function set_hash_for_asset( WP_Dependencies $dependencies, string $handle, string $hash ) : bool {
	return $dependencies->add_data( $handle, INTEGRITY_DATA_KEY, $hash );
}

/**
 * Output the integrity hash for a script.
 *
 * This is automatically added to the `script_loader_tag` filter. Use
 * `set_hash_for_script()` to set the integrity hash for a script.
 *
 * @param string $tag Script HTML tag.
 * @param string $handle Unique script handle.
 * @return string Script tag with `integrity` attribute set if available.
 */
function output_integrity_for_script( string $tag, string $handle ) : string {
	$hash = get_hash_for_script( $handle );
	if ( empty( $hash ) ) {
		return $tag;
	}

	// Insert the attribute.
	$tag = str_replace(
		" src=",
		sprintf(
			" integrity='%s' src=",
			esc_attr( $hash )
		),
		$tag
	);

	return $tag;
}

/**
 * Output the integrity hash for a stylesheet.
 *
 * This is automatically added to the `style_loader_tag` filter. Use
 * `set_hash_for_style()` to set the integrity hash for a stylesheet.
 *
 * @param string $html Stylesheet HTML tag.
 * @param string $handle Unique style handle.
 * @return string Stylesheet tag with `integrity` attribute set if available.
 */
function output_integrity_for_style( string $html, string $handle ) : string {
    $hash = get_hash_for_style($handle);
	if ( empty( $hash ) ) {
		return $html;
	}

	// Insert the attribute.
	$html = str_replace(
		" href='",
		sprintf(
			" integrity='%s' href='",
			esc_attr( $hash )
		),
		$html
	);
	return $html;
}

/**
 * Send XSS protection header for legacy browsers.
 *
 * This is deprecated, but some browsers still want it. Additionally, this is
 * often tested in automated security checks.
 *
 * @link https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection
 */
function send_xss_protection_header() {
	header( 'X-XSS-Protection: 1; mode=block' );
}

/**
 * Send HSTS protection header to force SSL.
 */
function send_hsts_header( $value ) {
	// Use default if just enabled.
	if ( $value === true ) {
		$value = 'max-age=86400';
	}

	header( sprintf( 'Strict-Transport-Security: %s', $value ) );
}

/**
 * Send Referrer-Policy header.
 *
 * @param string $value Referrer-Policy value.
 */
function send_referrer_policy_header($value) {
	if ( $value === true ) {
		$value = 'same-origin';
	}

	header( sprintf( 'Referrer-Policy: %s', $value ) );
}

/**
 * Send the frame options header for non-embed pages.
 *
 * The embed page specifically needs to be allowed in frames, but other pages
 * should not be by default.
 */
function maybe_send_frame_options_header() {
	if ( is_embed() ) {
		return;
	}

	send_frame_options_header();
}

/**
 * Filter an individual policy value.
 *
 * @param string       $name        Directive name.
 * @param string|array $value       Directive value.
 * @param bool         $report_only Whether the directive is being filtered for
 *                                  use in a Report-Only policy. (False by default.)
 * @return string[] List of directive values.
 */
function filter_policy_value( string $name, $value, bool $report_only = false ) : array {
	$value = (array) $value;

	$needs_quotes = [
		'self',
		'unsafe-inline',
		'unsafe-eval',
		'unsafe-hashes',
		'none',
		'strict-dynamic',
		'report-sample',
	];

	// Normalize directive values.
	foreach ( $value as &$item ) {
		$set_nonce = str_starts_with( $item, 'set-nonce' );

		if($set_nonce) {
			$item = str_replace( 'set-nonce', 'nonce-'. get_nonce_value(), $item );
		}

		$is_nonce = str_starts_with( $item, 'nonce-' );
		$is_hash = str_starts_with( $item, 'sha' );

		if ( $is_nonce || $is_hash || in_array( $item, $needs_quotes, true ) ) {
			// Add missing quotes if the value was erroneously added
			// without them.
			$item = sprintf( "'%s'", $item );
		}
	}

	if ( $report_only ) {
		/**
		 * Filter value for a given report-only policy directive.
		 *
		 * `$name` is the directive name.
		 *
		 * @param array $value List of directive values.
		 */
		$value = apply_filters( "smeedijzer.security.browser.filter_report_only_policy_value.$name", $value );

		/**
		 * Filter value for a given report-only policy directive.
		 *
		 * @param array $value List of directive values.
		 * @param string $name Directive name.
		 */
		return apply_filters( 'smeedijzer.security.browser.filter_report_only_policy_value', $value, $name );
	}

	/**
	 * Filter value for a given policy directive.
	 *
	 * `$name` is the directive name.
	 *
	 * @param array $value List of directive values.
	 */
	$value = apply_filters( "smeedijzer.security.browser.filter_policy_value.$name", $value );

	/**
	 * Filter value for a given policy directive.
	 *
	 * @param array $value List of directive values.
	 * @param string $name Directive name.
	 */
	return apply_filters( 'smeedijzer.security.browser.filter_policy_value', $value, $name );
}

/**
 * Send the Content-Security-Policy header.
 *
 * The header is only sent if policies have been specified. See
 * get_content_security_policies() for setting the policies.
 */
function send_enforced_csp_header() {
	// Gather and filter the policy parts.
	$policies = get_content_security_policies();
	send_content_security_policy_header( 'Content-Security-Policy', $policies );
}

/**
 * Send the Content-Security-Policy-Report-Only header.
 *
 * The header is only sent if policies have been specified. See
 * get_report_only_content_security_policies() for setting the policies.
 */
function send_report_only_csp_header() {
	// Gather and filter the report-only policy parts.
	$policies = get_report_only_content_security_policies();
	send_content_security_policy_header( 'Content-Security-Policy-Report-Only', $policies );
}

/**
 * Send the Content-Security-Policy or Content-Security-Policy-Report-Only headers.
 *
 * The header is only sent if policies have been specified. See
 * get_content_security_policies() and get_report_only_content_security_policies()
 * for setting the policies.
 *
 * @param string[] $policies The policies to apply for the specified header.
 * @param string   $header   One of 'Content-Security-Policy' or
 *                           'Content-Security-Policy-Report-Only'.
 * @return void Sends CSP header and exits.
 */
function send_content_security_policy_header( string $header, array $policies ) {
	$report_only = $header === 'Content-Security-Policy-Report-Only';
	$policy_parts = [];
	foreach ( $policies as $key => $value ) {
		$value = filter_policy_value( $key, $value, $report_only );
		if ( empty( $value ) ) {
			continue;
		}
		$policy_parts[] = sprintf( '%s %s', $key, implode( ' ', $value ) );
	}
	if ( empty( $policy_parts ) ) {
		return;
	}

	header( $header . ': ' . implode( '; ', $policy_parts ) );
}

/**
 * Return an array of CSP directives for use in CSP and CSP-Report-Only headers.
 *
 * @return array Map of directive names to empty arrays.
 */
function get_content_security_policy_directives() : array {
	return [
		'child-src' => [],
		'font-src' => [],
		'frame-src' => [],
		'img-src' => [],
		'media-src' => [],
		'object-src' => [],
		'script-src' => [],
		'style-src' => [],
	];
}

/**
 * Get the content security policies for the current page.
 *
 * @return array Map from directive name to value or list of values.
 */
function get_content_security_policies() : array {
	$policies = get_content_security_policy_directives();

	/**
	 * Filter the security policies for the current page.
	 *
	 * The filtered value is a map from directive name (e.g. `base-uri`,
	 * `default-src`) to directive value. Each directive value can be a string
	 * or list of strings.
	 *
	 * @link https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy
	 *
	 * @param string[] $policies Map from directive name to value or list of values.
	 */
	return apply_filters( 'smeedijzer.security.browser.content_security_policies', $policies );
}

/**
 * Get the content security policies for the current page.
 *
 * @return array Map from directive name to value or list of values.
 */
function get_report_only_content_security_policies() : array {
	$policies = get_content_security_policy_directives();

	/**
	 * Filter the report-only security policies for the current page.
	 *
	 * The filtered value is a map from directive name (e.g. `base-uri`,
	 * `default-src`) to directive value. Each directive value can be a
	 * string or array of strings.
	 *
	 * @link https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy-Report-Only
	 *
	 * @param string[] $policies Map from directive name to value or list of values.
	 */
	return apply_filters( 'smeedijzer.security.browser.report_only_content_security_policies', $policies );
}

/**
 * Restrict CORS origin
 *
 * @return mixed | WP_Error
 */
function restrict_cors_origin( $result ) {
	$allow = true;
	$origin = get_http_origin();

	/**
	 * Filter the allowed CORS origins.
	 *
	 * @param bool $allow Whether to allow the origin.
	 * @param string $origin The origin URL.
	 */
	$rest_allow_origin = apply_filters( 'smeedijzer.security.browser.rest_allow_origin', $allow, $origin );

	if ( ! $rest_allow_origin ) {
		return new WP_Error( 'smeedijzer.security.browser.origin_not_allowed', 'Origin is not on allowed list', [ 'status' => WP_Http::FORBIDDEN ] );
	}

	return $result;
}
