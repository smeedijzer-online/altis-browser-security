<?php
/**
 * Plugin Name: Smeedijzer Browser Security
 * Description: Browser security utilities for WordPress
 * Author: Human Made
 * Author URI: https://humanmade.com/
 */

namespace Smeedijzer\Security\Browser;

// temp
// if no-unsafe-inline plugin is active, do not load this plugin
if ( defined( 'NO_UNSAFE_INLINE_VERSION' ) ) {
	return;
}

// temp
if(str_contains($_SERVER['REQUEST_URI'], 'contactformulier') === true){
	return;
}

/**
 * Autoloader
 */
if (file_exists(__DIR__ . '/vendor/autoload.php')) {
	require_once __DIR__ . '/vendor/autoload.php';
} else {
	throw new \RuntimeException('Autoload does not exist.');
}

bootstrap( [
	'automatic-integrity' => defined( 'BS_AUTOMATIC_INTEGRITY' ) ? BS_AUTOMATIC_INTEGRITY : true,
	'nosniff-header' => defined( 'BS_NOSNIFF_HEADER' ) ? BS_NOSNIFF_HEADER : true,
	'frame-options-header' => defined( 'BS_FRAME_OPTIONS_HEADER' ) ? BS_FRAME_OPTIONS_HEADER : true,
	'strict-transport-security' => defined( 'BS_HSTS' ) ? BS_HSTS : ( ( defined( 'WP_ENVIRONMENT_TYPE' ) && WP_ENVIRONMENT_TYPE === 'production' ) ? 'max-age=31536000' : null ),
	'xss-protection-header' => defined( 'BS_XSS_PROTECTION_HEADER' ) ? BS_XSS_PROTECTION_HEADER : true,
	'referrer-policy-header' => defined( 'BS_REFERRER_POLICY_HEADER' ) ? BS_REFERRER_POLICY_HEADER : true,
	'convert-event-handler-attributes' => defined( 'BS_CONVERT_EVENT_HANDLER_ATTRIBUTES' ) ? BS_CONVERT_EVENT_HANDLER_ATTRIBUTES : false,
	'convert-inline-style-attributes' => defined( 'BS_CONVERT_INLINE_STYLE_ATTRIBUTES' ) ? BS_CONVERT_INLINE_STYLE_ATTRIBUTES : false,
	'nonce-for-inline-script-tags' => defined( 'BS_NONCE_FOR_INLINE_SCRIPT_TAGS' ) ? BS_NONCE_FOR_INLINE_SCRIPT_TAGS : false,
	'nonce-for-internal-style-tags' => defined( 'BS_NONCE_FOR_INTERNAL_STYLE_TAGS' ) ? BS_NONCE_FOR_INTERNAL_STYLE_TAGS : false,
] );
