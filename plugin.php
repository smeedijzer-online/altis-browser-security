<?php
/**
 * Plugin Name: Smeedijzer Browser Security
 * Description: Browser security utilities for WordPress
 * Author: Human Made
 * Author URI: https://humanmade.com/
 */

namespace Smeedijzer\Security\Browser;

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
	'automatic-integrity' => defined( 'ABS_AUTOMATIC_INTEGRITY' ) ? ABS_AUTOMATIC_INTEGRITY : true,
	'nosniff-header' => defined( 'ABS_NOSNIFF_HEADER' ) ? ABS_NOSNIFF_HEADER : true,
	'frame-options-header' => defined( 'ABS_FRAME_OPTIONS_HEADER' ) ? ABS_FRAME_OPTIONS_HEADER : true,
	'strict-transport-security' => defined( 'ABS_HSTS' ) ? ABS_HSTS : ( ( defined( 'WP_ENVIRONMENT_TYPE' ) && WP_ENVIRONMENT_TYPE === 'production' ) ? 'max-age=31536000' : null ),
	'xss-protection-header' => defined( 'ABS_XSS_PROTECTION_HEADER' ) ? ABS_XSS_PROTECTION_HEADER : true,
	'referrer-policy-header' => defined( 'ABS_REFERRER_POLICY_HEADER' ) ? ABS_REFERRER_POLICY_HEADER : true,
	'nonce-for-inline-scripts' => defined( 'ABS_NONCE_FOR_INLINE_SCRIPTS' ) ? ABS_NONCE_FOR_INLINE_SCRIPTS : false,
	'nonce-for-inline-styles' => defined( 'ABS_NONCE_FOR_INLINE_STYLES' ) ? ABS_NONCE_FOR_INLINE_STYLES : false,
] );
