<?php
/**
 * VulLink server-side collector.
 *
 * Runs inside WordPress through WP-CLI and prints a JSON inventory of everything that can be checked
 * against VulLink (core, plugins incl. inactive and must-use, themes, PHP, web server, MySQL/MariaDB,
 * distro packages, bundled Composer libraries) plus integrity and configuration findings.
 *
 * Recommended: run it over SSH from your own machine, so neither this file nor the inventory is ever
 * stored on the server:
 *
 *     ssh user@server 'wp --path=/var/www/html eval-file -' < collect.php > inventory.json
 *
 * Or copy it to a folder OUTSIDE the web root (the inventory is a map for attackers):
 *
 *     wp --path=/var/www/html eval-file ~/vullink/collect.php output=~/vullink/inventory.json
 *
 * Options: no-checksums (skip the wordpress.org checksum checks), output=PATH (file with permissions 600).
 * Writing the inventory anywhere inside the WordPress/web directory is refused, and when requested
 * over HTTP this file answers 404 and does nothing.
 *
 * Read-only: it never changes files or settings. (WP-CLI's update checks cache their result in a
 * transient, exactly like opening the WordPress dashboard does.)
 * Match the result on a machine that can reach VulLink:  wpcrawler match inventory.json
 *
 * Compatible with PHP 7.2+ and WP-CLI 2.x.
 */

// Requested through a web server (e.g. accidentally uploaded to the web root): reveal nothing.
if ( 'cli' !== PHP_SAPI ) {
	if ( ! headers_sent() ) {
		http_response_code( 404 );
	}
	exit;
}
if ( ! defined( 'ABSPATH' ) || ! class_exists( 'WP_CLI' ) ) {
	fwrite( STDERR, "Run this with WP-CLI: wp eval-file collect.php output=~/inventory.json\n" );
	exit( 1 );
}

$vl_options        = isset( $args ) && is_array( $args ) ? $args : array();
$vl_skip_checksums = in_array( 'no-checksums', $vl_options, true );

/* ------------------------------------------------------------------ output destination (checked first) */

/** Directories that may be served over HTTP: WordPress itself, wp-content, uploads, and the parent of a
 *  WordPress-in-a-subdirectory install. */
function vl_web_roots() {
	$roots  = array( ABSPATH, WP_CONTENT_DIR );
	$upload = wp_get_upload_dir();
	if ( ! empty( $upload['basedir'] ) ) {
		$roots[] = $upload['basedir'];
	}
	$parent = dirname( rtrim( ABSPATH, '/' ) );
	if ( file_exists( $parent . '/index.php' ) || file_exists( $parent . '/.htaccess' ) ) {
		$roots[] = $parent;
	}
	$real = array();
	foreach ( $roots as $r ) {
		$rp = realpath( $r );
		if ( $rp ) {
			$real[] = rtrim( $rp, '/' ) . '/';
		}
	}
	return array_unique( $real );
}

function vl_is_public_path( $file ) {
	$dir = realpath( dirname( $file ) );
	if ( ! $dir ) {
		return false;
	}
	$dir = rtrim( $dir, '/' ) . '/';
	foreach ( vl_web_roots() as $root ) {
		if ( 0 === strpos( $dir, $root ) ) {
			return true;
		}
	}
	return false;
}

function vl_abort( $message ) {
	fwrite( STDERR, "VulLink collector: $message\n" );
	exit( 1 );
}

$vl_output = null;
foreach ( $vl_options as $opt ) {
	if ( 0 === strpos( $opt, 'output=' ) ) {
		$vl_output = substr( $opt, 7 );
		if ( 0 === strpos( $vl_output, '~/' ) && getenv( 'HOME' ) ) {
			$vl_output = getenv( 'HOME' ) . substr( $vl_output, 1 );
		}
	}
}
if ( $vl_output ) {
	if ( ! is_dir( dirname( $vl_output ) ) ) {
		vl_abort( 'output directory does not exist: ' . dirname( $vl_output ) );
	}
	if ( vl_is_public_path( $vl_output ) ) {
		vl_abort( "refusing to write the inventory inside the web root ($vl_output). Use a path outside it, e.g. output=~/inventory.json" );
	}
} else {
	// "> file": refuse before anything is written if stdout is a file inside the web root. Compare the file's
	// identity (device + inode), not just its path: the path the kernel reports can differ from the path
	// visible to PHP (bind mounts, Docker Desktop). Candidates: the reported path, and the same file name in
	// the current directory (the classic mistake: "> inventory.json" typed inside the WordPress folder).
	$out_stat = function_exists( 'fstat' ) ? @fstat( STDOUT ) : false;
	$target   = is_link( '/proc/self/fd/1' ) ? (string) readlink( '/proc/self/fd/1' ) : '';
	if ( $out_stat && $target && '/' === $target[0] && ( $out_stat['mode'] & 0170000 ) === 0100000 ) {
		$cwd = getcwd();
		foreach ( array_unique( array( $target, $cwd ? $cwd . '/' . basename( $target ) : '' ) ) as $candidate ) {
			$st = $candidate ? @stat( $candidate ) : false;
			if ( $st && $st['dev'] === $out_stat['dev'] && $st['ino'] === $out_stat['ino'] && vl_is_public_path( $candidate ) ) {
				vl_abort( "stdout is redirected into the web root ($candidate). Nothing was written, but the empty file exists: delete it and use output=~/inventory.json instead." );
			}
		}
	}
}

$inventory = array(
	'schema'      => 'vullink-inventory/1',
	'collectedAt' => gmdate( 'c' ),
	'collector'   => 'VulLink-Collector/0.1',
	'site'        => array(),
	'components'  => array(),
	'packages'    => array(),
	'libraries'   => array(),
	'findings'    => array(),
	'integrity'   => array(),
	'environment' => array(),
	'errors'      => array(),
);

/* ------------------------------------------------------------------ helpers */

function vl_finding( &$inv, $id, $title, $severity, $location, $detail = '' ) {
	$inv['findings'][] = array(
		'id'       => $id,
		'title'    => $title,
		'severity' => $severity,
		'url'      => $location,
		'detail'   => $detail,
	);
}

function vl_component( &$inv, $type, $slug, $name, $version, $source, $details = array(), $notes = array() ) {
	$inv['components'][] = array(
		'type'    => $type,
		'slug'    => strtolower( (string) $slug ),
		'name'    => $name,
		'version' => ( '' === (string) $version ) ? null : (string) $version,
		'source'  => $source,
		'details' => $details,
		'notes'   => $notes,
	);
}

/** Run a WP-CLI command in-process; returns decoded JSON or null. */
function vl_wp_json( &$inv, $command ) {
	try {
		$out = WP_CLI::runcommand(
			$command,
			array( 'return' => 'all', 'exit_error' => false, 'launch' => false, 'parse' => false )
		);
	} catch ( \Throwable $e ) {
		$inv['errors'][] = "wp $command: " . $e->getMessage();
		return null;
	}
	if ( 0 !== (int) $out->return_code ) {
		$inv['errors'][] = "wp $command: " . trim( (string) $out->stderr );
		return null;
	}
	$data = json_decode( (string) $out->stdout, true );
	return is_array( $data ) ? $data : null;
}

/** Shell command output, or null if shell access is disabled/unavailable. */
function vl_shell( $command ) {
	if ( ! function_exists( 'shell_exec' ) ) {
		return null;
	}
	$disabled = array_map( 'trim', explode( ',', (string) ini_get( 'disable_functions' ) ) );
	if ( in_array( 'shell_exec', $disabled, true ) ) {
		return null;
	}
	$out = @shell_exec( $command . ' 2>&1' );
	return ( null === $out || false === $out ) ? null : trim( $out );
}

function vl_first_match( $pattern, $text ) {
	return ( is_string( $text ) && preg_match( $pattern, $text, $m ) ) ? $m[1] : null;
}

/* ------------------------------------------------------------------ site + core */

global $wp_version, $wpdb;
require ABSPATH . WPINC . '/version.php'; // authoritative core version, even if a plugin altered $wp_version

$inventory['site'] = array(
	'url'       => home_url(),
	'path'      => ABSPATH,
	'multisite' => is_multisite(),
	'locale'    => get_locale(),
);

$core_update = vl_wp_json( $inventory, 'core check-update --format=json' );
$core_latest = ( is_array( $core_update ) && ! empty( $core_update ) ) ? $core_update[0]['version'] : null;
vl_component(
	$inventory, 'core', 'wordpress', 'WordPress', $wp_version, 'wp-includes/version.php',
	array( 'status' => 'active', 'updateVersion' => $core_latest )
);

/* ------------------------------------------------------------------ plugins */

if ( ! function_exists( 'get_plugins' ) ) {
	require_once ABSPATH . 'wp-admin/includes/plugin.php';
}

$plugin_list = vl_wp_json( $inventory, 'plugin list --format=json --fields=name,status,version,update,update_version,file' );
$plugin_meta = get_plugins();

if ( is_array( $plugin_list ) ) {
	foreach ( $plugin_list as $p ) {
		if ( in_array( $p['status'], array( 'must-use', 'dropin' ), true ) ) {
			continue; // handled below
		}
		$file    = isset( $p['file'] ) ? $p['file'] : '';
		$meta    = isset( $plugin_meta[ $file ] ) ? $plugin_meta[ $file ] : array();
		$details = array(
			'status'        => $p['status'],
			'updateVersion' => ( 'available' === $p['update'] ) ? $p['update_version'] : null,
			'file'          => $file,
		);
		$notes = array();
		if ( ! empty( $meta['UpdateURI'] ) && false === strpos( $meta['UpdateURI'], 'wordpress.org' ) ) {
			$notes[] = 'Not distributed via wordpress.org (Update URI: ' . $meta['UpdateURI'] . '); its slug may differ in vulnerability databases.';
		}
		if ( 'inactive' === $p['status'] ) {
			$notes[] = 'Inactive, but its files are still on the server and can still be attacked directly. Remove it if unused.';
		}
		vl_component( $inventory, 'plugin', $p['name'], isset( $meta['Name'] ) ? $meta['Name'] : $p['name'],
			$p['version'], 'wp plugin list', $details, $notes );
	}
}

foreach ( get_mu_plugins() as $file => $meta ) {
	vl_component( $inventory, 'plugin', preg_replace( '/\.php$/', '', basename( $file ) ), $meta['Name'], $meta['Version'],
		'wp-content/mu-plugins', array( 'status' => 'must-use', 'file' => $file ),
		array( 'Must-use plugin: always active and not shown in the normal plugin list.' ) );
}

foreach ( get_dropins() as $file => $meta ) {
	$inventory['environment']['dropins'][] = array(
		'file'   => $file,
		'name'   => isset( $meta['Name'] ) ? $meta['Name'] : '',
		'author' => isset( $meta['Author'] ) ? $meta['Author'] : '',
	);
}

/* ------------------------------------------------------------------ themes */

$theme_list = vl_wp_json( $inventory, 'theme list --format=json --fields=name,status,version,update,update_version' );
if ( is_array( $theme_list ) ) {
	foreach ( $theme_list as $t ) {
		$theme  = wp_get_theme( $t['name'] );
		$parent = $theme->parent() ? $theme->parent()->get_stylesheet() : null;
		$notes  = array();
		if ( 'inactive' === $t['status'] ) {
			$notes[] = 'Inactive theme: still reachable on the server. Keep one default theme, remove the rest.';
		}
		vl_component( $inventory, 'theme', $t['name'], $theme->get( 'Name' ), $t['version'], 'wp theme list',
			array(
				'status'        => $t['status'],
				'updateVersion' => ( 'available' === $t['update'] ) ? $t['update_version'] : null,
				'parent'        => $parent,
			),
			$notes );
	}
}

/* ------------------------------------------------------------------ OS + packages */

$os = array();
if ( is_readable( '/etc/os-release' ) ) {
	foreach ( file( '/etc/os-release', FILE_IGNORE_NEW_LINES ) as $line ) {
		if ( preg_match( '/^(ID|VERSION_ID|PRETTY_NAME|VERSION_CODENAME)=(.*)$/', $line, $m ) ) {
			$os[ strtolower( $m[1] ) ] = trim( $m[2], '"' );
		}
	}
}
$inventory['environment']['os']     = $os;
$inventory['environment']['kernel'] = php_uname( 'r' );

$pkg_patterns = 'apache2 httpd nginx openlitespeed lsws mariadb-server mysql-server mysql-community-server '
	. 'percona-server-server openssl php* libapache2-mod-php*';
$dpkg = vl_shell( "dpkg-query -W -f='\${Package}\\t\${Version}\\t\${db:Status-Abbrev}\\n' $pkg_patterns" );
if ( $dpkg && false === strpos( $dpkg, 'not found' ) ) {
	foreach ( explode( "\n", $dpkg ) as $line ) {
		$parts = explode( "\t", $line );
		if ( 3 === count( $parts ) && 0 === strpos( trim( $parts[2] ), 'ii' ) ) {
			$inventory['packages'][] = array( 'manager' => 'dpkg', 'name' => $parts[0], 'version' => $parts[1] );
		}
	}
} else {
	$rpm = vl_shell( "rpm -qa --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\n' 'httpd' 'nginx' 'openlitespeed' 'mariadb*-server' 'mysql*-server' 'php*' 'openssl'" );
	if ( $rpm && false === strpos( $rpm, 'not found' ) ) {
		foreach ( explode( "\n", $rpm ) as $line ) {
			$parts = explode( "\t", $line );
			if ( 2 === count( $parts ) ) {
				$inventory['packages'][] = array( 'manager' => 'rpm', 'name' => $parts[0], 'version' => $parts[1] );
			}
		}
	}
}
if ( ! $inventory['packages'] ) {
	$apk = vl_shell( 'apk info -v 2>/dev/null' ); // Alpine: "name-1.2.3-r0" per line
	if ( $apk ) {
		foreach ( explode( "\n", $apk ) as $line ) {
			if ( preg_match( '/^((?:apache2|nginx|mariadb|mysql|php\d*|openssl)[a-z0-9-]*)-(\d[^-]*-r\d+)$/', trim( $line ), $m ) ) {
				$inventory['packages'][] = array( 'manager' => 'apk', 'name' => $m[1], 'version' => $m[2] );
			}
		}
	}
}
$distro = isset( $os['id'] ) ? $os['id'] : null;

/** First installed package matching the prefixes, in order of preference (exact name wins). */
function vl_package_version( $inv, $prefixes ) {
	foreach ( $prefixes as $prefix ) {
		foreach ( $inv['packages'] as $pkg ) {
			if ( $pkg['name'] === $prefix ) {
				return $pkg;
			}
		}
		foreach ( $inv['packages'] as $pkg ) {
			if ( 0 === strpos( $pkg['name'], $prefix ) ) {
				return $pkg;
			}
		}
	}
	return null;
}

function vl_distro_note( $pkg, $distro ) {
	if ( ! $pkg ) {
		return array();
	}
	return array( sprintf(
		'Installed from %s package %s %s: security fixes may be backported without changing the upstream version, so version matches can be false positives. Check the %s security tracker for this package version.',
		$distro ? $distro : 'a distribution', $pkg['name'], $pkg['version'], $distro ? $distro : 'distribution'
	) );
}

/* ------------------------------------------------------------------ PHP */

$php_pkg = vl_package_version( $inventory, array( 'php' . PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION, 'php-common', 'php' ) );
vl_component( $inventory, 'server', 'php', 'PHP', PHP_VERSION, 'PHP_VERSION (CLI)',
	array( 'sapi' => PHP_SAPI, 'package' => $php_pkg ),
	array_merge(
		array( 'Version of the PHP binary running WP-CLI. The web server may use a different PHP (e.g. php-fpm of another version); compare with Tools > Site Health > Info > Server.' ),
		vl_distro_note( $php_pkg, $distro )
	) );

$inventory['environment']['php'] = array(
	'version'           => PHP_VERSION,
	'extensions'        => get_loaded_extensions(),
	'expose_php'        => ini_get( 'expose_php' ),
	'display_errors'    => ini_get( 'display_errors' ),
	'allow_url_include' => ini_get( 'allow_url_include' ),
	'allow_url_fopen'   => ini_get( 'allow_url_fopen' ),
	'disable_functions' => ini_get( 'disable_functions' ),
);
if ( version_compare( PHP_VERSION, '8.1', '<' ) ) {
	vl_finding( $inventory, 'php-eol', 'PHP ' . PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION . ' no longer receives security fixes', 'high', 'PHP',
		'Upgrade to a supported PHP branch.' );
}
if ( filter_var( ini_get( 'allow_url_include' ), FILTER_VALIDATE_BOOLEAN ) ) {
	vl_finding( $inventory, 'php-allow-url-include', 'allow_url_include is enabled', 'high', 'php.ini',
		'Turns local file inclusion bugs into remote code execution.' );
}

/* ------------------------------------------------------------------ database server */

$db_info = method_exists( $wpdb, 'db_server_info' ) ? $wpdb->db_server_info() : $wpdb->get_var( 'SELECT VERSION()' );
if ( $db_info ) {
	$is_maria = false !== stripos( $db_info, 'mariadb' );
	$db_ver   = vl_first_match( '/(\d+\.\d+\.\d+)/', preg_replace( '/^5\.5\.5-/', '', $db_info ) ); // MariaDB's 5.5.5- prefix
	$db_pkg   = vl_package_version( $inventory, $is_maria ? array( 'mariadb-server' ) : array( 'mysql-server', 'mysql-community-server', 'percona-server-server' ) );
	$db_notes = vl_distro_note( $db_pkg, $distro );
	if ( 'localhost' !== DB_HOST && 0 !== strpos( DB_HOST, '127.' ) && 0 !== strpos( DB_HOST, 'localhost:' ) ) {
		$db_notes[] = 'Database runs on a separate host (' . DB_HOST . '); OS packages listed here do not describe it.';
	}
	vl_component( $inventory, 'server', $is_maria ? 'mariadb' : 'mysql', $is_maria ? 'MariaDB' : 'MySQL', $db_ver,
		'SELECT VERSION()', array( 'raw' => $db_info, 'package' => $db_pkg ), $db_notes );
}

/* ------------------------------------------------------------------ web server */

$web_candidates = array(
	array( 'apache', 'Apache HTTP Server', 'apache2 -v', '#Apache/(\d+\.\d+\.\d+)#', array( 'apache2', 'httpd' ) ),
	array( 'apache', 'Apache HTTP Server', 'httpd -v', '#Apache/(\d+\.\d+\.\d+)#', array( 'httpd', 'apache2' ) ),
	array( 'nginx', 'nginx', 'nginx -v', '#nginx/(\d+\.\d+\.\d+)#', array( 'nginx' ) ),
	array( 'openlitespeed', 'OpenLiteSpeed', '/usr/local/lsws/bin/lshttpd -v', '#(\d+\.\d+(?:\.\d+)?)#', array( 'openlitespeed' ) ),
);
$web_found = false;
foreach ( $web_candidates as $c ) {
	$out = vl_shell( $c[2] );
	$ver = vl_first_match( $c[3], $out );
	if ( $ver ) {
		$slug = $c[0];
		$name = $c[1];
		if ( 'openlitespeed' === $slug && false === stripos( (string) $out, 'openlitespeed' ) ) {
			$slug = 'litespeed';
			$name = 'LiteSpeed Web Server';
		}
		$pkg = vl_package_version( $inventory, $c[4] );
		vl_component( $inventory, 'server', $slug, $name, $ver, $c[2], array( 'package' => $pkg ), vl_distro_note( $pkg, $distro ) );
		$web_found = true;
		break;
	}
}
if ( ! $web_found ) {
	foreach ( array( array( 'apache2', 'apache' ), array( 'httpd', 'apache' ), array( 'nginx', 'nginx' ), array( 'openlitespeed', 'openlitespeed' ) ) as $map ) {
		$pkg = vl_package_version( $inventory, array( $map[0] ) );
		if ( $pkg ) {
			$upstream = vl_first_match( '/^(?:\d+:)?(\d+\.\d+(?:\.\d+)?)/', $pkg['version'] );
			vl_component( $inventory, 'server', $map[1], null, $upstream, 'package ' . $pkg['name'], array( 'package' => $pkg ),
				vl_distro_note( $pkg, $distro ) );
			$web_found = true;
			break;
		}
	}
}
if ( ! $web_found ) {
	$inventory['errors'][] = 'Web server not detected (no shell access, or it runs in another container/host).';
}

/* ------------------------------------------------------------------ bundled libraries */

$lib_roots = array_merge(
	glob( WP_PLUGIN_DIR . '/*', GLOB_ONLYDIR ) ?: array(),
	glob( get_theme_root() . '/*', GLOB_ONLYDIR ) ?: array()
);
foreach ( $lib_roots as $root ) {
	$owner = ( 0 === strpos( $root, WP_PLUGIN_DIR ) ? 'plugin:' : 'theme:' ) . basename( $root );
	foreach ( array( $root . '/vendor/composer/installed.json', $root . '/lib/vendor/composer/installed.json' ) as $installed ) {
		if ( ! is_readable( $installed ) ) {
			continue;
		}
		$data     = json_decode( (string) file_get_contents( $installed ), true );
		$packages = isset( $data['packages'] ) ? $data['packages'] : ( is_array( $data ) ? $data : array() ); // Composer 2 vs 1
		foreach ( $packages as $pkg ) {
			if ( isset( $pkg['name'], $pkg['version'] ) ) {
				$inventory['libraries'][] = array(
					'ecosystem' => 'composer',
					'name'      => $pkg['name'],
					'version'   => ltrim( $pkg['version'], 'v' ),
					'in'        => $owner,
				);
			}
		}
	}
}

/* ------------------------------------------------------------------ integrity */

if ( $vl_skip_checksums ) {
	$inventory['integrity']['skipped'] = true;
} else {
	$core = WP_CLI::runcommand( 'core verify-checksums', array( 'return' => 'all', 'exit_error' => false, 'launch' => false ) );
	$core_msgs = array_values( array_filter( array_map( 'trim', explode( "\n", $core->stderr ) ) ) );
	$inventory['integrity']['core'] = array( 'ok' => 0 === (int) $core->return_code, 'messages' => array_slice( $core_msgs, 0, 50 ) );
	if ( 0 !== (int) $core->return_code ) {
		vl_finding( $inventory, 'core-checksums', 'WordPress core files differ from wordpress.org', 'high', ABSPATH,
			implode( ' | ', array_slice( $core_msgs, 0, 5 ) ) );
	}

	$plugin_check = WP_CLI::runcommand( 'plugin verify-checksums --all --format=json',
		array( 'return' => 'all', 'exit_error' => false, 'launch' => false ) );
	$mismatches = json_decode( (string) $plugin_check->stdout, true );
	$inventory['integrity']['plugins'] = array(
		'ok'         => 0 === (int) $plugin_check->return_code,
		'mismatches' => is_array( $mismatches ) ? array_slice( $mismatches, 0, 200 ) : array(),
		'messages'   => array_slice( array_values( array_filter( array_map( 'trim', explode( "\n", $plugin_check->stderr ) ) ) ), 0, 50 ),
	);
	if ( is_array( $mismatches ) && $mismatches ) {
		$by_plugin = array();
		foreach ( $mismatches as $m ) {
			$by_plugin[ $m['plugin_name'] ] = ( isset( $by_plugin[ $m['plugin_name'] ] ) ? $by_plugin[ $m['plugin_name'] ] : 0 ) + 1;
		}
		foreach ( $by_plugin as $plugin => $count ) {
			vl_finding( $inventory, 'plugin-checksums', "Plugin files differ from wordpress.org: $plugin", 'high',
				WP_PLUGIN_DIR . "/$plugin", "$count file(s) added, removed or modified - check for backdoors." );
		}
	}
}

// PHP files in uploads are a classic web shell indicator (uploads should only hold media).
$uploads = wp_get_upload_dir();
if ( ! empty( $uploads['basedir'] ) && is_dir( $uploads['basedir'] ) ) {
	$php_in_uploads = array();
	$it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $uploads['basedir'], FilesystemIterator::SKIP_DOTS ) );
	foreach ( $it as $file ) {
		if ( preg_match( '/\.(php\d?|phtml|phar)$/i', $file->getFilename() ) && 'index.php' !== $file->getFilename() ) {
			$php_in_uploads[] = substr( $file->getPathname(), strlen( ABSPATH ) );
			if ( count( $php_in_uploads ) >= 50 ) {
				break;
			}
		}
	}
	$inventory['integrity']['phpInUploads'] = $php_in_uploads;
	if ( $php_in_uploads ) {
		vl_finding( $inventory, 'php-in-uploads', 'PHP files found in the uploads folder', 'high', $uploads['basedir'],
			count( $php_in_uploads ) . ' file(s), e.g. ' . implode( ', ', array_slice( $php_in_uploads, 0, 5 ) ) . ' - common web shell location.' );
	}
}

/* ------------------------------------------------------------------ configuration */

$config_file = file_exists( ABSPATH . 'wp-config.php' ) ? ABSPATH . 'wp-config.php' : dirname( ABSPATH ) . '/wp-config.php';
$config      = array(
	'WP_DEBUG'                   => defined( 'WP_DEBUG' ) && WP_DEBUG,
	'WP_DEBUG_DISPLAY'           => defined( 'WP_DEBUG_DISPLAY' ) ? (bool) WP_DEBUG_DISPLAY : true,
	'WP_DEBUG_LOG'               => defined( 'WP_DEBUG_LOG' ) ? WP_DEBUG_LOG : false,
	'DISALLOW_FILE_EDIT'         => defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT,
	'DISALLOW_FILE_MODS'         => defined( 'DISALLOW_FILE_MODS' ) && DISALLOW_FILE_MODS,
	'FORCE_SSL_ADMIN'            => defined( 'FORCE_SSL_ADMIN' ) && FORCE_SSL_ADMIN,
	'AUTOMATIC_UPDATER_DISABLED' => defined( 'AUTOMATIC_UPDATER_DISABLED' ) && AUTOMATIC_UPDATER_DISABLED,
	'WP_AUTO_UPDATE_CORE'        => defined( 'WP_AUTO_UPDATE_CORE' ) ? WP_AUTO_UPDATE_CORE : 'minor (default)',
	'table_prefix'               => $wpdb->prefix,
	'xmlrpc_enabled'             => (bool) apply_filters( 'xmlrpc_enabled', true ),
	'auto_update_plugins'        => count( (array) get_site_option( 'auto_update_plugins', array() ) ),
);
$inventory['environment']['wpConfig'] = $config;

if ( $config['WP_DEBUG'] && $config['WP_DEBUG_DISPLAY'] ) {
	vl_finding( $inventory, 'debug-display', 'WP_DEBUG is on and errors are displayed', 'medium', $config_file,
		'Error messages leak paths and internals to visitors. Set WP_DEBUG_DISPLAY to false on production.' );
}
if ( true === $config['WP_DEBUG_LOG'] && file_exists( WP_CONTENT_DIR . '/debug.log' ) ) {
	vl_finding( $inventory, 'debug-log-public-path', 'debug.log is written to wp-content (publicly reachable path)', 'medium',
		WP_CONTENT_DIR . '/debug.log', 'Set WP_DEBUG_LOG to a path outside the web root or block access to it.' );
}
if ( ! $config['DISALLOW_FILE_EDIT'] && ! $config['DISALLOW_FILE_MODS'] ) {
	vl_finding( $inventory, 'file-edit-enabled', 'Plugin/theme file editor is enabled', 'low', $config_file,
		'An attacker with an admin login can run arbitrary PHP via the editor. Set DISALLOW_FILE_EDIT to true.' );
}
if ( 'wp_' === $wpdb->base_prefix ) {
	vl_finding( $inventory, 'default-table-prefix', 'Default database table prefix wp_', 'info', $config_file,
		'Only marginal hardening value; mentioned for completeness.' );
}
if ( $config['xmlrpc_enabled'] ) {
	vl_finding( $inventory, 'xmlrpc-enabled', 'XML-RPC is enabled', 'low', 'xmlrpc.php',
		'Brute-force amplification and pingback abuse if not needed (Jetpack and some apps need it).' );
}
foreach ( array( 'AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY', 'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT' ) as $salt ) {
	if ( ! defined( $salt ) || '' === constant( $salt ) || 'put your unique phrase here' === constant( $salt ) ) {
		vl_finding( $inventory, 'default-salts', 'Authentication keys/salts are missing or still the defaults', 'high', $config_file,
			"$salt is not set to a unique value. Generate new ones: https://api.wordpress.org/secret-key/1.1/salt/" );
		break;
	}
}
if ( is_file( $config_file ) ) {
	$perms = fileperms( $config_file ) & 0777;
	if ( $perms & 0004 ) {
		vl_finding( $inventory, 'wp-config-world-readable', 'wp-config.php is readable by all users on the server', 'medium',
			$config_file, sprintf( 'Permissions %o; use 640 or 600 (shared hosting exposes DB credentials otherwise).', $perms ) );
	}
	if ( $perms & 0002 ) {
		vl_finding( $inventory, 'wp-config-world-writable', 'wp-config.php is writable by all users', 'high', $config_file,
			sprintf( 'Permissions %o.', $perms ) );
	}
}

/* ------------------------------------------------------------------ users */

$admins = get_users( array( 'role' => 'administrator', 'fields' => array( 'user_login' ) ) );
if ( is_multisite() ) {
	$admins = array_merge( $admins, array_map( function ( $login ) {
		return (object) array( 'user_login' => $login );
	}, get_super_admins() ) );
}
$admin_logins = array_values( array_unique( array_map( function ( $u ) {
	return $u->user_login;
}, $admins ) ) );
$inventory['environment']['administrators'] = array( 'count' => count( $admin_logins ), 'logins' => $admin_logins );
if ( array_intersect( array( 'admin', 'administrator', 'root', 'test' ), array_map( 'strtolower', $admin_logins ) ) ) {
	vl_finding( $inventory, 'guessable-admin-login', 'An administrator uses a guessable username', 'medium', 'users',
		'Usernames like "admin" are the first target of brute-force attacks.' );
}
if ( count( $admin_logins ) > 5 ) {
	vl_finding( $inventory, 'many-admins', count( $admin_logins ) . ' administrator accounts', 'low', 'users',
		'Every admin account is a takeover path; review whether all are needed.' );
}

/* ------------------------------------------------------------------ output */

$vl_json = wp_json_encode( $inventory, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) . "\n";
if ( $vl_output ) {
	$old_umask = umask( 077 );
	$written   = file_put_contents( $vl_output, $vl_json );
	umask( $old_umask );
	if ( false === $written ) {
		vl_abort( "could not write $vl_output" );
	}
	chmod( $vl_output, 0600 ); // also when the file already existed with wider permissions
	fwrite( STDERR, "Inventory written to $vl_output (permissions 600). Copy it to your machine, then delete it here.\n" );
} else {
	echo $vl_json;
}
