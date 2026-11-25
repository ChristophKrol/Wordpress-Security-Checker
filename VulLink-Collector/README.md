# VulLink-Collector

Server-side inventory for a WordPress installation. A single PHP file that runs inside WordPress
through WP-CLI and writes a JSON inventory of everything that can be checked against VulLink,
plus integrity and configuration checks that only work with access to the server.

The collector only collects. Matching happens elsewhere, on a machine that can reach the VulLink API,
with the crawler's `wpcrawler match` command. A production server never needs access to VulLink.

```
server:         wp eval-file collect.php > inventory.json
your machine:   wpcrawler match inventory.json
```

## Requirements

- Shell access to the server (SSH) and [WP-CLI](https://wp-cli.org/) 2.x
- PHP 7.2+ (whatever runs WordPress)
- Optional: `shell_exec` allowed for web server and OS package versions; internet access to
  wordpress.org for the checksum checks

## Usage

The inventory is a map for attackers (versions, paths, admin usernames). Neither the script nor its
output belongs in the web root: everything under the WordPress folder (`/var/www/html`, `public_html`,
`htdocs`, `wp-content`, `uploads`, ...) can be downloaded by anyone.

### Option 1 (recommended): run over SSH, store nothing on the server

```bash
# on your machine, in VulLink-Collector/
ssh user@server 'wp --path=/var/www/html eval-file -' < collect.php > inventory.json
ssh user@server 'wp --path=/var/www/html eval-file - no-checksums' < collect.php > inventory.json  # faster
```

WP-CLI reads the script from the SSH connection (`-`), and the JSON comes back the same way. Nothing is
written on the server. Replace `/var/www/html` with your WordPress folder. If the files belong to another
user: `ssh user@server 'sudo -u www-data wp --path=/var/www/html eval-file -' < collect.php > inventory.json`.

### Option 2: copy the script to a folder outside the web root

```bash
# on the server: a private folder in your home directory, NOT inside the website
mkdir -p ~/vullink && chmod 700 ~/vullink
# copy collect.php there (scp collect.php user@server:~/vullink/), then
wp --path=/var/www/html eval-file ~/vullink/collect.php output=~/vullink/inventory.json

# on your machine: fetch it, then delete it on the server
scp user@server:~/vullink/inventory.json .
ssh user@server 'rm ~/vullink/inventory.json'
```

On shared hosting the home folder often contains the website as a subfolder (`/home/user/public_html`).
Use `/home/user/vullink`, next to `public_html`, not inside it.

### Then match it

```bash
cd ../VulLink-Crawler
.venv/bin/wpcrawler match inventory.json
.venv/bin/wpcrawler match inventory.json --json report.json
```

### Built-in safeguards

- **Requested over HTTP** (e.g. uploaded to the web root by mistake), `collect.php` answers `404` with an
  empty body and executes nothing.
- **`output=` inside the website** (WordPress folder, `wp-content`, uploads, or the parent folder of a
  WordPress-in-a-subfolder install) is refused before anything is written. The file gets permissions 600.
- **`> file` into the website** (e.g. `> inventory.json` typed inside the WordPress folder) is detected on
  Linux and refused before anything is written; only the empty file the shell created remains.
- Still delete inventories from the server after copying them, and don't commit or email them unencrypted.

Run WP-CLI as the user that owns the WordPress files, not as root.

## What it collects

| Area | Source | Checked against VulLink |
|---|---|---|
| WordPress core | `wp-includes/version.php`, `wp core check-update` | yes |
| Plugins incl. inactive | `wp plugin list` + plugin headers (status, update available, non-wordpress.org `Update URI`) | yes |
| Must-use plugins, drop-ins | `get_mu_plugins()`, `get_dropins()` | mu-plugins yes (if public slug); drop-ins listed |
| Themes incl. inactive, parent themes | `wp theme list` | yes |
| PHP | `PHP_VERSION`, php.ini security settings | yes |
| MySQL / MariaDB | `SELECT VERSION()` | yes (not detectable from outside) |
| Web server | `apache2 -v`, `httpd -v`, `nginx -v`, `lshttpd -v`, else the OS package | yes |
| OS packages with distro patch level | `dpkg-query`, `rpm`, `apk` | listed (no distro security data in VulLink yet) |
| Bundled Composer libraries | `vendor/composer/installed.json` in plugins/themes | listed (no PHP library advisories in VulLink yet) |
| Integrity | `wp core verify-checksums`, `wp plugin verify-checksums --all`, PHP files in `uploads/` | findings |
| Configuration | `wp-config.php` constants, default salts, file permissions, XML-RPC, admin accounts | findings |

## Things to know

- **Read-only.** It never changes files, settings or users. The one side effect: WP-CLI's update checks
  cache their result in a transient, just like opening the WordPress dashboard does.
- **The inventory is sensitive.** It contains server paths, administrator usernames and the exact versions
  of everything installed: a map for an attacker. Don't commit it or send it around unencrypted.
- **CLI PHP may differ from the web server's PHP.** The reported PHP version is the one running WP-CLI.
  If the site uses php-fpm in another version, check Tools > Site Health > Info > Server.
- **Distribution packages** (Debian, Ubuntu, RHEL) backport security fixes without changing the upstream
  version. The package version with its distro suffix is included so you can check the distro's security tracker.
- **Separate hosts and containers.** If the database or web server runs on another host or container, the
  OS package list doesn't describe it. Without `shell_exec`, the web server version isn't detected.
- Only plugins from wordpress.org can be checksum-verified. Premium plugins are reported as not verifiable.

## Testing it against a local Docker WordPress

The official `wordpress` image doesn't include WP-CLI, so run the `wordpress:cli` image next to it:
mount the site read-only, join its network, and pass the same `WORDPRESS_DB_*` environment variables:

```bash
docker inspect <wordpress-container> --format '{{range .Config.Env}}{{println .}}{{end}}' | grep '^WORDPRESS_' > wp.env
docker run --rm --user 33:33 --env-file wp.env --network <network> \
  --volumes-from <wordpress-container>:ro -v "$PWD":/collector:ro \
  wordpress:cli wp eval-file /collector/collect.php > inventory.json
rm wp.env   # contains the database password
```
In that setup PHP, OS and packages describe the WP-CLI container, not the web container.
