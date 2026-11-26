# TODO
Plans for further development. This will be a security tool that will have an integration to MainWP as this allows for security management of all websites.

## Database
- Cronjob to automatically update the database
- Implement some kind of filter for false positives: As for now, It shows not relevant vulnerabilites eg. from 2007 (eg. CVE-2007-3205)


What: Distribution package versions
Where: dpkg -l / rpm -qa, for example apache2 2.4.66-1~deb12u1
Why it's important: Solves the backport false-positive problem: the patch level shows whether Debian already fixed a
  CVE
What the database would need: A new source: Debian Security Tracker, Ubuntu security notices or Red Hat OVAL
────────────────────────────────────────
What: Libraries bundled inside plugins
Where: vendor/composer/installed.json, composer.lock, JS libraries in plugin folders (PHPMailer, TCPDF, jQuery, …)
Why it's important: Plugins often bundle outdated libraries with their own CVEs
What the database would need: NVD scope beyond WordPress, or better OSV.dev / the GitHub Advisory Database (both PHP
  and JavaScript packages)
────────────────────────────────────────
What: Operating system packages
Where: OpenSSL, kernel, other system packages
Why it's important: Server security beyond WordPress
What the database would need: Same as the first row; outside the current WordPress scope
- 
## Crawler
Crawler simulates what every user can find out about a website (first layer)
- JSON output for checking

## Internal crawler
- cronjob to automatically check for vulnerabilities
Developing a script that runs through MainWP on all Websites that can check for files in the server (Has access on server)
- File integrity: wp core verify-checksums and wp plugin verify-checksums --all 

