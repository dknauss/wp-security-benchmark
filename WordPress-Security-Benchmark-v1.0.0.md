# NLM WordPress Benchmark #

**Full Stack Hardening Guide**

v1.0.0 — February 2026

**DRAFT**

WordPress 6.x on Linux (Ubuntu/Debian)

Nginx or Apache • PHP 8.x • MySQL 8.x / MariaDB 10.x+

*Format adapted from industry-standard benchmarks*


Authored by Dan Knauss 
dan@newlocalmedia.com


## Overview

This document provides prescriptive guidance for establishing a secure configuration posture for WordPress 6.x running on a Linux server stack. This benchmark covers the full stack: the operating system firewall, web server (Nginx or Apache), PHP runtime, MySQL/MariaDB database, and the WordPress application layer.

This benchmark is intended for system administrators, security engineers, DevOps teams, and WordPress developers responsible for deploying and maintaining WordPress installations in enterprise environments.

The guidance draws on many WordPress security resources and standards, such as the OWASP Top 10 (2021), NIST SP 800-63B, and field experience with enterprise WordPress hardening.

## Target Technology

-   WordPress 6.x (latest stable release recommended)

-   Ubuntu 22.04+ / Debian 12+ (or equivalent RHEL/CentOS)

-   Nginx 1.24+ or Apache 2.4+

-   PHP 8.1+ (8.2+ recommended)

-   MySQL 8.0+ or MariaDB 10.6+

**Note on Containerization:** While this benchmark assumes a traditional Linux stack, the principles and many of the configuration settings apply equally to containerized environments (Docker, Kubernetes). In such cases, configurations should be injected via environment variables or secret management systems rather than direct file edits where possible.

## Profile Definitions

This benchmark defines two configuration profiles:

| Level       | Description |
| ———-- | — |
| **Level 1** | Essential security settings that can be implemented on any WordPress deployment with minimal impact on functionality or performance. These form a baseline security posture that every site should meet. Implementing Level 1 items should not significantly inhibit the usability of the technology. |
| **Level 2** | Defense-in-depth settings intended for high-security environments. These recommendations may restrict functionality, require additional tooling, or involve operational overhead. They are appropriate for sites handling sensitive data, regulated industries, or high-value targets. |


## Assessment Status

**Automated:** Compliance can be verified programmatically using command-line tools, configuration file inspection, or API queries.

**Manual:** Compliance requires human judgment, review of policies, or inspection of settings through a graphical interface.

## 1 Web Server Configuration

This section provides recommendations for hardening the web server (Nginx or Apache) that serves the WordPress application.

#### 1.1 Ensure TLS 1.2+ is enforced

**Profile Applicability:** **Level 1**

**Assessment Status:** Automated

**Description:** Only TLS 1.2 and TLS 1.3 should be accepted. TLS 1.0 and 1.1 contain known vulnerabilities and must be disabled.

**Rationale:** TLS 1.0 and 1.1 are vulnerable to BEAST, POODLE, and other attacks. All major browsers have dropped support for these protocols. Enforcing 1.2+ eliminates a class of protocol-level attacks.

**Impact:** Legacy clients that do not support TLS 1.2 will be unable to connect. This is an acceptable trade-off for security.

**Audit:**

For Nginx, verify the ssl_protocols directive:
```
$ grep -r 'ssl_protocols' /etc/nginx/
```
Verify that the output contains only TLSv1.2 and TLSv1.3.
For Apache:
```
$ grep -r 'SSLProtocol' /etc/apache2/
```
Verify the output shows 'all -SSLv3 -TLSv1 -TLSv1.1' or equivalent.

**Remediation:**

For Nginx, set in the server or http block:
```
ssl_protocols TLSv1.2 TLSv1.3;
```
For Apache, set in the VirtualHost or global config:
SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
Restart the web server after changes.

**Default Value:** Nginx: TLSv1 TLSv1.1 TLSv1.2 (all enabled). Apache: All protocols enabled.

**References:** https://ssl-config.mozilla.org/
—


#### 1.2 Ensure HTTP security headers are configured

**Profile Applicability:** **Level 1**

**Assessment Status:** Automated

**Description:** The web server should send security-related HTTP headers including Content-Security-Policy, X-Content-Type-Options, X-Frame-Options, Strict-Transport-Security (HSTS), Referrer-Policy, and Permissions-Policy.

**Rationale:** HTTP security headers instruct the browser to enable built-in protections against common attacks such as XSS, clickjacking, MIME-type confusion, and insecure referrer leakage.

**Impact:** Overly restrictive Content-Security-Policy headers may break inline scripts, third-party integrations, or analytics tools. Note that `unsafe-inline` is often required for WordPress themes and plugins but represents a security trade-off. For Level 2, aim to remove `unsafe-inline` by using nonces or hashes.

**Audit:**

For Nginx, inspect the response headers:
```
$ curl -sI https://example.com \| grep -iE '(content-security\|x-content-type\|x-frame\|strict-transport\|referrer-policy\|permissions-policy)'
```
Verify all six headers are present.

**Remediation:**

For Nginx, add to the server block:
```
add_header X-Content-Type-Options \"nosniff\" always;
```

```
add_header X-Frame-Options \"SAMEORIGIN\" always;
```

```
add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;
```

```
add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;
```

```
add_header Permissions-Policy \"geolocation=(), camera=(), microphone=()\" always;
```

```
add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';\" always;
```
For Apache, use the Headers module:
Header always set X-Content-Type-Options \"nosniff\"

Header always set X-Frame-Options \"SAMEORIGIN\"

**Default Value:** No security headers are set by default.

**References:** https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers
OWASP Secure Headers Project

—


#### 1.3 Ensure server tokens and version information are hidden

**Profile Applicability:** **Level 1**

**Assessment Status:** Automated

**Description:** The web server should not disclose its version number, operating system, or module information in HTTP response headers or error pages.

**Rationale:** Version information helps attackers identify specific vulnerabilities to target. Removing it forces attackers to probe the server more actively, increasing the chance of detection.

**Audit:**

```
$ curl -sI https://example.com \| grep -i 'server'
```
Verify the Server header does not contain version numbers.

**Remediation:**

For Nginx:
```
server_tokens off;
```
For Apache:
ServerTokens Prod

ServerSignature Off

**Default Value:** Nginx: server_tokens on (version exposed). Apache: ServerTokens Full.

—


#### 1.4 Ensure direct PHP execution is blocked in upload directories

**Profile Applicability:** **Level 1**

**Assessment Status:** Automated

**Description:** PHP execution must be disabled in the wp-content/uploads/ directory and any other directories intended only for static file storage.

**Rationale:** If an attacker uploads a malicious PHP file through a vulnerability (e.g., an insecure file upload in a plugin), blocking PHP execution in the uploads directory prevents the file from being executed.

**Impact:** None. Legitimate WordPress operations never require PHP execution from the uploads directory.

**Audit:**

For Nginx, verify a location block exists for uploads:
```
$ grep -A5 'uploads' /etc/nginx/sites-enabled/\*
```
Verify that PHP processing is denied for the uploads directory.

**Remediation:**

For Nginx, add to the server block:
```
location ~\* /wp-content/uploads/.\*\.php$ {
```

```
deny all;
```

}
For Apache, create wp-content/uploads/.htaccess:
\<FilesMatch \"\.php$\"\>

Require all denied

\</FilesMatch\>

**Default Value:** PHP execution is allowed in all directories by default.

**References:** https://developer.wordpress.org/advanced-administration/security/hardening/

—


#### 1.5 Ensure rate limiting is configured for all API surfaces

**Profile Applicability:** **Level 1**

**Assessment Status:** Automated

**Description:** HTTP request rate limiting should be applied to all authentication and API endpoints, including `wp-login.php`, `xmlrpc.php`, and the WordPress REST API (`/wp-json/`).

**Rationale:** WordPress authentication and API interfaces are primary targets for automated brute-force and resource exhaustion attacks. Comprehensive rate limiting across all entry points reduces the effectiveness of these attacks and protects server resources.

**Impact:** Aggressive rate limiting may lock out legitimate users or break third-party integrations (e.g., decoupled front-ends) if not configured with appropriate burst allowances and whitelist exceptions.

**Audit:**

For Nginx, check for `limit_req` configuration:
```
$ grep -r 'limit_req' /etc/nginx/
```
Verify rate limiting zones are defined and applied to login, XML-RPC, and REST API locations.

**Remediation:**

For Nginx, define rate limiting zones and apply them to the relevant locations:

```nginx
# In http block:
limit_req_zone $binary_remote_addr zone=wplogin:10m rate=1r/s;
limit_req_zone $binary_remote_addr zone=wpapi:10m rate=5r/s;

# In server block:
location = /wp-login.php {
    limit_req zone=wplogin burst=3 nodelay;
    # ... PHP processing ...
}

location = /xmlrpc.php {
    limit_req zone=wplogin burst=3 nodelay;
    # ... PHP processing ...
}

location ~ ^/wp-json/ {
    limit_req zone=wpapi burst=10 nodelay;
    # ... PHP processing ...
}
```

**Default Value:** No rate limiting is configured by default.

—


## 2 PHP Configuration

This section provides recommendations for securing the PHP runtime environment.

#### 2.1 Ensure expose_php is disabled

**Profile Applicability:** **Level 1**

**Assessment Status:** Automated

**Description:** The expose_php directive in php.ini must be set to Off. This prevents PHP from disclosing its presence and version in HTTP response headers (X-Powered-By).

**Rationale:** Version information assists attackers in identifying vulnerabilities specific to the running PHP version.

**Audit:**

```
$ php -i \| grep expose_php
```
Verify the output shows 'expose_php =\> Off =\> Off'.

**Remediation:**

In php.ini:
```
expose_php = Off
```
Restart PHP-FPM or the web server.

**Default Value:** expose_php = On

—


#### 2.2 Ensure display_errors is disabled in production

**Profile Applicability:** **Level 1**

**Assessment Status:** Automated

**Description:** The display_errors directive must be set to Off in production environments. PHP errors should be logged to a file, not displayed to users.

**Rationale:** Displayed PHP errors can reveal file paths, database connection details, and application structure to attackers.

**Audit:**

```
$ php -i \| grep display_errors
```
Verify: 'display_errors =\> Off =\> Off'.

**Remediation:**

In php.ini:
```
display_errors = Off
```

```
log_errors = On
```

```
error_log = /var/log/php/error.log
```

**Default Value:** display_errors = On in development configurations.

—


#### 2.3 Ensure dangerous PHP functions are disabled

**Profile Applicability:** **Level 1**

**Assessment Status:** Automated

**Description:** PHP functions that allow arbitrary command execution, code evaluation, or information disclosure should be disabled unless specifically required.

**Rationale:** If an attacker achieves code execution (e.g., through a vulnerable plugin), these functions enable them to execute system commands, read arbitrary files, or escalate the attack.

**Impact:** Some WordPress plugins may require specific functions. Test thoroughly before deploying. The `eval()` function is a language construct and cannot be disabled via `disable_functions`.

**Recommendation (Level 2):** For high-security environments, consider using a PHP security extension like **Snuffleupagus** to mitigate `eval()` and provide additional hardening that `disable_functions` cannot achieve.

**Audit:**

```
$ php -i \| grep disable_functions
```
Verify the output includes dangerous functions.

**Remediation:**

In php.ini:
```
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_multi_exec,parse_ini_file,show_source,pcntl_exec
```

**Default Value:** No functions are disabled by default.

—


#### 2.4 Ensure open_basedir restricts file access

**Profile Applicability:** **Level 2**

**Assessment Status:** Automated

**Description:** The open_basedir directive should restrict PHP file operations to the WordPress installation directory and required system paths only.

**Rationale:** open_basedir prevents PHP code from reading or writing files outside the defined directory tree, limiting the impact of a file inclusion or traversal vulnerability.

**Impact:** Must include the WordPress root, /tmp (for file uploads), and the PHP session directory. Incorrect configuration will break WordPress.

**Audit:**

```
$ php -i \| grep open_basedir
```
Verify a restricted path is configured.

**Remediation:**

In the PHP-FPM pool configuration or php.ini:
```
open_basedir = /var/www/example.com:/tmp:/usr/share/php
```

**Default Value:** open_basedir is not set (unrestricted).

—


#### 2.5 Ensure PHP session security is configured

**Profile Applicability:** **Level 1**

**Assessment Status:** Automated

**Description:** PHP session configuration should enforce secure defaults: cookies marked Secure, HttpOnly, and SameSite=Lax or Strict. Session ID entropy and hashing should use strong algorithms.

**Rationale:** Secure session configuration prevents session fixation, cookie theft via XSS, and cross-site request forgery via session cookies.

**Audit:**

```
$ php -i \| grep -E 'session\.(cookie_secure\|cookie_httponly\|cookie_samesite\|use_strict_mode)'
```
Verify all are set to appropriate secure values.

**Remediation:**

In php.ini:
```
session.cookie_secure = 1
```

```
session.cookie_httponly = 1
```

```
session.cookie_samesite = Lax
```

```
session.use_strict_mode = 1
```

```
session.use_only_cookies = 1
```

**Default Value:** session.cookie_secure = 0, session.cookie_httponly = 0 (insecure defaults).

**References:** https://www.php.net/manual/en/session.security.ini.php

—


## 3 Database Configuration

This section covers MySQL/MariaDB configuration relevant to WordPress security.

#### 3.1 Ensure the WordPress database user has minimal privileges

**Profile Applicability:** **Level 1**

**Assessment Status:** Automated

**Description:** The MySQL/MariaDB user account used by WordPress should have only the privileges required for normal operation: SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, and DROP on the WordPress database only.

**Rationale:** Granting excessive privileges (e.g., FILE, SUPER, GRANT) increases the impact of a SQL injection vulnerability. With minimal privileges, an attacker who achieves SQLi cannot read arbitrary files, modify grants, or perform administrative operations.

**Impact:** Some plugins may require CREATE TEMPORARY TABLES or LOCK TABLES. Add only when verified necessary.

**Audit:**

Run as the MySQL root user:
SELECT user, host FROM mysql.user;

SHOW GRANTS FOR 'wp_user'@'localhost';
Verify the user has privileges only on the WordPress database and only the required types.

**Remediation:**

REVOKE ALL PRIVILEGES ON \*.\* FROM 'wp_user'@'localhost';

GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, DROP ON wp_database.\* TO 'wp_user'@'localhost';

FLUSH PRIVILEGES;

**Default Value:** Depends on initial setup. Many installation guides grant ALL PRIVILEGES.

—


#### 3.2 Ensure the database is not accessible from external hosts

**Profile Applicability:** **Level 1**

**Assessment Status:** Automated

**Description:** MySQL/MariaDB should be configured to listen only on localhost (127.0.0.1) or a Unix socket. Remote TCP connections should be disabled unless required and tunneled through SSH or a VPN.

**Rationale:** A database accessible over the network expands the attack surface. Brute-force attacks, credential stuffing, and exploitation of database vulnerabilities become possible from any host that can reach the port.

**Audit:**

```
$ grep -E 'bind-address\|skip-networking' /etc/mysql/mysql.conf.d/mysqld.cnf
```
Verify bind-address is 127.0.0.1 or ::1.
```
$ ss -tlnp \| grep 3306
```
Verify MySQL is listening only on 127.0.0.1:3306.

**Remediation:**

In mysqld.cnf or my.cnf under [mysqld]:
```
bind-address = 127.0.0.1
```
Restart MySQL.

**Default Value:** bind-address = 0.0.0.0 (listening on all interfaces) on some distributions.

—


#### 3.3 Ensure a non-default table prefix is used

**Profile Applicability:** **Level 1**

**Assessment Status:** Manual

**Description:** WordPress should be configured with a database table prefix other than the default wp_ to make automated SQL injection attacks less effective.

**Rationale:** Automated attack tools typically assume the default wp_ prefix. A non-default prefix requires attackers to discover the actual table names, adding a layer of difficulty.

**Impact:** Changing the prefix on an existing installation requires updating all table names and option/usermeta values that reference the prefix. This is best done at installation time.

**Audit:**

Inspect wp-config.php:
```
$ grep 'table_prefix' /path/to/wp-config.php
```
Verify the value is not 'wp_'.

**Remediation:**

In wp-config.php, set during installation:
```
$table_prefix = 'wxyz_';
```
Use a short, random string. Do not use personally identifiable or guessable values.

**Default Value:** $table_prefix = 'wp_';

—


#### 3.4 Ensure database query logging is enabled

**Profile Applicability:** **Level 2**

**Assessment Status:** Automated

**Description:** MySQL/MariaDB general query log or slow query log should be enabled to support forensic analysis and intrusion detection.

**Rationale:** Query logs provide critical evidence during incident response, including the exact queries executed by an attacker who achieved SQL injection. They also help identify performance issues that may indicate abuse.

**Impact:** General query logging incurs significant I/O overhead and should be used selectively or only during investigations. Slow query logging has minimal overhead and can remain enabled.

**Audit:**

```
$ grep -E '(general_log\|slow_query_log)' /etc/mysql/mysql.conf.d/mysqld.cnf
```
Verify at minimum slow_query_log is enabled.

**Remediation:**

In mysqld.cnf under [mysqld]:
```
slow_query_log = 1
```

```
slow_query_log_file = /var/log/mysql/mysql-slow.log
```

```
long_query_time = 2
```
For investigations, temporarily enable:
```
general_log = 1
```

```
general_log_file = /var/log/mysql/mysql-general.log
```

**Default Value:** Both logs are disabled by default.

—


## 4 WordPress Core Configuration

This section covers security settings in wp-config.php and WordPress core behavior.

#### 4.1 Ensure DISALLOW_FILE_MODS is set to true

**Profile Applicability:** **Level 1**

**Assessment Status:** Automated

**Description:** The DISALLOW_FILE_MODS constant should be defined as true in wp-config.php. This prevents all file modifications through the WordPress admin interface, including plugin and theme installation, updates, and code editing.

**Rationale:** If an attacker gains admin access (e.g., through a compromised account), DISALLOW_FILE_MODS prevents them from installing malicious plugins, modifying theme files, or uploading web shells through the admin interface. Updates should be handled through deployment pipelines or server-side automation.

**Impact:** Plugin and theme updates cannot be performed through the Dashboard. An alternative update mechanism (WP-CLI, CI/CD pipeline, or managed hosting) is required.

**Audit:**

```
$ grep 'DISALLOW_FILE_MODS' /path/to/wp-config.php
```
Verify: define( 'DISALLOW_FILE_MODS', true );

**Remediation:**

Add to wp-config.php before 'That's all, stop editing!':
define( 'DISALLOW_FILE_MODS', true );

**Default Value:** Not set (file modifications allowed).

**References:** https://developer.wordpress.org/advanced-administration/security/hardening/

—


#### 4.2 Ensure FORCE_SSL_ADMIN is set to true

**Profile Applicability:** **Level 1**

**Assessment Status:** Automated

**Description:** The FORCE_SSL_ADMIN constant forces all admin and login pages to be served over HTTPS.

**Rationale:** Without this setting, admin session cookies could be transmitted over unencrypted HTTP if a user accesses the admin via an HTTP URL, enabling session hijacking via network interception.

**Audit:**

```
$ grep 'FORCE_SSL_ADMIN' /path/to/wp-config.php
```
Verify: define( 'FORCE_SSL_ADMIN', true );

**Remediation:**

Add to wp-config.php:
define( 'FORCE_SSL_ADMIN', true );

**Default Value:** Not set (HTTPS not enforced for admin).

—


#### 4.3 Ensure WordPress debug mode is disabled in production

**Profile Applicability:** **Level 1**

**Assessment Status:** Automated

**Description:** WP_DEBUG must be set to false in production environments. WP_DEBUG_DISPLAY must also be false, and WP_DEBUG_LOG should write to a non-public location if enabled.

**Rationale:** Debug output can reveal file paths, database queries, and PHP errors to attackers. Debug log files in the default location (wp-content/debug.log) are publicly accessible unless explicitly blocked.

**Audit:**

```
$ grep -E 'WP_DEBUG\|WP_DEBUG_DISPLAY\|WP_DEBUG_LOG' /path/to/wp-config.php
```
Verify WP_DEBUG and WP_DEBUG_DISPLAY are false.
If WP_DEBUG_LOG is enabled, verify the log path is outside the web root or blocked by the web server.

**Remediation:**

define( 'WP_DEBUG', false );

define( 'WP_DEBUG_DISPLAY', false );

define( 'WP_DEBUG_LOG', false );
If logging is needed, direct to a non-public path:
define( 'WP_DEBUG_LOG', '/var/log/wordpress/debug.log' );

**Default Value:** WP_DEBUG = false (secure by default). However, many deployment guides enable debug mode.

—


#### 4.4 Ensure XML-RPC is disabled

**Profile Applicability:** **Level 1**

**Assessment Status:** Automated

**Description:** The XML-RPC interface (xmlrpc.php) should be disabled unless specifically required by a remote publishing client or integration.

**Rationale:** XML-RPC is commonly exploited for brute-force amplification attacks (the system.multicall method allows hundreds of password attempts in a single HTTP request) and DDoS amplification via pingbacks.

**Impact:** Disabling XML-RPC will break Jetpack (which requires it for WordPress.com communication), the WordPress mobile app (older versions), and any third-party tool that uses the XML-RPC API.

**Audit:**

```
$ curl -s -o /dev/null -w '%{http_code}' https://example.com/xmlrpc.php
```
A 200 response indicates XML-RPC is accessible. A 403 or 404 indicates it is blocked.

**Remediation:**

Block at the web server level (preferred).
For Nginx:
```
location = /xmlrpc.php {
```

```
deny all;
```

```
return 403;
```

}
Or disable via wp-config.php:
add_filter( 'xmlrpc_enabled', '__return_false' );
(Place in a must-use plugin, not wp-config.php directly.)

**Default Value:** XML-RPC is enabled and accessible by default.

**References:** https://developer.wordpress.org/advanced-administration/security/hardening/

—


#### 4.5 Ensure automatic core updates are enabled

**Profile Applicability:** **Level 1**

**Assessment Status:** Automated

**Description:** WordPress automatic background updates for minor (security) releases must remain enabled. Major version auto-updates should be evaluated based on organizational policy.

**Rationale:** Minor releases contain only security fixes and critical bug patches. Disabling them leaves the site vulnerable to known, publicly disclosed exploits.

**Impact:** In rare cases, a minor update may introduce a regression. Managed hosting providers typically handle this with rollback capabilities.

**Audit:**

```
$ wp config get WP_AUTO_UPDATE_CORE \--path=/path/to/wordpress 2\>/dev/null
```

```
$ grep 'WP_AUTO_UPDATE_CORE\\|AUTOMATIC_UPDATER_DISABLED' /path/to/wp-config.php
```
Verify WP_AUTO_UPDATE_CORE is not set to false and AUTOMATIC_UPDATER_DISABLED is not true.

**Remediation:**

Ensure wp-config.php does not contain:
define( 'AUTOMATIC_UPDATER_DISABLED', true );
Optionally, explicitly enable minor updates:
define( 'WP_AUTO_UPDATE_CORE', 'minor' );

**Default Value:** Minor auto-updates are enabled by default since WordPress 3.7.

—


#### 4.6 Ensure unique authentication keys and salts are configured

**Profile Applicability:** **Level 1**

**Assessment Status:** Automated

**Description:** All eight authentication keys and salts in wp-config.php must be set to unique, random values. These are: AUTH_KEY, SECURE_AUTH_KEY, LOGGED_IN_KEY, NONCE_KEY, and their corresponding SALT counterparts.

**Rationale:** These keys are used to hash session tokens stored in cookies. Default, empty, or guessable values weaken cookie security, making session forgery and hijacking easier.

**Audit:**

```
$ grep -E '(AUTH_KEY\|SECURE_AUTH_KEY\|LOGGED_IN_KEY\|NONCE_KEY\|AUTH_SALT\|SECURE_AUTH_SALT\|LOGGED_IN_SALT\|NONCE_SALT)' /path/to/wp-config.php
```
Verify all eight constants are defined with long, unique random strings. None should be 'put your unique phrase here' (the placeholder value).

**Remediation:**

Generate new keys using the WordPress.org API:
```
$ curl -s https://api.wordpress.org/secret-key/1.1/salt/
```
Replace the key definitions in wp-config.php with the generated output.

**Default Value:** Placeholder values ('put your unique phrase here') in fresh installations.

**References:** https://developer.wordpress.org/advanced-administration/security/hardening/

—


## 5 Authentication and Access Control

This section addresses user authentication, session management, and role-based access control within WordPress.

#### 5.1 Ensure two-factor authentication is required for administrators

**Profile Applicability:** **Level 1**

**Assessment Status:** Manual

**Description:** All user accounts with the Administrator role must have two-factor authentication (2FA) enabled using TOTP-based authenticator apps or hardware security keys (WebAuthn/FIDO2).

**Rationale:** Compromised administrator credentials grant full control over the WordPress installation. 2FA ensures that a stolen password alone is insufficient to gain access.

**Impact:** Requires a 2FA plugin (e.g., Two Factor, Wordfence, WP 2FA, or Fortress). WordPress core does not include 2FA natively as of version 6.9.

**Audit:**

This is a manual check. Verify that:
1\. A 2FA plugin is installed and active.
2\. All administrator accounts have 2FA configured.
3\. SMS-based 2FA is not used (vulnerable to SIM-swapping).

**Remediation:**

Install and configure a 2FA plugin. Require 2FA enrollment for all users with Administrator, Editor, or Shop Manager roles.
Recommended: Enforce 2FA as mandatory for admin roles with a grace period for initial setup.

**Default Value:** No 2FA is configured by default.

**References:** NIST SP 800-63B
https://developer.wordpress.org/advanced-administration/security/hardening/

—


#### 5.2 Ensure the number of administrator accounts is minimized

**Profile Applicability:** **Level 1**

**Assessment Status:** Manual

**Description:** The number of user accounts with the Administrator role should be limited to the minimum required. A primary administrator account should be reserved for emergency use only.

**Rationale:** Each administrator account is a potential entry point. Compromising any single admin account grants full site control. Minimizing admin accounts reduces the attack surface.

**Audit:**

```
$ wp user list \--role=administrator \--fields=ID,user_login,user_email \--path=/path/to/wordpress
```
Review the list. Verify that each admin account is actively needed and assigned to a specific individual.

**Remediation:**

1\. Audit existing administrator accounts.
2\. Downgrade accounts that don't require full admin capabilities to Editor or a custom role.
3\. Reserve one primary administrator account for break-glass emergencies.
4\. Use custom roles with tailored capabilities for day-to-day operations.

**Default Value:** One administrator account is created during installation.

—


#### 5.3 Ensure maximum session lifetime is enforced

**Profile Applicability:** **Level 2**

**Assessment Status:** Automated

**Description:** WordPress session cookies should have a maximum lifetime enforced, regardless of user activity. Privileged accounts (Administrators, Editors) should have shorter session limits (8--24 hours).

**Rationale:** Long-lived sessions increase the window of opportunity for session hijacking. If an auth cookie is stolen, a shorter lifetime limits how long the attacker can use it.

**Impact:** Users will need to re-authenticate more frequently. This can be mitigated with trusted device verification.

**Audit:**

Check for session management plugins or custom code:
```
$ grep -r 'auth_cookie_expiration' /path/to/wp-content/mu-plugins/ /path/to/wp-config.php
```
Verify a filter is in place to limit session lifetime.

**Remediation:**

Add a must-use plugin (wp-content/mu-plugins/session-limits.php):
add_filter( 'auth_cookie_expiration', function( $expiration, $user_id, $remember ) {

```
$user = get_userdata( $user_id );
```

```
if ( in_array( 'administrator', $user-\>roles ) ) {
```

```
return 8 \* HOUR_IN_SECONDS; // 8 hours for admins
```

}

```
return 24 \* HOUR_IN_SECONDS; // 24 hours for others
```

}, 10, 3 );

**Default Value:** 48 hours (2 days) without 'Remember Me'; 14 days with 'Remember Me'.

—


#### 5.4 Ensure user enumeration is prevented

**Profile Applicability:** **Level 1**

**Assessment Status:** Automated

**Description:** The REST API user endpoint and author archive URLs should be restricted to prevent unauthenticated enumeration of usernames.

**Rationale:** Username enumeration provides attackers with valid login targets for brute-force and credential stuffing attacks. The default WordPress REST API exposes user slugs at /wp-json/wp/v2/users, and author archives expose usernames via /?author=N URLs.

**Impact:** Blocking the REST API users endpoint may affect plugins that rely on it for public author data (e.g., some theme author bio features).

**Audit:**

```
$ curl -s https://example.com/wp-json/wp/v2/users \| python3 -m json.tool
```
If the response returns user data, enumeration is possible.
```
$ curl -sI https://example.com/?author=1
```
If the response is a 301 redirect to an author archive, enumeration is possible.

**Remediation:**

Block the REST API users endpoint for unauthenticated requests via a must-use plugin:
add_filter( 'rest_endpoints', function( $endpoints ) {

```
if ( ! is_user_logged_in() ) {
```

unset( $endpoints['/wp/v2/users'] );

unset( $endpoints['/wp/v2/users/(?P\<id\>[\\d]+)'] );

}

```
return $endpoints;
```

});
Block author archive enumeration at the web server level or with a plugin.

**Default Value:** User data is publicly accessible via the REST API and author archives.

—


#### 5.5 Ensure reauthentication is required for privileged actions

**Profile Applicability:** **Level 2**

**Assessment Status:** Manual

**Description:** WordPress should require reauthentication (sudo mode) before performing sensitive administrative actions such as changing user passwords, email addresses, roles, or installing plugins.

**Rationale:** If a session is hijacked, reauthentication limits the damage the attacker can do with the stolen session by requiring the account password for critical actions.

**Impact:** Requires a plugin or custom implementation. WordPress core does not natively enforce reauthentication for most admin actions.

**Audit:**

This is a manual check. Verify that:
1\. A reauthentication mechanism is in place for sensitive admin actions.
2\. Changing user email/password requires current password entry.

**Remediation:**

Implement via a security plugin that supports sudo/reauthentication mode (e.g., Fortress by Snicco), or add custom reauthentication checks to critical admin functions.

**Default Value:** WordPress requires password confirmation only for profile email/password changes.

—


#### 5.6 Ensure unauthenticated REST API access is restricted

**Profile Applicability:** **Level 2**

**Assessment Status:** Automated

**Description:** The WordPress REST API should be restricted to authenticated users only, except for specific public endpoints that require unauthenticated access (e.g., for front-end search or decoupled front-ends).

**Rationale:** By default, the REST API is open and provides significant information about the site structure, content, and users. Restricting access reduces the attack surface and prevents information leakage to unauthenticated actors.

**Impact:** Will break decoupled (headless) installations or plugins that rely on unauthenticated REST API access for front-end functionality.

**Audit:**

```
$ curl -sI https://example.com/wp-json/wp/v2/posts
```
If the response is `200 OK`, unauthenticated access is allowed. A `401 Unauthorized` or `403 Forbidden` indicates restricted access.

**Remediation:**

Add a must-use plugin:
```php
add_filter( 'rest_authentication_errors', function( $result ) {
    if ( ! empty( $result ) ) {
        return $result;
    }
    if ( ! is_user_logged_in() ) {
        return new WP_Error( 'rest_not_logged_in', 'You are not currently logged in.', array( 'status' => 401 ) );
    }
    return $result;
});
```

**Default Value:** REST API is accessible to unauthenticated users.

—


#### 5.7 Ensure a strong password policy is enforced

**Profile Applicability:** **Level 1**

**Assessment Status:** Manual

**Description:** Configure WordPress to enforce a strong password policy that follows current OWASP recommendations: minimum length of 12 characters, checking against breached password/dictionary lists, and avoiding arbitrary complexity rules that lead to predictable patterns.

**Rationale:** Weak passwords are a primary vector for account takeover. Modern standards (NIST SP 800-63B and OWASP) emphasize length and entropy over complexity (e.g., forcing special characters), and mandate checking against known compromised credentials.

**Impact:** Users may need to update existing weak passwords. Requires a plugin for advanced enforcement (e.g., Wordfence, iThemes Security, or Passthrough Authentication).

**Audit:**

This is a manual check. Verify that:
1\. A password enforcement mechanism is active.
2\. Test by attempting to set a simple 8-character password; verify it is rejected.
3\. Verify the policy requires at least 12 characters.

**Remediation:**

1\. Install a security plugin that supports password policy enforcement.
2\. Configure the policy to require a minimum of 12 characters.
3\. Enable "pwned password" checks to block credentials found in previous data breaches.
4\. Remove legacy requirements for symbols or numbers if they interfere with user-generated passphrases.

**Default Value:** WordPress encourages strong passwords but does not strictly enforce a minimum length or check against breached lists by default.

**References:** OWASP Authentication Cheat Sheet, NIST SP 800-63B

—


## 6 File System Permissions

This section covers file ownership and permission settings for the WordPress installation.

#### 6.1 Ensure WordPress files are owned by a non-web-server user

**Profile Applicability:** **Level 1**

**Assessment Status:** Automated

**Description:** WordPress files should be owned by a system user account, not the web server process user (www-data, nginx, apache). The web server should have read access only, with write access limited to specific directories (uploads, cache).

**Rationale:** If the web server process is compromised, file ownership by a separate user prevents the attacker from modifying WordPress core, plugin, or theme files.

**Impact:** WordPress auto-updates and plugin installations via the Dashboard require write access to the file system. With DISALLOW_FILE_MODS enabled (see 4.1), this is not needed.

**Audit:**

```
$ stat -c '%U:%G' /path/to/wordpress/wp-config.php
```

```
$ stat -c '%U:%G' /path/to/wordpress/wp-includes/version.php
```
Verify files are not owned by www-data, nginx, or apache.

**Remediation:**

```
sudo chown -R wp_user:www-data /path/to/wordpress/
```

```
sudo find /path/to/wordpress/ -type d -exec chmod 750 {} \;
```

```
sudo find /path/to/wordpress/ -type f -exec chmod 640 {} \;
```

```
sudo chmod 660 /path/to/wordpress/wp-config.php

# Allow web server to write to uploads (if needed)
sudo find /path/to/wordpress/wp-content/uploads -type d -exec chmod 775 {} \;
sudo find /path/to/wordpress/wp-content/uploads -type f -exec chmod 664 {} \;
```

**Default Value:** Ownership depends on installation method. Many guides set www-data as owner.

—


#### 6.2 Ensure wp-config.php has restrictive permissions

**Profile Applicability:** **Level 1**

**Assessment Status:** Automated

**Description:** wp-config.php must have file permissions of 600 (owner read/write only) or 640 (owner read/write, group read). It should not be readable by the web server user directly; access should be through the PHP-FPM pool running as the site user.

**Rationale:** wp-config.php contains database credentials, authentication keys, and security-sensitive configuration. Broad read permissions could expose these to other users on a shared server or to a compromised web server process.

**Audit:**

```
$ stat -c '%a %U:%G' /path/to/wordpress/wp-config.php
```
Verify permissions are 600 or 640, and the owner is not the web server user.

**Remediation:**

```
chmod 600 /path/to/wordpress/wp-config.php
```

```
chown wp_user:wp_user /path/to/wordpress/wp-config.php
```

**Default Value:** 644 (world-readable) in many default configurations.

—


## 7 Logging and Monitoring

This section addresses audit logging, activity monitoring, and intrusion detection for WordPress.

#### 7.1 Ensure WordPress user activity logging is enabled

**Profile Applicability:** **Level 1**

**Assessment Status:** Manual

**Description:** A WordPress audit logging solution must be installed and configured to record all user activity, including: logins and logouts, failed login attempts, content creation and modification, user account changes, plugin and theme changes, and settings modifications.

**Rationale:** Audit logs are essential for detecting unauthorized activity, supporting incident response, and meeting compliance requirements (PCI DSS, HIPAA, GDPR). Without logging, security incidents may go undetected and forensic analysis is impossible.

**Impact:** Requires a third-party plugin. Recommended: WP Activity Log, Stream, or equivalent.

**Audit:**

This is a manual check. Verify that:
1\. An audit logging plugin is installed and active.
2\. Logs capture login activity, content changes, and settings modifications.
3\. Logs are retained for a period consistent with compliance requirements.

**Remediation:**

Install and configure an audit logging plugin (e.g., WP Activity Log).
Configure log retention for at least 90 days (or per organizational policy).
Enable email alerts for critical events: failed logins, new admin users, plugin changes.
Export logs to a centralized SIEM for correlation (Level 2).

**Default Value:** No audit logging is configured by default.

—


#### 7.2 Ensure file integrity monitoring is configured

**Profile Applicability:** **Level 2**

**Assessment Status:** Automated

**Description:** A mechanism should be in place to detect unauthorized changes to WordPress core files, plugins, themes, and configuration files.

**Rationale:** Unauthorized file modifications are a strong indicator of compromise. Integrity monitoring detects web shells, backdoors, and unauthorized code changes.

**Impact:** Can be implemented at the server level (AIDE, OSSEC, Tripwire) or WordPress level (Wordfence, Sucuri) or both.

**Audit:**

For WordPress core integrity:
```
$ wp core verify-checksums \--path=/path/to/wordpress
```
For plugin integrity:
```
$ wp plugin verify-checksums \--all \--path=/path/to/wordpress
```
Verify both commands report no modifications.

**Remediation:**

1\. Run wp core verify-checksums and wp plugin verify-checksums on a scheduled basis (daily recommended).
2\. Install a file integrity monitoring plugin or configure server-level monitoring.
3\. Alert on any unexpected file changes in wp-includes/, wp-admin/, and plugin directories.

**Default Value:** No integrity monitoring is configured by default.

**References:** https://developer.wordpress.org/cli/commands/core/verify-checksums/

—


## 8 Supply Chain and Extension Management

This section addresses the security of WordPress plugins, themes, and their update processes.

#### 8.1 Ensure all unused plugins and themes are removed

**Profile Applicability:** **Level 1**

**Assessment Status:** Automated

**Description:** All deactivated plugins and non-active themes (except one default fallback theme) should be deleted from the server, not merely deactivated.

**Rationale:** Deactivated plugins and themes remain on the file system and may contain exploitable vulnerabilities. PHP files in deactivated plugins can be accessed directly if the web server processes them, bypassing WordPress entirely.

**Audit:**

```
$ wp plugin list \--status=inactive \--fields=name,version \--path=/path/to/wordpress
```

```
$ wp theme list \--status=inactive \--fields=name,version \--path=/path/to/wordpress
```
Verify no unused plugins or themes are present (one default/fallback theme is acceptable).

**Remediation:**

```
$ wp plugin delete \<plugin-name\> \--path=/path/to/wordpress
```

```
$ wp theme delete \<theme-name\> \--path=/path/to/wordpress
```
Retain only the active theme and one default WordPress theme as a fallback.

**Default Value:** Default themes and example plugins (Akismet, Hello Dolly) are included in fresh installations.

—


#### 8.2 Ensure all plugins and themes are from trusted sources

**Profile Applicability:** **Level 1**

**Assessment Status:** Manual

**Description:** Plugins and themes should only be installed from the official WordPress.org repository or verified commercial vendors. Nulled (pirated) plugins and themes must never be used.

**Rationale:** Nulled and pirated plugins are a leading vector for malware distribution. They frequently contain backdoors, cryptominers, SEO spam injectors, and other malicious code. Even legitimate-appearing free plugins from unofficial sources may be trojanized.

**Audit:**

This is a manual check. Review all installed plugins and themes:
```
$ wp plugin list \--fields=name,status,version,update_available \--path=/path/to/wordpress
```
Verify each plugin is available in the WordPress.org repository or from a known commercial vendor.

**Remediation:**

1\. Audit all installed plugins and themes for their source.
2\. Remove any plugins not traceable to a legitimate source.
3\. Establish an approved plugin list for the organization.
4\. Block plugin installation from the admin interface (see 4.1: DISALLOW_FILE_MODS).

**Default Value:** WordPress allows installation from any ZIP file by default.

—


#### 8.3 Ensure plugin and theme updates are applied promptly

**Profile Applicability:** **Level 1**

**Assessment Status:** Manual

**Description:** Security updates for plugins and themes should be applied within 72 hours of release. Critical security updates should be applied immediately or virtual-patched within 24 hours.

**Rationale:** Known vulnerabilities in popular WordPress plugins are actively exploited within hours of public disclosure. Delayed patching is the most common technical root cause of WordPress compromises.

**Impact:** Updates may occasionally introduce regressions or compatibility issues. Use a staging environment for testing when possible, but do not delay critical security patches.

**Audit:**

```
$ wp plugin list \--fields=name,version,update_available \--path=/path/to/wordpress
```

```
$ wp theme list \--fields=name,version,update_available \--path=/path/to/wordpress
```
Verify no security updates are pending.

**Remediation:**

1\. Enable auto-updates for plugins and themes where supported.
2\. Subscribe to vulnerability notification services (Patchstack, WPScan, Wordfence).
3\. Establish a maintenance schedule for manual update review (weekly minimum).
4\. Deploy virtual patching for critical vulnerabilities that cannot be patched immediately.

**Default Value:** Plugin and theme auto-updates are disabled by default (can be enabled per-plugin).

**References:** https://patchstack.com/database/

—


## 9 Web Application Firewall

This section addresses the deployment and configuration of a Web Application Firewall (WAF) to protect the WordPress application.

#### 9.1 Ensure Web Application Firewall is Configured

**Profile Applicability:** **Level 2**

**Assessment Status:** Manual

**Description:** Deploy a Web Application Firewall (WAF). This can be a server-level solution like **ModSecurity** with the OWASP Core Rule Set (CRS), or a cloud-based solution such as **Cloudflare WAF**, **Akamai**, or **Sucuri**.

**Rationale:** A WAF provides immediate protection against common web attacks (SQLi, XSS, RCE) before they reach the application. For server-level WAFs like ModSecurity, WordPress-specific exclusion rules are necessary to allow legitimate functionality (like post saving and media uploads) to pass through without being blocked as false positives. Cloud WAFs typically manage these rulesets automatically.

**Impact:** WAFs can introduce latency and false positives. Tuning is required. Cloud WAFs may require DNS changes.

**Audit:**

This is a manual check. Verify that:
1. A WAF is active and blocking malicious requests (verify via logs or simulation).
2. If using ModSecurity, the OWASP Core Rule Set and WordPress Rule Exclusions are enabled.
3. If using a Cloud WAF, the WordPress-specific protection profile is active.

**Remediation:**

For server-level WAF:
1. Install ModSecurity and the OWASP Core Rule Set.
2. Enable the WordPress exclusion rule set.
   - For OWASP CRS v3.x: Uncomment the WordPress exclusion rule in `crs-setup.conf`.
   - For OWASP CRS v4.x: Use the [WordPress Rule Exclusions Plugin](https://github.com/coreruleset/wordpress-rule-exclusions-plugin).

For Cloud WAF:
1. Route traffic through a provider such as Cloudflare, Akamai, or Sucuri.
2. Enable Managed Rulesets related to WordPress and OWASP Top 10.

**Default Value:** No WAF is configured by default.

**References:** https://coreruleset.org/
https://github.com/coreruleset/wordpress-rule-exclusions-plugin

—


## Appendix A: Recommendation Summary

The following table summarizes all recommendations in this benchmark.

| **ID** | **Recommendation**                                  | **Level** | **Assessment** |
| :--- | :-------------------------------------------------- | :-------- | :------------- |
| 1.1  | Ensure TLS 1.2+ is enforced                         | L1        | Automated      |
| 1.2  | Ensure HTTP security headers are configured         | L1        | Automated      |
| 1.3  | Ensure server tokens are hidden                     | L1        | Automated      |
| 1.4  | Ensure PHP execution is blocked in uploads          | L1        | Automated      |
| 1.5  | Ensure rate limiting is configured for all APIs    | L1        | Automated      |
| 2.1  | Ensure expose_php is disabled                       | L1        | Automated      |
| 2.2  | Ensure display_errors is disabled                   | L1        | Automated      |
| 2.3  | Ensure dangerous PHP functions are disabled         | L1        | Automated      |
| 2.4  | Ensure open_basedir restricts file access           | L2        | Automated      |
| 2.5  | Ensure PHP session security is configured           | L1        | Automated      |
| 3.1  | Ensure DB user has minimal privileges               | L1        | Automated      |
| 3.2  | Ensure DB is not externally accessible              | L1        | Automated      |
| 3.3  | Ensure non-default table prefix is used             | L1        | Manual         |
| 3.4  | Ensure database query logging is enabled            | L2        | Automated      |
| 4.1  | Ensure DISALLOW_FILE_MODS is true                   | L1        | Automated      |
| 4.2  | Ensure FORCE_SSL_ADMIN is true                      | L1        | Automated      |
| 4.3  | Ensure debug mode is disabled                       | L1        | Automated      |
| 4.4  | Ensure XML-RPC is disabled                          | L1        | Automated      |
| 4.5  | Ensure automatic core updates are enabled           | L1        | Automated      |
| 4.6  | Ensure unique auth keys and salts are configured    | L1        | Automated      |
| 5.1  | Ensure 2FA is required for administrators           | L1        | Manual         |
| 5.2  | Ensure admin accounts are minimized                 | L1        | Manual         |
| 5.3  | Ensure max session lifetime is enforced             | L2        | Automated      |
| 5.4  | Ensure user enumeration is prevented                | L1        | Automated      |
| 5.5  | Ensure reauthentication for privileged actions      | L2        | Manual         |
| 5.6  | Ensure unauthenticated REST API is restricted       | L2        | Automated      |
| 5.7  | Ensure strong password policy is enforced          | L1        | Manual         |
| 6.1  | Ensure files are owned by non-web-server user       | L1        | Automated      |
| 6.2  | Ensure wp-config.php has restrictive permissions    | L1        | Automated      |
| 7.1  | Ensure user activity logging is enabled             | L1        | Manual         |
| 7.2  | Ensure file integrity monitoring is configured      | L2        | Automated      |
| 8.1  | Ensure unused plugins and themes are removed        | L1        | Automated      |
| 8.2  | Ensure extensions are from trusted sources          | L1        | Manual         |
| 8.3  | Ensure plugin/theme updates are applied promptly    | L1        | Manual         |
| 9.1  | Ensure Web Application Firewall is Configured        | L2        | Manual         |

## License

This document is licensed under the Creative Commons Attribution-ShareAlike 4.0 International License (CC BY-SA 4.0). This document is an independent work.
