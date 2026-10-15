<?php
/* Harbor database editor: Adminer, signed in to one database.
 *
 * The panel's "Open" button creates a temporary MySQL user that can only use that
 * database and writes its login to a one-time token file. This wrapper swaps the
 * token for an Adminer login (the password never reaches the browser), always
 * connects to the local server, and only accepts Harbor's temporary users.
 * nginx lets a browser reach this page only while it's signed in to the panel.
 */
const HARBOR_ADMINER = '/opt/harbor/adminer/adminer.php';
const HARBOR_TOKENS = '/var/lib/harbor-dbadmin/tokens';
const HARBOR_USER_RE = '~^hbr_ed_[0-9a-f]{12}$~';

function harbor_page(int $code, string $title, string $text): void {
    http_response_code($code);
    header('Content-Type: text/html; charset=utf-8');
    header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'");
    $t = htmlspecialchars($title);
    echo "<!doctype html><meta charset='utf-8'><meta name='viewport' content='width=device-width'><title>$t</title>"
       . "<body style='font:16px/1.5 system-ui,sans-serif;max-width:34rem;margin:12vh auto;padding:0 16px;color:#16242c'>"
       . "<h1 style='font-size:1.3rem'>$t</h1><p>$text</p><p><a href='/sites' style='color:#0d7a6b'>Back to Harbor</a></p>";
    exit;
}

// the Harbor look (served from here because nginx only routes /dbadmin/ to this file)
if (isset($_GET['harbor_css'])) {
    header('Content-Type: text/css; charset=utf-8');
    header('Cache-Control: max-age=86400');
    readfile(__DIR__ . '/harbor.css');
    exit;
}

if (!is_file(HARBOR_ADMINER)) {
    harbor_page(503, 'Database editor not installed', 'Run <code>sudo bash /opt/harbor/source/install.sh</code> on the server to add it.');
}

if (isset($_GET['harbor'])) {
    $token = (string) $_GET['harbor'];
    $login = null;
    if (preg_match('~^[A-Za-z0-9_-]{20,100}$~', $token)) {
        $file = HARBOR_TOKENS . "/$token.json";
        $raw = @file_get_contents($file);
        if ($raw !== false) {
            @unlink($file);  // one use only
            $login = json_decode($raw, true);
        }
    }
    if (!is_array($login) || ($login['expires'] ?? 0) < time() || !preg_match(HARBOR_USER_RE, $login['username'] ?? '')) {
        harbor_page(403, 'This link has expired', "Links from the panel work once, for two minutes. Go back to the site's Databases tab and click Open again.");
    }
    // hand Adminer a login form submission, then let it redirect to the database
    // remember which site this came from, for the "back to Harbor" link
    setcookie('harbor_site', (string) (int) ($login['site_id'] ?? 0),
              ['path' => '/dbadmin/', 'secure' => true, 'httponly' => true, 'samesite' => 'Strict']);
    $_COOKIE['harbor_site'] = (string) (int) ($login['site_id'] ?? 0);
    $_POST = ['auth' => ['driver' => 'server', 'server' => '', 'username' => $login['username'],
                         'password' => $login['password'], 'db' => $login['db'], 'permanent' => '']];
    $_SERVER['REQUEST_METHOD'] = 'POST';
    unset($_GET['harbor']);
    $_SERVER['REQUEST_URI'] = strtok($_SERVER['REQUEST_URI'], '?');
    $_SERVER['QUERY_STRING'] = '';
}

function adminer_object() {
    class HarborAdminer extends \Adminer\Adminer {
        function name() {
            $site = (int) ($_COOKIE['harbor_site'] ?? 0);
            $back = $site ? "/sites/$site/databases" : '/sites';
            return "<a href='$back' id='h1' title='Back to Harbor'>"
                 . "<svg viewBox='0 0 32 32' aria-hidden='true'><rect width='32' height='32' rx='7' fill='#0d2a33'/>"
                 . "<g fill='none' stroke='#5fd3c0' stroke-width='2.4' stroke-linecap='round'><circle cx='16' cy='8' r='2.8'/>"
                 . "<path d='M16 11v15M10 15h12M6.5 19c1 4.5 4.8 7 9.5 7s8.5-2.5 9.5-7'/></g></svg>"
                 . "<span>Harbor<small>Database editor</small></span></a>";
        }
        function css() {
            return ['?harbor_css=' . crc32((string) @file_get_contents(__DIR__ . '/harbor.css')) => ''];
        }
        // always the local server, whatever the URL says
        function credentials() {
            return ['localhost', $_GET['username'] ?? '', \Adminer\get_password()];
        }
        function login($login, $password) {
            return preg_match(HARBOR_USER_RE, (string) $login) ? true : 'Open databases from Harbor.';
        }
        function databases($flush = true) {
            $hidden = ['information_schema', 'performance_schema', 'mysql', 'sys'];
            return array_values(array_filter(\Adminer\get_databases($flush), fn($d) => !in_array($d, $hidden, true)));
        }
        function loginForm() {
            $site = (int) ($_COOKIE['harbor_site'] ?? 0);
            $back = $site ? "/sites/$site/databases" : '/sites';
            echo "<div class='message' style='color:inherit'><b>Open a database from Harbor.</b> "
               . "On the site's Databases tab, click Open next to the database. Editor sessions last two hours.</div>"
               . "<p><a href='$back'>Back to Harbor</a></p>";
        }
        function permanentLogin($create = false) {
            return '';
        }
    }
    return new HarborAdminer;
}

include HARBOR_ADMINER;
