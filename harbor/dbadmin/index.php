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
            return "<a href='/sites' id='h1' title='Back to Harbor'>Harbor</a>";
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
            echo "<p>Open a database from its site's <b>Databases</b> tab in Harbor. "
               . "Editor sessions last two hours.</p><p><a href='/sites'>Go to Harbor</a></p>";
        }
        function permanentLogin($create = false) {
            return '';
        }
    }
    return new HarborAdminer;
}

include HARBOR_ADMINER;
