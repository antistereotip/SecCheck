<?php
declare(strict_types=1);
/**
 * SecCheck – skener bezbednosti za PHP sajtove i skripte
 *
 * Module:
 *  1) URL skener (bezbedne, neagresivne provere): TLS, security headeri, kolačići, CORS, HTTP metode,
 *     curenje informacija, izložene osetljive datoteke (.env, .git, phpinfo...), forme bez CSRF tokena,
 *     mixed content, reflektovanje unosa, prikaz grešaka (PHP/SQL), directory listing, izložen PHP izvorni kod.
 *  2) Statička analiza PHP koda: eval, command injection, SQLi, XSS, LFI/RFI, unserialize, upload,
 *     open redirect, slabi hash-ovi, hardkodovane lozinke itd.
 *
 * Koristi ISKLJUČIVO na sajtovima koje poseduješ ili imaš pisanu dozvolu da testiraš.
 * Zahteva: PHP 8.0+, cURL, DOM, OpenSSL ekstenzije.
 */

session_start();
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'");

const SEV_ORDER  = ['critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3, 'info' => 4];
const SEV_WEIGHT = ['critical' => 25, 'high' => 15, 'medium' => 7, 'low' => 3, 'info' => 0];
const SEV_LABEL  = ['critical' => 'KRITIČNO', 'high' => 'VISOKO', 'medium' => 'SREDNJE', 'low' => 'NISKO', 'info' => 'INFO'];

function e(string $s): string { return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }

/* ------------------------------------------------------------------ */
/*  Statička analiza PHP koda                                          */
/* ------------------------------------------------------------------ */
final class CodeAnalyzer
{
    private static function rules(): array
    {
        $in = '\$_(?:GET|POST|REQUEST|COOKIE)';
        return [
            ['~\beval\s*\(~i', 'critical', 'eval() – izvršavanje proizvoljnog koda', 'Ukloni eval(); zameni jasnom logikom.'],
            ['~\bassert\s*\(\s*\$~i', 'high', 'assert() sa promenljivom (izvršava kod u starijim PHP verzijama)', 'Ukloni assert() iz produkcijskog koda.'],
            ['~\b(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(~i', 'high', 'Izvršavanje sistemskih komandi (command injection)', 'Izbegavaj; ako je neophodno koristi escapeshellarg() i whitelist.'],
            ['~`[^`\n]*\$\w+[^`\n]*`~', 'high', 'Backtick operator sa promenljivom (command injection)', 'Zameni bezbednom alternativom + escapeshellarg().'],
            ['~\bunserialize\s*\([^;]*' . $in . '~i', 'critical', 'unserialize() nad korisničkim unosom (PHP Object Injection)', 'Koristi json_decode() umesto unserialize().'],
            ['~\bunserialize\s*\(~i', 'medium', 'unserialize() – rizik od Object Injection', "Koristi ['allowed_classes' => false] ili JSON."],
            ['~\b(?:include|require)(?:_once)?\b[^;]*' . $in . '~i', 'critical', 'include/require sa korisničkim unosom (LFI/RFI)', 'Koristi whitelist dozvoljenih fajlova.'],
            ['~(?:mysqli?_query|->query|->exec|pg_query|sqlite_query)\s*\([^;]*' . $in . '~i', 'critical', 'Korisnički unos direktno u SQL upitu (SQL Injection)', 'Koristi PDO/mysqli prepared statements.'],
            ['~[\x22\x27]\s*(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^;]*?\$\w+~i', 'high', 'SQL upit sa ubačenom promenljivom (moguć SQL Injection)', 'Koristi parametrizovane upite.'],
            ['~\b(?:echo|print)\b[^;]*' . $in . '|<\?=[^?]*' . $in . '~i', 'high', 'Ispis korisničkog unosa bez enkodovanja (XSS)', 'htmlspecialchars($x, ENT_QUOTES | ENT_SUBSTITUTE, "UTF-8")',
                '~htmlspecialchars|htmlentities|intval|\(int\)|filter_var|json_encode~i'],
            ['~\bextract\s*\(\s*' . $in . '~i', 'high', 'extract() nad korisničkim unosom (prepisivanje promenljivih)', 'Ručno čitaj samo očekivana polja.'],
            ['~' . $in . '\s*\[[^\]]*\]\s*\(~', 'critical', 'Korisnički unos se poziva kao funkcija', 'Nikad ne pozivaj funkcije po imenu iz unosa.'],
            ['~\b(?:call_user_func(?:_array)?|array_map|usort|array_filter)\s*\(\s*' . $in . '~i', 'high', 'Callback iz korisničkog unosa (izvršavanje koda)', 'Koristi whitelist dozvoljenih funkcija.'],
            ['~preg_replace\s*\(\s*[\x22\x27]/[^\x22\x27]*/[a-z]*e[a-z]*[\x22\x27]~i', 'high', 'preg_replace sa /e modifikatorom (izvršavanje koda)', 'Koristi preg_replace_callback().'],
            ['~\b(?:file_get_contents|file_put_contents|fopen|readfile|file|copy|unlink|rename)\s*\([^;]*' . $in . '~i', 'high', 'Rad sa fajlovima nad korisničkim unosom (path traversal / SSRF)', 'Validiraj putanju: realpath() + whitelist direktorijum.'],
            ['~\bmove_uploaded_file\s*\(~i', 'medium', 'Upload fajlova – proveri validaciju', 'Proveri MIME (finfo), ekstenziju whitelist-om, nasumično ime, upload van web root-a.'],
            ['~header\s*\(\s*[\x22\x27]Location:[^;]*' . $in . '~i', 'medium', 'Open redirect', 'Redirektuj samo na whitelist adresa.'],
            ['~\bmail\s*\([^;]*' . $in . '~i', 'medium', 'Korisnički unos u mail() (header injection)', 'Ukloni \\r i \\n iz unosa; koristi PHPMailer.'],
            ['~\bsession_id\s*\([^)]*' . $in . '~i', 'high', 'Session ID iz korisničkog unosa (session fixation)', 'Nikad ne postavljaj session_id iz zahteva.'],
            ['~CURLOPT_SSL_VERIFY(?:PEER|HOST)\s*,\s*(?:false|0)~i', 'high', 'Isključena provera TLS sertifikata', 'Ostavi verifikaciju uključenom.'],
            ['~(?:password|passwd|pwd|secret|api_?key|token)[\x22\x27]?\s*(?:=>|=)\s*[\x22\x27][^\x22\x27$]{4,}[\x22\x27]~i', 'medium', 'Hardkodovani kredencijali/ključevi', 'Prebaci u promenljive okruženja / van repozitorijuma.'],
            ['~\b(?:md5|sha1|crypt)\s*\(~i', 'low', 'Slab hash algoritam', 'Za lozinke koristi password_hash()/password_verify().'],
            ['~\b(?:rand|mt_rand|uniqid|lcg_value)\s*\(~i', 'low', 'Nesiguran generator slučajnih brojeva', 'Za tokene koristi random_bytes()/random_int().'],
            ['~\bmysql_\w+\s*\(~i', 'medium', 'Zastarele mysql_* funkcije', 'Pređi na PDO ili mysqli.'],
            ['~\$\$\w+~', 'medium', 'Promenljive promenljivih ($$var)', 'Koristi nizove umesto dinamičkih imena.'],
            ['~\bphpinfo\s*\(~i', 'medium', 'phpinfo() otkriva konfiguraciju servera', 'Ukloni iz produkcije.'],
            ['~ini_set\s*\(\s*[\x22\x27]display_errors[\x22\x27]\s*,\s*[\x22\x27]?(?:1|on|true)~i', 'low', 'Uključen display_errors', 'Isključi na produkciji, loguj u fajl.'],
            ['~\b(?:loadXML|simplexml_load_(?:string|file))\s*\(~i', 'low', 'XML parsiranje – proveri XXE', 'Koristi LIBXML_NONET, nikad LIBXML_NOENT.'],
            ['~\b(?:base64_decode|gzinflate|str_rot13|gzuncompress)\s*\(~i', 'low', 'Dekodiranje/obfuskacija – proveri da nije webshell', 'Pregledaj šta se dekodira i izvršava.'],
        ];
    }

    public static function analyze(string $code): array
    {
        $findings = [];
        $hits = [];
        $rules = self::rules();
        foreach (preg_split('/\R/', $code) as $i => $line) {
            $t = ltrim($line);
            if ($t === '' || str_starts_with($t, '//') || str_starts_with($t, '#') || str_starts_with($t, '*') || str_starts_with($t, '/*')) continue;
            foreach ($rules as $ri => $r) {
                if (preg_match($r[0], $line) && !(isset($r[4]) && preg_match($r[4], $line))) {
                    $hits[$ri][] = ($i + 1) . ': ' . mb_substr(trim($line), 0, 110);
                }
            }
        }
        foreach ($hits as $ri => $list) {
            $r = $rules[$ri];
            $detail = 'Pogođeno ' . count($list) . '× → ' . implode(' | ', array_slice($list, 0, 4));
            $findings[] = ['sev' => $r[1], 'title' => $r[2], 'detail' => $detail, 'fix' => $r[3]];
        }
        return $findings;
    }
}

/* ------------------------------------------------------------------ */
/*  URL skener                                                         */
/* ------------------------------------------------------------------ */
final class Scanner
{
    public array $f = [];
    private bool $verify = true;
    private const MAX_BODY = 2097152;

    private const FILES = [
        '/.env'                => ['~(?:DB_|APP_KEY|SECRET|PASSWORD|API_KEY)\w*\s*=~i', 'critical', '.env fajl je javno dostupan'],
        '/.git/HEAD'           => ['~^ref:\s*refs/~', 'critical', '.git repozitorijum je javno dostupan (izvorni kod curi)'],
        '/.git/config'         => ['~\[core\]~', 'critical', '.git/config je javno dostupan'],
        '/.htpasswd'           => ['~^\w+:(?:\$apr1\$|\$2y\$|\{SHA\}|[\w./]{13})~m', 'critical', '.htpasswd je javno dostupan'],
        '/backup.sql'          => ['~CREATE TABLE|INSERT INTO~i', 'critical', 'SQL backup je javno dostupan'],
        '/dump.sql'            => ['~CREATE TABLE|INSERT INTO~i', 'critical', 'SQL dump je javno dostupan'],
        '/config.php.bak'      => ['~<\?php|define\s*\(|DB_PASSWORD~i', 'critical', 'Backup konfiguracije je dostupan'],
        '/wp-config.php.bak'   => ['~DB_PASSWORD|<\?php~i', 'critical', 'Backup wp-config.php je dostupan'],
        '/wp-config.php~'      => ['~DB_PASSWORD|<\?php~i', 'critical', 'Backup wp-config.php je dostupan'],
        '/phpinfo.php'         => ['~phpinfo\(\)|PHP Version~i', 'high', 'phpinfo() stranica je javno dostupna'],
        '/info.php'            => ['~phpinfo\(\)|PHP Version~i', 'high', 'info.php (phpinfo) je javno dostupan'],
        '/error_log'           => ['~PHP (?:Warning|Fatal|Notice|Parse)~i', 'high', 'error_log je javno dostupan'],
        '/server-status'       => ['~Apache Server Status~i', 'medium', 'Apache server-status je javno dostupan'],
        '/adminer.php'         => ['~Adminer~i', 'medium', 'Adminer je javno dostupan'],
        '/phpmyadmin/'         => ['~phpMyAdmin~i', 'medium', 'phpMyAdmin je javno dostupan – ograniči pristup po IP-u'],
        '/composer.lock'       => ['~"packages"~', 'low', 'composer.lock otkriva verzije biblioteka'],
        '/composer.json'       => ['~"require"~', 'low', 'composer.json otkriva zavisnosti'],
        '/.DS_Store'           => ['~Bud1~', 'low', '.DS_Store otkriva strukturu direktorijuma'],
    ];

    public function add(string $sev, string $title, string $detail = '', string $fix = ''): void
    {
        $this->f[] = ['sev' => $sev, 'title' => $title, 'detail' => $detail, 'fix' => $fix];
    }

    /** SSRF zaštita: razrešava domen i odbija privatne/rezervisane IP adrese. */
    public static function resolve(string $host): array
    {
        static $cache = [];
        if (isset($cache[$host])) return $cache[$host];
        $ips = filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ? [$host] : (gethostbynamel($host) ?: []);
        if (!$ips) throw new RuntimeException("Domen se ne može razrešiti: $host");
        foreach ($ips as $ip) {
            if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                throw new RuntimeException("Meta pokazuje na privatnu/rezervisanu adresu ($ip) – blokirano.");
            }
        }
        return $cache[$host] = $ips;
    }

    private function http(string $url, string $method = 'GET', array $hdr = []): array
    {
        $p = parse_url($url);
        $host = trim($p['host'], '[]');
        $port = $p['port'] ?? (strtolower($p['scheme']) === 'https' ? 443 : 80);
        $ip = self::resolve($host)[0];
        $headers = [];
        $data = '';
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_CUSTOMREQUEST  => $method,
            CURLOPT_NOBODY         => $method === 'HEAD',
            CURLOPT_RESOLVE        => ["$host:$port:$ip"],   // fiksira IP (zaštita od DNS rebinding-a)
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT        => 10,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_USERAGENT      => 'SecCheck/1.0 (self-audit)',
            CURLOPT_HTTPHEADER     => $hdr,
            CURLOPT_PROTOCOLS      => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_SSL_VERIFYPEER => $this->verify,
            CURLOPT_SSL_VERIFYHOST => $this->verify ? 2 : 0,
            CURLOPT_HEADERFUNCTION => function ($c, $l) use (&$headers) {
                if (str_contains($l, ':')) {
                    [$k, $v] = explode(':', $l, 2);
                    $headers[strtolower(trim($k))][] = trim($v);
                }
                return strlen($l);
            },
            CURLOPT_WRITEFUNCTION  => function ($c, $d) use (&$data) {
                $room = self::MAX_BODY - strlen($data);
                if ($room > 0) $data .= substr($d, 0, $room);
                return strlen($d);
            },
        ]);
        curl_exec($ch);
        $r = ['code' => (int)curl_getinfo($ch, CURLINFO_HTTP_CODE), 'h' => $headers, 'body' => $data, 'err' => curl_error($ch)];
        curl_close($ch);
        usleep(150000); // blago opterećenje mete
        return $r;
    }

    private static function h(array $r, string $name): ?string { return $r['h'][$name][0] ?? null; }

    public function scan(string $url): void
    {
        $p = parse_url($url);
        if (!$p || !isset($p['scheme'], $p['host']) || !in_array(strtolower($p['scheme']), ['http', 'https'], true)) {
            throw new RuntimeException('Neispravan URL (dozvoljeni su samo http:// i https://).');
        }
        if (isset($p['user']) || isset($p['pass'])) throw new RuntimeException('URL sa kredencijalima nije dozvoljen.');
        $https  = strtolower($p['scheme']) === 'https';
        $port   = $p['port'] ?? ($https ? 443 : 80);
        $origin = strtolower($p['scheme']) . '://' . $p['host'] . (isset($p['port']) ? ':' . $p['port'] : '');
        self::resolve(trim($p['host'], '[]'));

        if ($https) $this->tls(trim($p['host'], '[]'), $port);
        else $this->add('high', 'Sajt radi preko HTTP-a (bez šifrovanja)', 'Saobraćaj i lozinke mogu biti presretnuti.', 'Uvedi HTTPS (Let\'s Encrypt) i preusmeri sav HTTP saobraćaj.');

        $r = $this->http($url);
        if (!$r['code']) throw new RuntimeException('Nije moguće učitati stranicu: ' . $r['err']);
        $body = $r['body'];

        $this->headers($r, $https);
        $this->cookies($r, $https);
        $this->disclosure($r);
        $this->cors($url);
        $this->methods($url);
        $this->html($body, $https, $p['host']);
        $this->sourceLeak($body);
        $this->listing($body);
        $this->probes($url);
        $this->sensitiveFiles($origin);
    }

    private function tls(string $host, int $port): void
    {
        $ctx = stream_context_create(['ssl' => ['capture_peer_cert' => true, 'verify_peer' => true, 'verify_peer_name' => true, 'peer_name' => $host, 'SNI_enabled' => true]]);
        $s = @stream_socket_client('ssl://' . self::resolve($host)[0] . ':' . $port, $en, $es, 8, STREAM_CLIENT_CONNECT, $ctx);
        if (!$s) {
            $this->verify = false;
            $this->add('high', 'TLS sertifikat nije validan ili TLS nije dostupan', (string)$es, 'Instaliraj validan sertifikat za tačan domen.');
            return;
        }
        $cert = openssl_x509_parse(stream_context_get_params($s)['options']['ssl']['peer_certificate']);
        $days = (int)floor(($cert['validTo_time_t'] - time()) / 86400);
        if ($days < 0) $this->add('high', 'TLS sertifikat je istekao', "Istekao pre " . abs($days) . " dana.", 'Obnovi sertifikat.');
        elseif ($days < 14) $this->add('medium', 'TLS sertifikat uskoro ističe', "Preostalo dana: $days", 'Uključi automatsku obnovu.');
        else $this->add('info', 'TLS sertifikat je validan', "Važi još $days dana.");
        $proto = stream_get_meta_data($s)['crypto']['protocol'] ?? '';
        if ($proto && !preg_match('/TLSv1\.[23]/', $proto)) $this->add('high', 'Zastareo TLS protokol', $proto, 'Dozvoli samo TLS 1.2 i 1.3.');
        fclose($s);
    }

    private function headers(array $r, bool $https): void
    {
        $csp = self::h($r, 'content-security-policy');
        if (!$csp) $this->add('medium', 'Nedostaje Content-Security-Policy', 'Nema odbrane u dubini protiv XSS-a.', "Dodaj header, npr. Content-Security-Policy: default-src 'self'");
        if ($https) {
            $hsts = self::h($r, 'strict-transport-security');
            if (!$hsts) $this->add('medium', 'Nedostaje HSTS', '', 'Strict-Transport-Security: max-age=31536000; includeSubDomains');
            elseif (preg_match('/max-age=(\d+)/i', $hsts, $m) && (int)$m[1] < 15552000) $this->add('low', 'HSTS max-age je prekratak', $hsts, 'Postavi najmanje 31536000.');
        }
        if (!self::h($r, 'x-frame-options') && !preg_match('/frame-ancestors/i', (string)$csp)) $this->add('medium', 'Nema zaštite od clickjacking-a', '', "X-Frame-Options: DENY ili CSP frame-ancestors 'none'");
        if (strtolower((string)self::h($r, 'x-content-type-options')) !== 'nosniff') $this->add('low', 'Nedostaje X-Content-Type-Options: nosniff');
        if (!self::h($r, 'referrer-policy')) $this->add('low', 'Nedostaje Referrer-Policy', '', 'Referrer-Policy: strict-origin-when-cross-origin');
        if (!self::h($r, 'permissions-policy')) $this->add('info', 'Nedostaje Permissions-Policy');
    }

    private function cookies(array $r, bool $https): void
    {
        foreach ($r['h']['set-cookie'] ?? [] as $c) {
            $name = trim(explode('=', $c, 2)[0]);
            $l = strtolower($c);
            $miss = [];
            if (!str_contains($l, 'httponly')) $miss[] = 'HttpOnly';
            if ($https && !str_contains($l, 'secure')) $miss[] = 'Secure';
            if (!str_contains($l, 'samesite')) $miss[] = 'SameSite';
            if ($miss) {
                $sev = (preg_match('/sess|auth|token|login/i', $name) && !str_contains($l, 'httponly')) ? 'medium' : 'low';
                $this->add($sev, "Kolačić „{$name}“ nema: " . implode(', ', $miss), '', 'session.cookie_httponly=1, session.cookie_secure=1, session.cookie_samesite=Lax');
            }
        }
    }

    private function disclosure(array $r): void
    {
        $srv = self::h($r, 'server');
        if ($srv && preg_match('/\d+\.\d+/', $srv)) $this->add('low', 'Server otkriva verziju', $srv, 'ServerTokens Prod / server_tokens off');
        $xp = self::h($r, 'x-powered-by');
        if ($xp) {
            $this->add('low', 'X-Powered-By otkriva tehnologiju', $xp, 'expose_php = Off');
            if (preg_match('/PHP\/(\d+)\.(\d+)/i', $xp, $m) && ((int)$m[1] < 8 || ((int)$m[1] === 8 && (int)$m[2] < 2))) {
                $this->add('high', "PHP {$m[1]}.{$m[2]} više nije podržan (nema sigurnosnih zakrpa)", $xp, 'Nadogradi PHP – proveri php.net/supported-versions.php');
            }
        }
    }

    private function cors(string $url): void
    {
        $r = $this->http($url, 'GET', ['Origin: https://evil.example']);
        $acao = self::h($r, 'access-control-allow-origin');
        $acac = strtolower((string)self::h($r, 'access-control-allow-credentials')) === 'true';
        if ($acao === 'https://evil.example') $this->add($acac ? 'high' : 'medium', 'CORS reflektuje proizvoljan Origin' . ($acac ? ' sa credentials' : ''), "ACAO: $acao", 'Koristi striktnu listu dozvoljenih origin-a.');
        elseif ($acao === '*') $this->add('low', 'CORS dozvoljava sve origin-e (*)', '', 'Ograniči ako API nije javni.');
    }

    private function methods(string $url): void
    {
        $r = $this->http($url, 'OPTIONS');
        $allow = strtoupper((string)(self::h($r, 'allow') ?? ''));
        foreach (['TRACE', 'PUT', 'DELETE', 'CONNECT'] as $m) {
            if (preg_match('/\b' . $m . '\b/', $allow)) $this->add('medium', "Dozvoljena HTTP metoda $m", $allow, 'Onemogući nepotrebne metode na web serveru.');
        }
    }

    private function html(string $body, bool $https, string $host): void
    {
        if (!preg_match('/<html|<form|<body/i', $body)) return;
        libxml_use_internal_errors(true);
        $d = new DOMDocument();
        $d->loadHTML('<?xml encoding="UTF-8">' . $body, LIBXML_NONET);
        $x = new DOMXPath($d);

        foreach ($x->query('//form') as $form) {
            /** @var DOMElement $form */
            $method = strtolower($form->getAttribute('method') ?: 'get');
            $action = $form->getAttribute('action');
            $hasPass = $x->query('.//input[@type="password"]', $form)->length > 0;
            if ($method === 'post') {
                $csrf = false;
                foreach ($x->query('.//input[@type="hidden"]', $form) as $i) {
                    if (preg_match('/csrf|token|nonce|authenticity|xsrf/i', $i->getAttribute('name'))) $csrf = true;
                }
                if (!$csrf) $this->add('medium', 'POST forma bez vidljivog CSRF tokena', 'action="' . mb_substr($action, 0, 80) . '"', 'Dodaj nasumični token vezan za sesiju i proveri ga hash_equals()-om.');
            }
            if ($hasPass && (!$https || str_starts_with(strtolower($action), 'http://'))) $this->add('high', 'Forma sa lozinkom se šalje preko HTTP-a', $action);
            if ($hasPass && strtolower($form->getAttribute('autocomplete')) !== 'off' && $method === 'get') $this->add('high', 'Forma sa lozinkom koristi GET', 'Lozinka završava u URL-u i logovima.');
        }
        foreach ($x->query('//script[@src]') as $s) {
            $src = $s->getAttribute('src');
            $h = parse_url($src, PHP_URL_HOST);
            if ($h && strcasecmp($h, $host) !== 0 && !$s->hasAttribute('integrity')) $this->add('low', 'Eksterna skripta bez SRI (integrity)', mb_substr($src, 0, 100), 'Dodaj integrity i crossorigin atribute.');
            if ($https && str_starts_with(strtolower($src), 'http://')) $this->add('medium', 'Mixed content: skripta preko HTTP-a', $src);
        }
        if ($https) {
            foreach ($x->query('//img[@src]|//link[@href]|//iframe[@src]') as $n) {
                $u = $n->getAttribute('src') ?: $n->getAttribute('href');
                if (str_starts_with(strtolower($u), 'http://')) { $this->add('low', 'Mixed content (resurs preko HTTP-a)', mb_substr($u, 0, 100)); break; }
            }
        }
        foreach ($x->query('//comment()') as $c) {
            if (preg_match('/password|passwd|secret|api[_-]?key|todo|debug|admin|TODO|FIXME/i', $c->nodeValue)) {
                $this->add('low', 'HTML komentar sa osetljivim sadržajem', mb_substr(trim($c->nodeValue), 0, 100), 'Ukloni komentare iz produkcije.');
                break;
            }
        }
        $gen = $x->query('//meta[@name="generator"]')->item(0);
        if ($gen) $this->add('info', 'Meta generator otkriva CMS/verziju', $gen->getAttribute('content'));
    }

    private function sourceLeak(string $body): void
    {
        if (preg_match('/<\?php|<\?=\s/', $body)) {
            $this->add('critical', 'Server vraća PHP izvorni kod (PHP se ne izvršava)', 'Odgovor sadrži <?php.', 'Proveri konfiguraciju PHP handler-a na serveru.');
            foreach (CodeAnalyzer::analyze($body) as $f) { $f['title'] = '[izloženi kod] ' . $f['title']; $this->f[] = $f; }
        }
    }

    private function listing(string $body): void
    {
        if (preg_match('/<title>Index of \/|<h1>Index of \//i', $body)) $this->add('medium', 'Uključen directory listing', '', 'Options -Indexes (Apache) / autoindex off (nginx).');
    }

    /** Bezopasne probe: marker reflektovanja i izazivanje poruke o grešci (bez ikakvog exploita). */
    private function probes(string $url): void
    {
        $sep = str_contains($url, '?') ? '&' : '?';
        $mark = 'sc' . bin2hex(random_bytes(4));
        $r = $this->http($url . $sep . '__sc=' . rawurlencode($mark . '"\'<>'));
        if (str_contains($r['body'], $mark . '"\'<>') || str_contains($r['body'], $mark . '<')) {
            $this->add('high', 'Unos se reflektuje bez enkodovanja (potencijalni XSS)', 'Specijalni znakovi < > " \' vraćeni su neizmenjeni.', 'htmlspecialchars() pri svakom ispisu + CSP.');
        } elseif (str_contains($r['body'], $mark)) {
            $this->add('info', 'Parametar se reflektuje u odgovoru (enkodovan)', 'Proveri ručno različite kontekste (atribut, JS, URL).');
        }
        $this->errors($r['body']);
        $r2 = $this->http($url . $sep . '__sc[]=1&id=%27');
        $this->errors($r2['body']);
    }

    private array $errSeen = [];
    private function errors(string $b): void
    {
        $tests = [
            'php'   => ['~(?:Warning|Notice|Fatal error|Parse error|Deprecated):.{0,200}? in .{0,200}? on line \d+~is', 'high', 'Prikazuju se PHP greške (curi putanja i kod)', 'display_errors=Off, log_errors=On'],
            'trace' => ['~Stack trace:|#0 .*\.php\(\d+\)~i', 'high', 'Prikazuje se stack trace', 'Isključi debug režim.'],
            'sql'   => ['~You have an error in your SQL syntax|SQLSTATE\[|mysqli?_\w+\(\)|ORA-\d{5}|PG::\w+|unterminated quoted string~i', 'high', 'Prikazuju se SQL greške (indikator SQL Injection ranjivosti)', 'Prepared statements + sakrij greške.'],
        ];
        foreach ($tests as $k => [$re, $sev, $title, $fix]) {
            if (!isset($this->errSeen[$k]) && preg_match($re, $b, $m)) {
                $this->errSeen[$k] = true;
                $this->add($sev, $title, mb_substr(trim(strip_tags($m[0])), 0, 140), $fix);
            }
        }
    }

    private function sensitiveFiles(string $origin): void
    {
        foreach (self::FILES as $path => [$re, $sev, $title]) {
            $r = $this->http($origin . $path);
            if ($r['code'] === 200 && preg_match($re, $r['body'])) {
                $this->add($sev, $title, $origin . $path, 'Obriši fajl ili blokiraj pristup na nivou web servera.');
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/*  Kontroler                                                          */
/* ------------------------------------------------------------------ */
if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32));
$results = [];
$error = '';
$urlsIn = '';
$codeIn = '';

function scoreOf(array $findings): int
{
    $s = 100;
    foreach ($findings as $f) $s -= SEV_WEIGHT[$f['sev']];
    return max(0, $s);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $urlsIn = (string)($_POST['urls'] ?? '');
    $codeIn = (string)($_POST['code'] ?? '');
    if (!hash_equals($_SESSION['csrf'], (string)($_POST['csrf'] ?? ''))) {
        $error = 'Nevažeći CSRF token.';
    } elseif (time() - ($_SESSION['last'] ?? 0) < 5) {
        $error = 'Sačekaj nekoliko sekundi između skeniranja.';
    } else {
        $_SESSION['last'] = time();
        $urls = array_values(array_unique(array_filter(array_map('trim', preg_split('/\R/', $urlsIn)))));
        if (count($urls) > 5) $urls = array_slice($urls, 0, 5);
        if ($urls && empty($_POST['confirm'])) {
            $error = 'Moraš potvrditi da si vlasnik sajta ili imaš dozvolu za testiranje.';
        } else {
            set_time_limit(180);
            foreach ($urls as $u) {
                $sc = new Scanner();
                try { $sc->scan($u); $results[] = ['target' => $u, 'f' => $sc->f, 'err' => '']; }
                catch (Throwable $ex) { $results[] = ['target' => $u, 'f' => $sc->f, 'err' => $ex->getMessage()]; }
            }
            if (trim($codeIn) !== '') {
                $results[] = ['target' => 'Zalepljeni PHP kod (statička analiza)', 'f' => CodeAnalyzer::analyze(mb_substr($codeIn, 0, 500000)), 'err' => ''];
            }
            if (!$results) $error = 'Unesi bar jedan URL ili zalepi PHP kod.';
        }
    }
}
?>
<!doctype html>
<html lang="sr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SecCheck – skener bezbednosti</title>
<style>
 :root{--bg:#f6f7f9;--card:#fff;--tx:#1b1f24;--mut:#6b7280;--bd:#e3e6ea}
 @media(prefers-color-scheme:dark){:root{--bg:#0f1216;--card:#181c22;--tx:#e6e8eb;--mut:#9aa3ad;--bd:#2a3038}}
 *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);font:15px/1.5 system-ui,sans-serif}
 main{max-width:900px;margin:0 auto;padding:24px 16px}
 h1{margin:0 0 4px}p.s{color:var(--mut);margin:0 0 20px}
 .card{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:16px;margin-bottom:16px}
 textarea{width:100%;background:transparent;color:inherit;border:1px solid var(--bd);border-radius:8px;padding:10px;font:13px ui-monospace,monospace}
 label{display:block;font-weight:600;margin:10px 0 4px}
 button{background:#2563eb;color:#fff;border:0;border-radius:8px;padding:10px 18px;font-size:15px;cursor:pointer}
 .err{background:#fee2e2;color:#991b1b;border-radius:8px;padding:10px 14px;margin-bottom:16px}
 .f{border-left:4px solid;padding:8px 12px;margin:10px 0;background:rgba(127,127,127,.06);border-radius:0 8px 8px 0}
 .f small{display:block;color:var(--mut);word-break:break-word}
 .b{font-size:11px;font-weight:700;padding:2px 7px;border-radius:99px;color:#fff;margin-right:6px}
 .critical{border-color:#b91c1c}.critical .b{background:#b91c1c}.high{border-color:#ea580c}.high .b{background:#ea580c}
 .medium{border-color:#d97706}.medium .b{background:#d97706}.low{border-color:#2563eb}.low .b{background:#2563eb}
 .info{border-color:#6b7280}.info .b{background:#6b7280}
 .score{font-size:28px;font-weight:700}
</style>
</head>
<body><main>
<h1>🛡️ SecCheck</h1>
<p class="s">Neagresivni skener bezbednosti PHP sajtova + statička analiza PHP koda. Koristi samo na svojim sajtovima.</p>

<?php if ($error): ?><div class="err"><?= e($error) ?></div><?php endif; ?>

<form method="post" class="card">
  <input type="hidden" name="csrf" value="<?= e($_SESSION['csrf']) ?>">
  <label for="urls">Linkovi za proveru (jedan po liniji, max 5)</label>
  <textarea id="urls" name="urls" rows="4" placeholder="https://moj-sajt.rs/&#10;https://moj-sajt.rs/login.php"><?= e($urlsIn) ?></textarea>
  <label for="code">…ili zalepi PHP kod za statičku analizu</label>
  <textarea id="code" name="code" rows="8" placeholder="<?php echo $_GET['x']; ?>"><?= e($codeIn) ?></textarea>
  <label style="font-weight:400;margin-top:12px"><input type="checkbox" name="confirm" value="1"> Potvrđujem da sam vlasnik ovih sajtova ili imam izričitu dozvolu da ih testiram.</label>
  <p><button type="submit">Pokreni proveru</button></p>
</form>

<?php foreach ($results as $r):
    usort($r['f'], fn($a, $b) => SEV_ORDER[$a['sev']] <=> SEV_ORDER[$b['sev']]);
    $score = scoreOf($r['f']); ?>
  <section class="card">
    <h2 style="margin-top:0;word-break:break-all"><?= e($r['target']) ?></h2>
    <?php if ($r['err']): ?><div class="err"><?= e($r['err']) ?></div><?php endif; ?>
    <div class="score">Ocena: <?= $score ?>/100</div>
    <?php if (!$r['f'] && !$r['err']): ?><p>Nisu pronađeni problemi u okviru ovih provera.</p><?php endif; ?>
    <?php foreach ($r['f'] as $f): ?>
      <div class="f <?= e($f['sev']) ?>">
        <span class="b"><?= e(SEV_LABEL[$f['sev']]) ?></span><strong><?= e($f['title']) ?></strong>
        <?php if ($f['detail']): ?><small><?= e($f['detail']) ?></small><?php endif; ?>
        <?php if ($f['fix']): ?><small>✔ Popravka: <?= e($f['fix']) ?></small><?php endif; ?>
      </div>
    <?php endforeach; ?>
  </section>
<?php endforeach; ?>

<p class="s">Napomena: automatski skener ne može pronaći sve ranjivosti (logičke greške, autorizacija, složeni SQLi/XSS). Za kritične sisteme uradi i ručni pentest / code review.</p>
</main></body></html>
