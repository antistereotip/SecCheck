<?php
declare(strict_types=1);
/**
 * SecCheck v3 – skener bezbednosti PHP sajtova, baza podataka i JavaScript fajlova (čist PHP, bez spoljnog JS-a)
 *
 *  1) URL skener (neagresivne provere): TLS, headeri, kolačići/sesije, CORS, HTTP metode, curenje informacija,
 *     PHP-specifične provere (expose_php, EOL verzije, PHPSESSID u URL-u, Laravel/Symfony/WordPress/phpunit tragovi),
 *     izložene osetljive datoteke uključujući baze podataka (.sql, .sqlite, database.yml, konekcioni fajlovi,
 *     Adminer/phpMyAdmin), greške iz MySQL/PostgreSQL/MSSQL/SQLite/MongoDB, GraphQL introspekcija (pasivno),
 *     forme bez CSRF tokena, mixed content, reflektovanje unosa.
 *  2) Statička analiza PHP koda (zalepljen kod ili otpremljeni fajlovi): ~50 pravila + heuristika praćenja
 *     „zaprljanih" promenljivih ($id = $_GET['id'] → kasnije u SQL upitu).
 *  3) Analiza JavaScript fajlova sa stranice (automatsko otkrivanje istog porekla): hardkodovani API ključevi/tajne,
 *     eval/new Function, DOM-based XSS obrasci, postMessage bez provere origin-a, tokeni u localStorage,
 *     izložene source mape, zastarele ranjive biblioteke (jQuery/AngularJS).
 *
 *  NAPOMENA: skener NE šalje prave napadačke payload-e (SQLi, XSS eksploati, brute force) – samo pasivne provere
 *  i neutralne test-markere. Aktivno iskorišćavanje ranjivosti (npr. izvlačenje podataka iz baze) nije podržano
 *  jer bi se takav alat mogao koristiti za napad na tuđe sajtove.
 *  3) Pregledan izveštaj: ocena, prioriteti, grupisanje po kategorijama, filter po ozbiljnosti (čist CSS),
 *     izvoz u HTML / TXT / JSON.
 *
 * Koristi ISKLJUČIVO na sajtovima koje poseduješ ili imaš dozvolu da testiraš.
 * Zahteva PHP 8.0+ (cURL, DOM, OpenSSL).
 */

if (!function_exists('mb_substr')) { // rezerva ako mbstring nije instaliran
    function mb_substr(string $s, int $start, ?int $len = null, ?string $enc = null): string
    {
        if ($len !== null) $s = substr($s, 0, ($start + $len) * 4); // najviše 4 bajta po UTF-8 znaku
        $chars = @preg_split('//u', $s, -1, PREG_SPLIT_NO_EMPTY);
        return $chars === false ? substr($s, $start, $len) : implode('', array_slice($chars, $start, $len));
    }
}

session_start();
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');

const SEV_ORDER  = ['critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3, 'info' => 4];
const SEV_WEIGHT = ['critical' => 25, 'high' => 15, 'medium' => 7, 'low' => 3, 'info' => 0];
const SEV_LABEL  = ['critical' => 'KRITIČNO', 'high' => 'VISOKO', 'medium' => 'SREDNJE', 'low' => 'NISKO', 'info' => 'INFO'];

function e(string $s): string { return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
/** Escapuje tekst, a `kod` u backtick-ovima pretvara u <code>. */
function fmt(string $s): string { return preg_replace('/`([^`]+)`/', '<code>$1</code>', e($s)); }

function summarize(array $findings): array
{
    $c = array_fill_keys(array_keys(SEV_ORDER), 0);
    foreach ($findings as $f) $c[$f['sev']]++;
    $score = 100;
    foreach ($c as $sev => $n) $score -= min($n, 5) * SEV_WEIGHT[$sev];
    $score = max(0, $score);
    $grade = $score >= 90 ? 'A' : ($score >= 75 ? 'B' : ($score >= 60 ? 'C' : ($score >= 40 ? 'D' : 'F')));
    if ($c['critical'] > 0 && in_array($grade, ['A', 'B', 'C'], true)) $grade = 'D';
    return ['count' => $c, 'score' => $score, 'grade' => $grade];
}

/* ================================================================== */
/*  Statička analiza PHP koda                                          */
/* ================================================================== */
final class CodeAnalyzer
{
    private const SANITIZER = '~intval|\(int\)|\(float\)|\(bool\)|filter_var|htmlspecialchars|htmlentities|basename|ctype_|is_numeric|strip_tags|escapeshellarg|urlencode|rawurlencode|md5\(|sha1\(|hash\(|password_hash|count\(~i';

    /** Promenljive u koje se upisuje sirov korisnički unos ($id = $_GET['id']). */
    private static function taintedVars(array $lines): array
    {
        $vars = [];
        foreach ($lines as $l) {
            if (preg_match('~^\s*(\$\w+)\s*=(?!=)[^;]*\$_(?:GET|POST|REQUEST|COOKIE)\b~', $l, $m) && !preg_match(self::SANITIZER, $l)) {
                $vars[$m[1]] = true;
            }
        }
        return array_slice(array_keys($vars), 0, 50);
    }

    private static function rules(string $in): array
    {
        $r = static fn(string $re, string $sev, string $cat, string $title, string $why, string $fix, string $cwe, ?string $unless = null): array
            => ['re' => $re, 'sev' => $sev, 'cat' => $cat, 'title' => $title, 'why' => $why, 'fix' => $fix, 'cwe' => $cwe, 'unless' => $unless];
        $INJ = 'Injekcije i izvršavanje koda';
        $XSS = 'XSS (ispis podataka)';
        $FIL = 'Fajlovi i upload';
        $CRY = 'Lozinke i kriptografija';
        $CFG = 'Konfiguracija i greške';
        $NET = 'Mreža (SSRF / redirect)';
        $LOG = 'Logičke greške i tipovi';

        return [
            $r('~\beval\s*\(~i', 'critical', $INJ, 'eval() izvršava proizvoljan kod', 'Ako deo stringa potiče od korisnika, napadač preuzima server (RCE).', 'Ukloni `eval()`; zameni običnom logikom, mapom funkcija ili šablonima.', 'CWE-95'),
            $r('~\bcreate_function\s*\(~i', 'high', $INJ, 'create_function() (uklonjena iz PHP 8)', 'Interno radi kao eval() i omogućava izvršavanje koda.', 'Koristi anonimne funkcije: `fn($x) => ...`.', 'CWE-95'),
            $r('~\bassert\s*\(\s*\$~i', 'high', $INJ, 'assert() sa promenljivom', 'U starijim verzijama PHP-a string u assert() se izvršava kao kod.', 'Ne koristi assert() za logiku aplikacije.', 'CWE-95'),
            $r('~\b(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(~i', 'high', $INJ, 'Izvršavanje sistemskih komandi', 'Ako komanda sadrži korisnički unos, napadač izvršava komande na serveru (command injection).', 'Izbegavaj; ako mora, `escapeshellarg()` na svaki argument i whitelist dozvoljenih komandi.', 'CWE-78'),
            $r('~`[^`\n]*\$\w+[^`\n]*`~', 'high', $INJ, 'Backtick operator sa promenljivom', 'Backtick je skriveni shell_exec().', 'Zameni bezbednom PHP funkcijom ili `escapeshellarg()`.', 'CWE-78'),
            $r('~\bunserialize\s*\([^;]*' . $in . '~i', 'critical', $INJ, 'unserialize() nad korisničkim unosom', 'PHP Object Injection – napadač kreira objekte i preko „magic" metoda dolazi do RCE-a.', 'Koristi `json_decode()`. Ako moraš: `unserialize($s, ["allowed_classes" => false])`.', 'CWE-502'),
            $r('~\bunserialize\s*\(~i', 'medium', $INJ, 'unserialize() – proveri poreklo podataka', 'Deserijalizacija nepouzdanih podataka je čest put do RCE-a.', 'Koristi JSON ili `allowed_classes => false`.', 'CWE-502'),
            $r('~\b(?:include|require)(?:_once)?\b[^;]*' . $in . '~i', 'critical', $INJ, 'include/require sa korisničkim unosom (LFI/RFI)', 'Napadač učitava proizvoljne lokalne (ili udaljene) fajlove i izvršava ih.', 'Whitelist: `$allowed = ["home","about"]; in_array($p, $allowed, true)`.', 'CWE-98'),
            $r('~(?:mysqli?_query|->query|->exec|pg_query|sqlite_query)\s*\([^;]*' . $in . '~i', 'critical', $INJ, 'Korisnički unos direktno u SQL upitu', 'SQL Injection – krađa, izmena i brisanje podataka, ponekad i preuzimanje servera.', 'Prepared statements: `$st = $pdo->prepare("... WHERE id = ?"); $st->execute([$id]);`', 'CWE-89'),
            $r('~[\x22\x27]\s*(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^;]*?\$\w+~i', 'high', $INJ, 'SQL upit sa ubačenom promenljivom', 'Konkatenacija ili interpolacija u SQL-u je najčešći uzrok SQL Injection-a.', 'Koristi parametrizovane upite (PDO/mysqli prepared statements).', 'CWE-89'),
            $r('~\bextract\s*\(\s*' . $in . '~i', 'high', $INJ, 'extract() nad korisničkim unosom', 'Napadač prepisuje bilo koju promenljivu (npr. `$isAdmin`).', 'Čitaj samo očekivana polja: `$name = $_POST["name"] ?? ""`.', 'CWE-621'),
            $r('~' . $in . '\s*\[[^\]]*\]\s*\(~', 'critical', $INJ, 'Korisnički unos se poziva kao funkcija', 'Napadač bira koja će se funkcija izvršiti.', 'Mapa dozvoljenih akcija: `$actions[$name] ?? null`.', 'CWE-95'),
            $r('~\b(?:call_user_func(?:_array)?|array_map|usort|array_filter)\s*\(\s*' . $in . '~i', 'high', $INJ, 'Callback dolazi iz korisničkog unosa', 'Izvršavanje proizvoljne funkcije (npr. `system`).', 'Whitelist dozvoljenih callback-ova.', 'CWE-95'),
            $r('~preg_replace\s*\(\s*[\x22\x27]/[^\x22\x27]*/[a-z]*e[a-z]*[\x22\x27]~i', 'high', $INJ, 'preg_replace sa /e modifikatorom', '/e izvršava zamenu kao PHP kod.', 'Koristi `preg_replace_callback()`.', 'CWE-95'),
            $r('~\bpreg_(?:match|match_all|replace|split)\s*\(\s*' . $in . '~i', 'medium', $INJ, 'Regularni izraz iz korisničkog unosa', 'Moguć ReDoS (zakucavanje CPU-a) i greške u obradi.', 'Ne dozvoli korisniku da zadaje pattern; koristi `preg_quote()`.', 'CWE-1333'),
            $r('~\b(?:echo|print)\b[^;]*' . $in . '|<\?=[^?]*' . $in . '~i', 'high', $XSS, 'Ispis korisničkog unosa bez enkodovanja', 'Cross-Site Scripting – napadač ubacuje JavaScript koji krade sesije i radi u ime korisnika.', 'Uvek: `htmlspecialchars($x, ENT_QUOTES | ENT_SUBSTITUTE, "UTF-8")`.', 'CWE-79',
                '~htmlspecialchars|htmlentities|intval|\(int\)|filter_var|json_encode~i'),
            $r('~(?:echo|print|action\s*=|<\?=)[^;]*\$_SERVER\s*\[\s*[\x22\x27](?:PHP_SELF|REQUEST_URI|QUERY_STRING|HTTP_REFERER)[\x22\x27]~i', 'medium', $XSS, '$_SERVER["PHP_SELF"] / REQUEST_URI u izlazu', 'Ove vrednosti kontroliše napadač (XSS preko URL-a).', 'Enkoduj sa `htmlspecialchars()` ili koristi `action=""`.', 'CWE-79',
                '~htmlspecialchars|htmlentities~i'),
            $r('~\b(?:file_get_contents|file_put_contents|fopen|readfile|file|copy|unlink|rename|mkdir|rmdir)\s*\([^;]*' . $in . '~i', 'high', $FIL, 'Rad sa fajlovima nad korisničkim unosom', 'Path traversal (`../../etc/passwd`), brisanje fajlova, upis web shell-a ili SSRF preko URL-a.', 'Validiraj: `realpath()` + provera da je u dozvoljenom direktorijumu; `basename()`.', 'CWE-22'),
            $r('~\bmove_uploaded_file\s*\(~i', 'medium', $FIL, 'Upload fajlova – proveri validaciju', 'Neprovereni upload omogućava otpremanje web shell-a (.php).', 'Whitelist ekstenzija, provera `finfo`, nasumično ime, čuvanje van web root-a.', 'CWE-434'),
            $r('~\$_FILES\s*\[[^\]]+\]\s*\[\s*[\x22\x27]type[\x22\x27]\s*\]~', 'medium', $FIL, 'Poverenje u $_FILES[...]["type"]', 'MIME tip šalje klijent – napadač ga lako lažira.', 'Koristi `finfo_file()` na stvarnom sadržaju.', 'CWE-434'),
            $r('~\bchmod\s*\([^;]*0?777~', 'medium', $FIL, 'chmod 0777', 'Svako na serveru može menjati fajl.', 'Koristi 0644 (fajlovi) / 0755 (direktorijumi).', 'CWE-732'),
            $r('~header\s*\(\s*[\x22\x27]Location:[^;]*' . $in . '~i', 'medium', $NET, 'Open redirect', 'Napadač koristi vaš domen za phishing preusmeravanja.', 'Redirektuj samo na whitelist putanja/domena.', 'CWE-601'),
            $r('~\bcurl_init\s*\(\s*' . $in . '|CURLOPT_URL[^;]*' . $in . '~i', 'high', $NET, 'cURL na URL iz korisničkog unosa (SSRF)', 'Napadač tera server da pristupa internoj mreži i cloud metadata servisima.', 'Whitelist domena, blokiraj privatne IP opsege, ne prati redirekte.', 'CWE-918'),
            $r('~\bmail\s*\([^;]*' . $in . '~i', 'medium', $NET, 'Korisnički unos u mail()', 'Header injection – slanje spama preko vašeg servera.', 'Ukloni `\\r` i `\\n`; koristi PHPMailer/Symfony Mailer.', 'CWE-93'),
            $r('~header\s*\(\s*[\x22\x27]Access-Control-Allow-Origin:\s*\*~i', 'low', $NET, 'CORS: dozvoljen svaki origin (*)', 'Bilo koji sajt može čitati odgovore (ako nisu javni, curi sadržaj).', 'Vrati samo origin sa liste poverenih.', 'CWE-942'),
            $r('~\bsession_id\s*\([^)]*' . $in . '~i', 'high', $CRY, 'Session ID iz korisničkog unosa', 'Session fixation – napadač nameće poznat ID žrtvi.', 'Nikad ne postavljaj `session_id()` iz zahteva; posle prijave `session_regenerate_id(true)`.', 'CWE-384'),
            $r('~CURLOPT_SSL_VERIFY(?:PEER|HOST)\s*,\s*(?:false|0)~i', 'high', $CRY, 'Isključena provera TLS sertifikata', 'Moguć man-in-the-middle napad.', 'Ostavi `CURLOPT_SSL_VERIFYPEER = true`.', 'CWE-295'),
            $r('~(?:password|passwd|pwd|secret|api_?key|token)[\x22\x27]?\s*(?:=>|=)\s*[\x22\x27][^\x22\x27$]{4,}[\x22\x27]~i', 'medium', $CRY, 'Hardkodovani kredencijali / ključevi', 'Svako ko vidi kod (repo, backup) vidi i lozinku.', 'Prebaci u promenljive okruženja (`getenv()`) i van repozitorijuma.', 'CWE-798'),
            $r('~\b(?:md5|sha1|crypt)\s*\(~i', 'low', $CRY, 'Slab hash algoritam', 'MD5/SHA1 se za lozinke razbijaju za sekunde.', '`password_hash($p, PASSWORD_DEFAULT)` i `password_verify()`.', 'CWE-328'),
            $r('~\b(?:rand|mt_rand|uniqid|lcg_value)\s*\(~i', 'low', $CRY, 'Nesiguran generator slučajnih brojeva', 'Predvidivi tokeni (reset lozinke, CSRF) mogu se pogoditi.', '`bin2hex(random_bytes(32))` ili `random_int()`.', 'CWE-338'),
            $r('~\b(?:md5|sha1|crc32|hash)\s*\([^;]*\)\s*[!=]=(?!=)~i', 'medium', $LOG, 'Labavo poređenje hash-eva (== umesto ===)', 'Type juggling: "0e123..." == "0e456..." je true – zaobilaženje provere.', 'Koristi `hash_equals()` ili `===`.', 'CWE-697'),
            $r('~\bin_array\s*\([^;]*' . $in . '[^;]*\)~i', 'low', $LOG, 'in_array() bez strict parametra', 'Labavo poređenje može dati lažno pozitivan rezultat.', '`in_array($x, $list, true)`.', 'CWE-697', '~,\s*true\s*\)~i'),
            $r('~\bparse_str\s*\(\s*[^,;]+\)\s*;~i', 'medium', $LOG, 'parse_str() bez drugog argumenta', 'Upisuje promenljive u trenutni scope (prepisivanje).', '`parse_str($s, $out);`', 'CWE-621'),
            $r('~\$\$\w+~', 'medium', $LOG, 'Promenljive promenljivih ($$var)', 'Ako ime potiče od korisnika, napadač prepisuje proizvoljne promenljive.', 'Koristi asocijativne nizove.', 'CWE-914'),
            $r('~\b(?:echo|print|die|exit)\b[^;]*(?:mysqli?_error|->getMessage\s*\(|getTraceAsString|->errorInfo|->error\b)~i', 'medium', $CFG, 'Greška baze/izuzetka se ispisuje korisniku', 'Otkriva strukturu baze i putanje – olakšava SQL Injection.', 'Loguj sa `error_log()`, korisniku prikaži opštu poruku.', 'CWE-209'),
            $r('~\bphpinfo\s*\(~i', 'medium', $CFG, 'phpinfo() u kodu', 'Otkriva verzije, putanje, ekstenzije i promenljive okruženja.', 'Ukloni iz produkcije.', 'CWE-200'),
            $r('~ini_set\s*\(\s*[\x22\x27]display_errors[\x22\x27]\s*,\s*[\x22\x27]?(?:1|on|true)~i', 'low', $CFG, 'Uključen display_errors', 'Greške otkrivaju putanje i delove koda.', 'Produkcija: `display_errors=0`, `log_errors=1`.', 'CWE-209'),
            $r('~ini_set\s*\(\s*[\x22\x27]allow_url_(?:include|fopen)[\x22\x27]~i', 'high', $CFG, 'allow_url_include/fopen se uključuje u kodu', 'Omogućava udaljeno izvršavanje preko include.', 'Ostavi isključeno.', 'CWE-98'),
            $r('~\berror_reporting\s*\(\s*0\s*\)|@\s*(?:mysqli?_\w+|include|require|file_get_contents|fopen|unlink)\b~i', 'low', $CFG, 'Potiskivanje grešaka (@ / error_reporting(0))', 'Greške ostaju neprimećene, sigurnosni problemi se kriju.', 'Obrađuj greške izuzecima i loguj ih.', 'CWE-390'),
            $r('~\bsetcookie\s*\(~i', 'low', $CFG, 'setcookie() – proveri HttpOnly/Secure/SameSite', 'Kolačić bez zastavica može biti ukraden preko XSS-a ili poslat preko HTTP-a.', '`setcookie($n, $v, ["httponly"=>true,"secure"=>true,"samesite"=>"Lax"])`.', 'CWE-1004', '~httponly~i'),
            $r('~\bmysql_\w+\s*\(~i', 'medium', $CFG, 'Zastarele mysql_* funkcije', 'Uklonjene iz PHP 7; oslanjaju se na ručno escapovanje.', 'Pređi na PDO/mysqli sa prepared statements.', 'CWE-1104'),
            $r('~\b(?:loadXML|simplexml_load_(?:string|file))\s*\(~i', 'low', $INJ, 'Parsiranje XML-a – proveri XXE', 'XXE čita lokalne fajlove ili pravi SSRF.', 'Ne koristi `LIBXML_NOENT`; dodaj `LIBXML_NONET`.', 'CWE-611'),
            $r('~\b(?:base64_decode|gzinflate|str_rot13|gzuncompress)\s*\(~i', 'low', $INJ, 'Dekodiranje/obfuskacija – proveri da nije web shell', 'Zlonamerne skripte sakrivaju kod kodiranjem.', 'Pregledaj šta se dekodira i gde se izvršava.', 'CWE-506'),
        ];
    }

    public static function analyze(string $code): array
    {
        $lines = preg_split('/\R/', $code);
        $tainted = self::taintedVars($lines);
        $in = '(?:\$_(?:GET|POST|REQUEST|COOKIE)';
        if ($tainted) $in .= '|(?:' . implode('|', array_map(static fn($v) => preg_quote($v, '~'), $tainted)) . ')\b';
        $in .= ')';
        $rules = self::rules($in);

        $hits = [];
        $inBlock = false;
        foreach ($lines as $i => $line) {
            $t = ltrim($line);
            if ($inBlock) { if (str_contains($line, '*/')) $inBlock = false; continue; }
            if (str_starts_with($t, '/*')) { if (!str_contains($line, '*/')) $inBlock = true; continue; }
            if ($t === '' || str_starts_with($t, '//') || str_starts_with($t, '#') || str_starts_with($t, '*')) continue;
            foreach ($rules as $ri => $r) {
                if (preg_match($r['re'], $line) && !($r['unless'] && preg_match($r['unless'], $line))) {
                    $ctx = [];
                    for ($k = max(0, $i - 1); $k <= min(count($lines) - 1, $i + 1); $k++) $ctx[] = [$k + 1, mb_substr(rtrim($lines[$k]), 0, 160)];
                    $hits[$ri][] = ['n' => $i + 1, 'ctx' => $ctx];
                }
            }
        }
        $out = [];
        foreach ($hits as $ri => $list) {
            $r = $rules[$ri];
            $out[] = ['sev' => $r['sev'], 'cat' => $r['cat'], 'title' => $r['title'], 'detail' => 'Broj pogodaka: ' . count($list) . ' (linije: ' . implode(', ', array_slice(array_column($list, 'n'), 0, 12)) . (count($list) > 12 ? ', …' : '') . ')',
                'why' => $r['why'], 'fix' => $r['fix'], 'cwe' => $r['cwe'], 'hits' => array_slice($list, 0, 4)];
        }
        $meta = count($lines) . ' linija' . ($tainted ? ', praćene promenljive iz unosa: ' . implode(' ', array_slice($tainted, 0, 8)) : '');
        return ['f' => $out, 'meta' => $meta];
    }
}

/* ================================================================== */
/*  Analiza JavaScript fajlova                                         */
/* ================================================================== */
final class JsAnalyzer
{
    private static function rules(): array
    {
        $r = static fn(string $re, string $sev, string $title, string $why, string $fix, ?string $unless = null): array
            => ['re' => $re, 'sev' => $sev, 'title' => $title, 'why' => $why, 'fix' => $fix, 'unless' => $unless];
        return [
            $r('~\b(?:AKIA|ASIA)[0-9A-Z]{16}\b~', 'critical', 'AWS pristupni ključ u JS fajlu', 'Napadač dobija direktan pristup vašem AWS nalogu.', 'Ukloni ključ, poništi ga u AWS konzoli i premesti pozive na backend.'),
            $r('~\bAIza[0-9A-Za-z_-]{35}\b~', 'high', 'Google API ključ u JS fajlu', 'Ključ se može zloupotrebiti (naplata, kvote, pristup API-ju).', 'Ograniči ključ po domenu/API-ju u Google Console ili ga premesti na backend.'),
            $r('~\bsk_live_[0-9a-zA-Z]{24,}\b~', 'critical', 'Stripe LIVE tajni ključ u JS fajlu', 'Omogućava direktne finansijske transakcije u ime naloga.', 'Odmah poništi ključ u Stripe panelu; tajni ključevi idu samo na server.'),
            $r('~\bghp_[0-9a-zA-Z]{36}\b~', 'critical', 'GitHub token u JS fajlu', 'Pristup repozitorijumima i mogućim tajnama u njima.', 'Poništi token na GitHub-u i premesti logiku na backend.'),
            $r('~\bxox[baprs]-[0-9a-zA-Z-]{10,}\b~', 'high', 'Slack token u JS fajlu', 'Pristup Slack radnom prostoru.', 'Poništi token u Slack App Management.'),
            $r('~\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}~', 'medium', 'JWT token hardkodovan u JS fajlu', 'Ako je validan, napadač ga može koristiti za predstavljanje korisnika.', 'Ukloni iz koda; tokeni se izdaju dinamički po korisniku.'),
            $r('~(?:password|passwd|secret|api[_-]?key|access[_-]?token|private[_-]?key)["\']?\s*[:=]\s*["\'][^"\']{6,}["\']~i', 'medium', 'Mogući hardkodovani kredencijal u JS fajlu', 'Svako ko otvori JS fajl u browseru vidi ovu vrednost.', 'Premesti tajne na backend; frontend ne sme sadržati kredencijale.'),
            $r('~\beval\s*\(~', 'high', 'eval() u JavaScript kodu', 'Ako sadržaj dolazi iz mreže ili URL-a, napadač izvršava proizvoljan kod (XSS).', 'Zameni sa JSON.parse() ili drugom bezbednom alternativom.'),
            $r('~\bnew\s+Function\s*\(~', 'medium', 'new Function() – izvršavanje koda iz stringa', 'Slično eval()-u, rizik od izvršavanja proizvoljnog koda.', 'Izbegavaj dinamičko generisanje funkcija iz stringova.'),
            $r('~document\.write\s*\([^)]*(?:location|document\.URL|document\.referrer)~i', 'high', 'document.write() sa URL/referrer vrednošću', 'Klasičan DOM-based XSS: napadač kontroliše sadržaj kroz URL.', 'Koristi textContent ili enkoduj vrednost pre upisa.'),
            $r('~\.innerHTML\s*=[^=][^;]*(?:location\.(?:href|search|hash)|document\.URL|document\.referrer|getParameter)~i', 'high', 'innerHTML se postavlja iz URL-a (DOM XSS)', 'Napadač ubacuje HTML/JS kroz parametre linka, izvršava se u browseru žrtve.', 'Koristi textContent ili enkoduj (npr. DOMPurify) pre upisa u innerHTML.'),
            $r('~\.innerHTML\s*=[^=]~', 'low', 'Dodela innerHTML – proveri izvor podataka', 'Ako sadržaj ikad potiče od korisnika, moguć je XSS.', 'Koristi textContent gde god je moguće, ili sanitizuj HTML.',
                '~location|document\.URL|document\.referrer|getParameter~i'),
            $r('~window\.addEventListener\s*\(\s*["\']message["\']~i', 'medium', 'postMessage listener – proveri da li se validira origin', 'Bez provere event.origin, bilo koja stranica može slati poruke vašoj aplikaciji.', 'Uvek proveri `if (event.origin !== "https://tvoj-sajt.rs") return;` na početku handlera.'),
            $r('~\.postMessage\s*\([^,)]+,\s*["\']\*["\']\s*\)~', 'medium', 'postMessage sa ciljnim origin-om "*"', 'Poruka ide bilo kojoj stranici koja je učitala vaš prozor/iframe.', 'Navedi tačan origin umesto "*".'),
            $r('~localStorage\.setItem\s*\(\s*["\'][^"\']*(?:token|jwt|auth|password)[^"\']*["\']~i', 'medium', 'Token/lozinka se čuva u localStorage', 'localStorage je dostupan svakom JS-u na stranici – XSS odmah krade token.', 'Koristi HttpOnly kolačić za sesijske tokene umesto localStorage.'),
            $r('~Math\.random\s*\(\s*\)[^;]*(?:token|password|secret|session|id\s*=)~i', 'low', 'Math.random() za token/ID', 'Math.random() nije kriptografski siguran i može se predvideti.', 'Koristi `crypto.getRandomValues()`.'),
            $r('~\bdebugger\s*;~', 'low', 'debugger; ostavljen u kodu', 'Nije sigurnosni rizik sam po sebi, ali ukazuje na neočišćen debug kod.', 'Ukloni pre objavljivanja na produkciju.'),
            $r('~console\.(?:log|debug|info)\s*\([^)]*(?:password|token|secret|api[_-]?key)~i', 'low', 'Osetljiva vrednost se ispisuje u console', 'Vidljivo svakom ko otvori konzolu u browseru.', 'Ukloni debug ispise osetljivih podataka.'),
            $r('~//#\s*sourceMappingURL\s*=\s*(\S+\.map)~i', 'info', 'Source map je referenciran (proveriti da li je javno dostupan)', 'Source map otkriva originalni, nesažeti izvorni kod.', 'Ukloni source mape sa produkcije ili ih zaštiti pristupom.'),
            $r('~\bjquery[.-]?(1\.[0-9]|2\.[0-2])\.[0-9]+(?:\.min)?\.js~i', 'medium', 'Zastarela verzija jQuery-ja (poznate XSS ranjivosti)', 'Starije verzije jQuery-ja (pre 3.0) imaju poznate XSS ranjivosti u $() i .html().', 'Nadogradi na jQuery 3.x ili noviji.'),
            $r('~\bangular(?:\.min)?\.js["\'].*1\.[0-5]\.~i', 'medium', 'Zastarela verzija AngularJS-a (1.x, EOL)', 'AngularJS 1.x je u EOL-u i ima poznate ranjivosti (sandbox escape, XSS).', 'Razmotri migraciju na noviji framework.'),
            $r('~crossDomain\s*:\s*true[^}]*withCredentials\s*:\s*true~is', 'medium', 'Cross-domain zahtev sa credentials', 'Šalje kolačiće/kredencijale ka drugom domenu – proveri da li je to namerno.', 'Ograniči na poverene domene.'),
            $r('~XMLHttpRequest\(\)[^;]*\.open\s*\([^,]+,\s*(?:location|document\.URL)~i', 'high', 'AJAX zahtev na URL iz adresne trake (SSRF/open redirect preko klijenta)', 'Napadač menja parametar i preusmerava zahteve na proizvoljnu adresu.', 'Validiraj URL whitelist-om pre korišćenja.'),
        ];
    }

    public static function analyze(string $code, string $label): array
    {
        $lines = preg_split('/\R/', $code);
        $rules = self::rules();
        $hits = [];
        foreach ($lines as $i => $line) {
            $t = ltrim($line);
            if ($t === '' || str_starts_with($t, '//') && !str_contains($t, 'sourceMappingURL')) continue;
            foreach ($rules as $ri => $r) {
                if (preg_match($r['re'], $line) && !($r['unless'] && preg_match($r['unless'], $line))) {
                    $hits[$ri][] = ($i + 1) . ': ' . mb_substr(trim($line), 0, 140);
                }
            }
        }
        $out = [];
        foreach ($hits as $ri => $list) {
            $r = $rules[$ri];
            $out[] = ['sev' => $r['sev'], 'cat' => 'Kritični JavaScript fajlovi', 'title' => "[$label] " . $r['title'],
                'detail' => 'Pogođeno ' . count($list) . '× → ' . implode(' | ', array_slice($list, 0, 4)), 'why' => $r['why'], 'fix' => $r['fix'], 'cwe' => '', 'hits' => []];
        }
        return $out;
    }
}

/* ================================================================== */
/*  URL skener                                                         */
/* ================================================================== */
final class Scanner
{
    public array $f = [];
    public array $ok = [];
    public array $tech = [];
    private bool $verify = true;
    private array $errSeen = [];

    private const C_TLS = 'TLS i HTTPS', C_HDR = 'HTTP sigurnosni headeri', C_COOKIE = 'Kolačići i sesije', C_INFO = 'Curenje informacija',
        C_PHP = 'PHP konfiguracija', C_CORS = 'CORS i HTTP metode', C_HTML = 'Sadržaj stranice', C_FILES = 'Izložene datoteke', C_ERR = 'Greške i obrada unosa';
    private const MAX_BODY = 2097152;
    private const FILE_WHY = 'Fajl je dostupan svima na internetu bez prijave; može otkriti lozinke, strukturu aplikacije ili izvorni kod.';

    /** putanja => [regex potpisa, ozbiljnost, naslov] */
    private const FILES = [
        '/.env'                  => ['~(?:DB_|APP_KEY|SECRET|PASSWORD|API_KEY)\w*\s*=~i', 'critical', '.env fajl je javno dostupan (lozinke i ključevi)'],
        '/.env.local'            => ['~(?:DB_|APP_|SECRET|PASSWORD)\w*\s*=~i', 'critical', '.env.local je javno dostupan'],
        '/.env.production'       => ['~(?:DB_|APP_|SECRET|PASSWORD)\w*\s*=~i', 'critical', '.env.production je javno dostupan'],
        '/.git/HEAD'             => ['~^ref:\s*refs/~', 'critical', '.git repozitorijum je javno dostupan (izvorni kod curi)'],
        '/.git/config'           => ['~\[core\]~', 'critical', '.git/config je javno dostupan'],
        '/.htpasswd'             => ['~^\w+:(?:\$apr1\$|\$2y\$|\{SHA\}|[\w./]{13})~m', 'critical', '.htpasswd je javno dostupan'],
        '/backup.sql'            => ['~CREATE TABLE|INSERT INTO~i', 'critical', 'SQL backup je javno dostupan'],
        '/dump.sql'              => ['~CREATE TABLE|INSERT INTO~i', 'critical', 'SQL dump je javno dostupan'],
        '/database.sql'          => ['~CREATE TABLE|INSERT INTO~i', 'critical', 'SQL fajl baze je javno dostupan'],
        '/config.php.bak'        => ['~<\?php|define\s*\(|DB_PASSWORD~i', 'critical', 'Backup konfiguracije je dostupan'],
        '/config.php~'           => ['~<\?php|define\s*\(|DB_PASSWORD~i', 'critical', 'Editor backup konfiguracije je dostupan'],
        '/wp-config.php.bak'     => ['~DB_PASSWORD|<\?php~i', 'critical', 'Backup wp-config.php je dostupan'],
        '/wp-config.php~'        => ['~DB_PASSWORD|<\?php~i', 'critical', 'Backup wp-config.php je dostupan'],
        '/wp-config.php.old'     => ['~DB_PASSWORD|<\?php~i', 'critical', 'Stari wp-config.php je dostupan'],
        '/_ignition/health-check'=> ['~"can_execute_commands"~', 'high', 'Laravel Ignition debug je izložen (poznate RCE ranjivosti)'],
        '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php' => ['~^\s*$~', 'high', 'phpunit eval-stdin.php je dostupan (CVE-2017-9841, RCE) – potvrdi ručno'],
        '/storage/logs/laravel.log' => ['~(?:local|production)\.(?:ERROR|DEBUG)|Stack trace~', 'high', 'Laravel log je javno dostupan'],
        '/wp-content/debug.log'  => ['~PHP (?:Warning|Fatal|Notice|Deprecated)~', 'high', 'WordPress debug.log je javno dostupan'],
        '/php_errors.log'        => ['~PHP (?:Warning|Fatal|Notice|Parse)~', 'high', 'PHP log grešaka je javno dostupan'],
        '/error_log'             => ['~PHP (?:Warning|Fatal|Notice|Parse)~', 'high', 'error_log je javno dostupan'],
        '/phpinfo.php'           => ['~phpinfo\(\)|PHP Version~i', 'high', 'phpinfo() stranica je javno dostupna'],
        '/info.php'              => ['~phpinfo\(\)|PHP Version~i', 'high', 'info.php (phpinfo) je javno dostupan'],
        '/.user.ini'             => ['~auto_prepend_file|display_errors|memory_limit|upload_max|\w+\s*=~i', 'medium', '.user.ini je javno dostupan'],
        '/php.ini'               => ['~\[PHP\]|display_errors|memory_limit~i', 'medium', 'php.ini je javno dostupan'],
        '/server-status'         => ['~Apache Server Status~i', 'medium', 'Apache server-status je javno dostupan'],
        '/_profiler/'            => ['~Symfony Profiler~i', 'medium', 'Symfony Profiler je javno dostupan'],
        '/adminer.php'           => ['~Adminer~i', 'medium', 'Adminer je javno dostupan'],
        '/phpmyadmin/'           => ['~phpMyAdmin~i', 'medium', 'phpMyAdmin je javno dostupan – ograniči pristup (IP / VPN)'],
        '/wp-json/wp/v2/users'   => ['~"slug"~', 'low', 'WordPress REST API izlistava korisnike (enumeracija)'],
        '/xmlrpc.php'            => ['~XML-RPC server accepts POST requests only~i', 'low', 'WordPress xmlrpc.php je uključen (brute force / DDoS vektor)'],
        '/composer.lock'         => ['~"packages"~', 'low', 'composer.lock otkriva tačne verzije biblioteka'],
        '/composer.json'         => ['~"require"~', 'low', 'composer.json otkriva zavisnosti'],
        '/vendor/composer/installed.json' => ['~"packages"|"name"~', 'low', 'vendor/ direktorijum je dostupan sa weba'],
        '/.DS_Store'             => ['~Bud1~', 'low', '.DS_Store otkriva strukturu direktorijuma'],
        // --- Baze podataka i konekcije ---
        '/backup.sql.gz'         => ['~^\x1f\x8b~', 'critical', 'Kompresovan SQL backup je javno dostupan'],
        '/db.sql'                => ['~CREATE TABLE|INSERT INTO~i', 'critical', 'SQL fajl baze je javno dostupan'],
        '/database.sqlite'       => ['~^SQLite format 3~', 'critical', 'SQLite baza je javno dostupna'],
        '/database.yml'          => ['~adapter:|database:|password:~i', 'critical', 'database.yml (kredencijali baze) je javno dostupan'],
        '/config/database.php'   => ['~<\?php|return \[|DB_|password~i', 'critical', 'config/database.php je javno dostupan'],
        '/db_connect.php'        => ['~<\?php|mysqli_connect|new PDO~i', 'high', 'Fajl za konekciju na bazu je javno dostupan (proveri da li vraća kod)'],
        '/dbtest.php'            => ['~<\?php|connect|Connected~i', 'medium', 'Test-konekcija na bazu je javno dostupna'],
        '/adminer-4.8.1.php'     => ['~Adminer~i', 'medium', 'Adminer (verzionisan fajl) je javno dostupan'],
        '/pma/'                  => ['~phpMyAdmin~i', 'medium', 'phpMyAdmin (alias /pma/) je javno dostupan'],
        '/mysql.php'             => ['~<\?php|mysqli?_~i', 'medium', 'mysql.php skripta je javno dostupna'],
        '/graphql'               => ['~"__schema"|"errors"|"data"~', 'info', 'GraphQL endpoint je prisutan (proveri introspekciju)'],
    ];

    public function add(string $sev, string $cat, string $title, string $detail = '', string $fix = '', string $why = ''): void
    {
        $this->f[] = ['sev' => $sev, 'cat' => $cat, 'title' => $title, 'detail' => $detail, 'why' => $why, 'fix' => $fix, 'cwe' => '', 'hits' => []];
    }
    private function pass(string $cat, string $title): void { $this->ok[] = ['cat' => $cat, 'title' => $title]; }

    /** SSRF zaštita: razrešava domen i odbija privatne/rezervisane IP adrese. */
    public static function resolve(string $host): array
    {
        static $cache = [];
        if (isset($cache[$host])) return $cache[$host];
        $ips = filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ? [$host] : (gethostbynamel($host) ?: []);
        if (!$ips) throw new RuntimeException("Domen se ne može razrešiti: $host");
        foreach ($ips as $ip) {
            if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                throw new RuntimeException("Meta pokazuje na privatnu/rezervisanu adresu ($ip) – blokirano radi zaštite od SSRF-a.");
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
            CURLOPT_RESOLVE        => ["$host:$port:$ip"],
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT        => 10,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_USERAGENT      => 'SecCheck/2.0 (self-audit)',
            CURLOPT_HTTPHEADER     => $hdr,
            CURLOPT_PROTOCOLS      => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_SSL_VERIFYPEER => $this->verify,
            CURLOPT_SSL_VERIFYHOST => $this->verify ? 2 : 0,
            CURLOPT_HEADERFUNCTION => function ($c, $l) use (&$headers) {
                if (str_contains($l, ':')) { [$k, $v] = explode(':', $l, 2); $headers[strtolower(trim($k))][] = trim($v); }
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
        usleep(150000);
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
        else $this->add('high', self::C_TLS, 'Sajt radi preko HTTP-a (bez šifrovanja)', 'Skeniranja adresa počinje sa http://.', 'Uvedi HTTPS (npr. Let\'s Encrypt) i preusmeri sav HTTP saobraćaj na HTTPS.', 'Lozinke, kolačići i podaci se mogu presresti na putu do servera.');

        $r = $this->http($url);
        if (!$r['code']) throw new RuntimeException('Nije moguće učitati stranicu: ' . ($r['err'] ?: 'nema odgovora'));
        $this->tech[] = 'HTTP ' . $r['code'];
        if ($s = self::h($r, 'server')) $this->tech[] = 'Server: ' . $s;

        $this->headers($r, $https);
        $this->cookies($r, $https);
        $this->disclosure($r, $p);
        $this->phpProbes($r, $origin);
        $this->cors($url);
        $this->methods($url);
        $this->html($r['body'], $https, $p['host']);
        $this->jsScan($r['body'], $origin, $p['host']);
        $this->sourceLeak($r['body']);
        $this->graphql($origin);
        if (preg_match('/<title>Index of \/|<h1>Index of \//i', $r['body'])) $this->add('medium', self::C_INFO, 'Uključen directory listing', '', 'Apache: `Options -Indexes`; nginx: `autoindex off;`.', 'Napadač vidi sve fajlove u direktorijumu, uključujući backup-e.');
        else $this->pass(self::C_INFO, 'Directory listing nije uključen');
        $this->inputProbes($url);
        $this->sensitiveFiles($origin);
    }

    private function tls(string $host, int $port): void
    {
        $ctx = stream_context_create(['ssl' => ['capture_peer_cert' => true, 'verify_peer' => true, 'verify_peer_name' => true, 'peer_name' => $host, 'SNI_enabled' => true]]);
        $s = @stream_socket_client('ssl://' . self::resolve($host)[0] . ':' . $port, $en, $es, 8, STREAM_CLIENT_CONNECT, $ctx);
        if (!$s) {
            $this->verify = false;
            $this->add('high', self::C_TLS, 'TLS sertifikat nije validan ili TLS nije dostupan', (string)$es, 'Instaliraj validan sertifikat izdat za tačan domen i kompletan lanac.', 'Browseri prikazuju upozorenje, a veza se može presresti.');
            return;
        }
        $cert = openssl_x509_parse(stream_context_get_params($s)['options']['ssl']['peer_certificate']);
        $days = (int)floor(($cert['validTo_time_t'] - time()) / 86400);
        if ($days < 0) $this->add('high', self::C_TLS, 'TLS sertifikat je istekao', 'Istekao pre ' . abs($days) . ' dana.', 'Obnovi sertifikat i uključi automatsku obnovu.', 'Posetioci dobijaju upozorenje o nebezbednoj vezi.');
        elseif ($days < 14) $this->add('medium', self::C_TLS, 'TLS sertifikat uskoro ističe', "Preostalo dana: $days", 'Uključi automatsku obnovu (certbot timer).', 'Istek sertifikata prekida rad sajta.');
        else $this->pass(self::C_TLS, "TLS sertifikat je validan (još $days dana)");
        $proto = stream_get_meta_data($s)['crypto']['protocol'] ?? '';
        if ($proto && !preg_match('/TLSv1\.[23]/', $proto)) $this->add('high', self::C_TLS, 'Zastareo TLS protokol', $proto, 'Dozvoli samo TLS 1.2 i 1.3.', 'Stariji protokoli imaju poznate slabosti.');
        elseif ($proto) $this->pass(self::C_TLS, "Koristi se $proto");
        fclose($s);
    }

    private function headers(array $r, bool $https): void
    {
        $c = self::C_HDR;
        $csp = self::h($r, 'content-security-policy');
        $csp ? $this->pass($c, 'Content-Security-Policy je postavljen')
             : $this->add('medium', $c, 'Nedostaje Content-Security-Policy', '', "Dodaj npr. `Content-Security-Policy: default-src 'self'`.", 'CSP je druga linija odbrane: čak i kad XSS postoji, browser blokira tuđe skripte.');
        if ($https) {
            $hsts = self::h($r, 'strict-transport-security');
            if (!$hsts) $this->add('medium', $c, 'Nedostaje HSTS', '', '`Strict-Transport-Security: max-age=31536000; includeSubDomains`', 'Bez HSTS-a napadač može da spusti vezu na HTTP (SSL stripping).');
            elseif (preg_match('/max-age=(\d+)/i', $hsts, $m) && (int)$m[1] < 15552000) $this->add('low', $c, 'HSTS max-age je prekratak', $hsts, 'Postavi najmanje 31536000 (godina dana).', 'Kratka zaštita brzo prestaje da važi.');
            else $this->pass($c, 'HSTS je uključen');
        }
        (self::h($r, 'x-frame-options') || preg_match('/frame-ancestors/i', (string)$csp))
            ? $this->pass($c, 'Zaštita od clickjacking-a postoji')
            : $this->add('medium', $c, 'Nema zaštite od clickjacking-a', '', "`X-Frame-Options: DENY` ili CSP `frame-ancestors 'none'`.", 'Napadač može učitati vaš sajt u nevidljiv iframe i navesti korisnika da klikne.');
        strtolower((string)self::h($r, 'x-content-type-options')) === 'nosniff'
            ? $this->pass($c, 'X-Content-Type-Options: nosniff')
            : $this->add('low', $c, 'Nedostaje X-Content-Type-Options: nosniff', '', 'Dodaj `X-Content-Type-Options: nosniff`.', 'Browser može pogrešno protumačiti tip fajla (npr. upload kao skriptu).');
        self::h($r, 'referrer-policy')
            ? $this->pass($c, 'Referrer-Policy je postavljen')
            : $this->add('low', $c, 'Nedostaje Referrer-Policy', '', '`Referrer-Policy: strict-origin-when-cross-origin`', 'Pun URL (sa parametrima) može curiti ka drugim sajtovima.');
        self::h($r, 'permissions-policy') ?: $this->add('info', $c, 'Nedostaje Permissions-Policy', '', 'Isključi nepotrebne browser funkcije (kamera, mikrofon, geolokacija).');
    }

    private function cookies(array $r, bool $https): void
    {
        $bad = 0;
        foreach ($r['h']['set-cookie'] ?? [] as $c) {
            $name = trim(explode('=', $c, 2)[0]);
            $l = strtolower($c);
            $miss = [];
            if (!str_contains($l, 'httponly')) $miss[] = 'HttpOnly';
            if ($https && !str_contains($l, 'secure')) $miss[] = 'Secure';
            if (!str_contains($l, 'samesite')) $miss[] = 'SameSite';
            if ($name === 'PHPSESSID') $this->tech[] = 'PHP sesije (PHPSESSID)';
            if ($miss) {
                $bad++;
                $sev = (preg_match('/sess|auth|token|login/i', $name) && !str_contains($l, 'httponly')) ? 'medium' : 'low';
                $this->add($sev, self::C_COOKIE, "Kolačić „{$name}“ nema zastavice: " . implode(', ', $miss), '', 'U php.ini: `session.cookie_httponly=1`, `session.cookie_secure=1`, `session.cookie_samesite=Lax`.', 'Bez HttpOnly kolačić krade XSS; bez Secure ide i preko HTTP-a; bez SameSite olakšava CSRF.');
            }
        }
        if (!$bad && !empty($r['h']['set-cookie'])) $this->pass(self::C_COOKIE, 'Svi kolačići imaju sigurnosne zastavice');
    }

    private static function phpStatus(int $maj, int $min): ?array
    {
        if ($maj < 8 || ($maj === 8 && $min < 2)) return ['high', 'više nije podržan (EOL) i ne dobija sigurnosne zakrpe'];
        if ($maj === 8 && $min === 2) return ['medium', 'dobija samo sigurnosne zakrpe do 31.12.2026.'];
        return null;
    }

    private function disclosure(array $r, array $p): void
    {
        $c = self::C_INFO;
        $clean = true;
        $srv = self::h($r, 'server');
        if ($srv && preg_match('/\d+\.\d+/', $srv)) { $clean = false; $this->add('low', $c, 'Server otkriva verziju', $srv, 'Apache: `ServerTokens Prod`; nginx: `server_tokens off;`.', 'Napadač lakše bira exploit za tačnu verziju.'); }
        $xp = self::h($r, 'x-powered-by');
        if ($xp) {
            $clean = false;
            $this->add('low', self::C_PHP, 'X-Powered-By otkriva tehnologiju', $xp, 'U php.ini: `expose_php = Off`.', 'Olakšava ciljane napade na poznate ranjivosti.');
            if (preg_match('/PHP\/(\d+)\.(\d+)(?:\.(\d+))?/i', $xp, $m)) {
                $this->tech[] = 'PHP ' . $m[1] . '.' . $m[2] . (isset($m[3]) ? '.' . $m[3] : '');
                if ($st = self::phpStatus((int)$m[1], (int)$m[2])) {
                    $this->add($st[0], self::C_PHP, "PHP {$m[1]}.{$m[2]} {$st[1]}", $xp, 'Nadogradi na podržanu verziju – proveri `php.net/supported-versions.php`.', 'Poznate ranjivosti u starim verzijama ostaju nezakrpljene.');
                } else $this->pass(self::C_PHP, "PHP {$m[1]}.{$m[2]} je podržana verzija");
            }
        }
        if ($clean) $this->pass($c, 'Server ne otkriva verzije u headerima');
    }

    /** PHP-specifične provere. */
    private function phpProbes(array $r, string $origin): void
    {
        $egg = $this->http($origin . '/?=PHPE9568F36-D428-11d2-A769-00AA001ACF42');
        $ct = (string)(self::h($egg, 'content-type') ?? '');
        if (str_starts_with($ct, 'image/') && (str_starts_with($egg['body'], "\x89PNG") || str_starts_with($egg['body'], 'GIF8'))) {
            $this->tech[] = 'PHP (expose_php=On)';
            $this->add('low', self::C_PHP, 'expose_php je uključen', 'Poseban URL vraća PHP logo.', 'U php.ini: `expose_php = Off`.', 'Potvrđuje napadaču da je u pitanju PHP i otkriva detalje.');
        } else $this->pass(self::C_PHP, 'expose_php nije uključen');

        if (preg_match('~[?&;](?:PHPSESSID|session_id|sid)=[a-z0-9,-]{16,}~i', $r['body'])) {
            $this->add('medium', self::C_COOKIE, 'ID sesije se nalazi u URL-u', 'Pronađen PHPSESSID u linku.', 'U php.ini: `session.use_only_cookies=1`, `session.use_trans_sid=0`.', 'ID u URL-u curi kroz istoriju, logove i Referer header – moguće preuzimanje sesije.');
        }
    }

    private function cors(string $url): void
    {
        $r = $this->http($url, 'GET', ['Origin: https://evil.example']);
        $acao = self::h($r, 'access-control-allow-origin');
        $acac = strtolower((string)self::h($r, 'access-control-allow-credentials')) === 'true';
        if ($acao === 'https://evil.example') {
            $this->add($acac ? 'high' : 'medium', self::C_CORS, 'CORS reflektuje proizvoljan Origin' . ($acac ? ' uz credentials' : ''), "Access-Control-Allow-Origin: $acao", 'Dozvoli samo origin-e sa striktne liste.', $acac ? 'Tuđi sajt može čitati odgovore u ime prijavljenog korisnika.' : 'Tuđi sajt može čitati odgovore ovog URL-a.');
        } elseif ($acao === '*') $this->add('low', self::C_CORS, 'CORS dozvoljava sve origin-e (*)', '', 'Ograniči ako odgovori nisu javni.', 'Bilo koji sajt može čitati odgovore.');
        else $this->pass(self::C_CORS, 'CORS ne dozvoljava tuđe origin-e');
    }

    private function methods(string $url): void
    {
        $r = $this->http($url, 'OPTIONS');
        $allow = strtoupper((string)(self::h($r, 'allow') ?? ''));
        $bad = false;
        foreach (['TRACE', 'PUT', 'DELETE', 'CONNECT'] as $m) {
            if (preg_match('/\b' . $m . '\b/', $allow)) { $bad = true; $this->add('medium', self::C_CORS, "Dozvoljena HTTP metoda $m", "Allow: $allow", 'Onemogući nepotrebne metode na web serveru.', 'Nepotrebne metode povećavaju površinu napada (npr. TRACE za krađu kolačića, PUT za otpremanje fajlova).'); }
        }
        if (!$bad) $this->pass(self::C_CORS, 'Nema opasnih HTTP metoda');
    }

    private function html(string $body, bool $https, string $host): void
    {
        $c = self::C_HTML;
        if (!preg_match('/<html|<form|<body/i', $body)) return;
        libxml_use_internal_errors(true);
        $d = new DOMDocument();
        $d->loadHTML('<?xml encoding="UTF-8">' . $body, LIBXML_NONET);
        $x = new DOMXPath($d);

        $post = 0; $noCsrf = 0;
        foreach ($x->query('//form') as $form) {
            $method = strtolower($form->getAttribute('method') ?: 'get');
            $action = $form->getAttribute('action');
            $hasPass = $x->query('.//input[@type="password"]', $form)->length > 0;
            if ($method === 'post') {
                $post++;
                $csrf = false;
                foreach ($x->query('.//input[@type="hidden"]', $form) as $i) if (preg_match('/csrf|token|nonce|authenticity|xsrf/i', $i->getAttribute('name'))) $csrf = true;
                if (!$csrf) { $noCsrf++; $this->add('medium', $c, 'POST forma bez vidljivog CSRF tokena', 'action="' . mb_substr($action, 0, 80) . '"', 'Generiši token sa `bin2hex(random_bytes(32))`, čuvaj u sesiji i proveri `hash_equals()`-om.', 'Napadač može naterati prijavljenog korisnika da nesvesno pošalje formu (CSRF).'); }
            }
            if ($hasPass && (!$https || str_starts_with(strtolower($action), 'http://'))) $this->add('high', $c, 'Forma sa lozinkom se šalje preko HTTP-a', $action, 'Šalji isključivo preko HTTPS-a.', 'Lozinka putuje nešifrovana.');
            if ($hasPass && $method === 'get') $this->add('high', $c, 'Forma sa lozinkom koristi GET', '', 'Koristi `method="post"`.', 'Lozinka završava u URL-u, istoriji i logovima.');
        }
        if ($post && !$noCsrf) $this->pass($c, 'Sve POST forme imaju CSRF token');

        foreach ($x->query('//script[@src]') as $s) {
            $src = $s->getAttribute('src');
            $h = parse_url($src, PHP_URL_HOST);
            if ($h && strcasecmp($h, $host) !== 0 && !$s->hasAttribute('integrity')) $this->add('low', $c, 'Eksterna skripta bez SRI (integrity)', mb_substr($src, 0, 100), 'Dodaj atribute `integrity` i `crossorigin`.', 'Ako se tuđi server kompromituje, zlonamerna skripta se izvršava na vašem sajtu.');
            if ($https && str_starts_with(strtolower($src), 'http://')) $this->add('medium', $c, 'Mixed content: skripta preko HTTP-a', $src, 'Učitavaj sve resurse preko HTTPS-a.', 'Presretač može podmetnuti kod u stranicu.');
        }
        if ($https) {
            foreach ($x->query('//img[@src]|//link[@href]|//iframe[@src]') as $n) {
                $u = $n->getAttribute('src') ?: $n->getAttribute('href');
                if (str_starts_with(strtolower($u), 'http://')) { $this->add('low', $c, 'Mixed content (resurs preko HTTP-a)', mb_substr($u, 0, 100), 'Zameni sa https:// adresom.', 'Narušava zaštitu HTTPS-a.'); break; }
            }
        }
        foreach ($x->query('//comment()') as $cm) {
            if (preg_match('/password|passwd|secret|api[_-]?key|todo|debug|admin|fixme/i', $cm->nodeValue)) {
                $this->add('low', $c, 'HTML komentar sa osetljivim sadržajem', mb_substr(trim($cm->nodeValue), 0, 100), 'Ukloni komentare iz produkcije.', 'Komentare vidi svako ko otvori izvor stranice.');
                break;
            }
        }
        $gen = $x->query('//meta[@name="generator"]')->item(0);
        if ($gen) $this->add('info', self::C_INFO, 'Meta generator otkriva CMS/verziju', $gen->getAttribute('content'), 'Ukloni meta tag.');
    }

    private const MAX_JS = 8;
    private const MAX_JS_BYTES = 1048576;

    /** Nalazi iste-origin JS fajlove na stranici, preuzima ih (do limita) i pušta kroz JsAnalyzer. */
    private function jsScan(string $body, string $origin, string $host): void
    {
        if (!preg_match('/<html|<body/i', $body)) return;
        libxml_use_internal_errors(true);
        $d = new DOMDocument();
        $d->loadHTML('<?xml encoding="UTF-8">' . $body, LIBXML_NONET);
        $x = new DOMXPath($d);
        $urls = [];
        foreach ($x->query('//script[@src]') as $s) {
            $src = $s->getAttribute('src');
            if ($src === '') continue;
            $abs = $this->toAbsolute($src, $origin);
            if (!$abs) continue;
            $h = parse_url($abs, PHP_URL_HOST);
            if ($h && strcasecmp($h, $host) === 0) $urls[$abs] = true;
        }
        $urls = array_slice(array_keys($urls), 0, self::MAX_JS);
        if (!$urls) { $this->pass(self::C_HTML, 'Nema JS fajlova za analizu (ili su svi eksterni)'); return; }

        $found = 0; $checked = 0; $skipped = 0;
        foreach ($urls as $u) {
            $r = $this->http($u);
            if ($r['code'] !== 200 || !$r['body']) continue;
            if (strlen($r['body']) >= self::MAX_JS_BYTES) { $skipped++; continue; }
            $checked++;
            $label = basename((string)parse_url($u, PHP_URL_PATH)) ?: $u;
            $fs = JsAnalyzer::analyze($r['body'], $label);
            $found += count($fs);
            foreach ($fs as $f) $this->f[] = $f;

            // ako kod referencira source mapu, proveri da li je ta mapa javno dostupna
            if (preg_match('~//#\s*sourceMappingURL\s*=\s*(\S+\.map)~i', $r['body'], $m)) {
                $mapUrl = $this->toAbsolute($m[1], $u);
                if ($mapUrl) {
                    $mr = $this->http($mapUrl);
                    if ($mr['code'] === 200 && str_contains($mr['body'], '"sources"')) {
                        $found++;
                        $this->add('medium', 'Kritični JavaScript fajlovi', "[$label] Source map je javno dostupna", $mapUrl, 'Ukloni .map fajlove sa produkcionog servera ili ih zaštiti pristupom.', 'Source map otkriva originalni (nesažeti) izvorni kod, uključujući komentare i internu logiku.');
                    }
                }
            }
        }
        if ($skipped) $this->add('info', self::C_HTML, "$skipped JS fajl(ova) preskočeno (veći od 1 MB)");
        if ($checked && !$found) $this->pass(self::C_HTML, "Pregledano $checked JS fajl(ova), bez očiglednih problema");
    }

    private function toAbsolute(string $url, string $base): ?string
    {
        if (preg_match('~^https?://~i', $url)) return $url;
        if (str_starts_with($url, '//')) return parse_url($base, PHP_URL_SCHEME) . ':' . $url;
        $b = parse_url($base);
        if (!$b) return null;
        $origin = $b['scheme'] . '://' . $b['host'] . (isset($b['port']) ? ':' . $b['port'] : '');
        if (str_starts_with($url, '/')) return $origin . $url;
        $path = isset($b['path']) ? preg_replace('~/[^/]*$~', '/', $b['path']) : '/';
        return $origin . $path . $url;
    }

    /** Pasivna GraphQL introspekcija: standardni, read-only upit za šemu (nije napad). */
    private function graphql(string $origin): void
    {
        foreach (['/graphql', '/api/graphql'] as $path) {
            $probe = $this->http($origin . $path);
            if ($probe['code'] !== 200 && $probe['code'] !== 400 && $probe['code'] !== 405) continue;
            $r = $this->http($origin . $path, 'POST', ['Content-Type: application/json']);
            // GET sa ?query= je dovoljno za detekciju bez slanja POST tela; ako endpoint prihvata GET:
            $q = $origin . $path . '?query=' . rawurlencode('query{__schema{types{name}}}');
            $r2 = $this->http($q);
            if ($r2['code'] === 200 && str_contains($r2['body'], '__schema')) {
                $this->add('medium', self::C_FILES, 'GraphQL introspekcija je uključena', $origin . $path, 'Isključi introspekciju na produkciji (npr. `introspection: false`).', 'Napadač dobija kompletnu šemu API-ja (sva polja, tipove i mutacije) bez autentifikacije.');
            }
        }
    }

    private function sourceLeak(string $body): void
    {
        if (preg_match('/<\?php|<\?=\s/', $body)) {
            $this->add('critical', self::C_PHP, 'Server vraća PHP izvorni kod (PHP se ne izvršava)', 'Odgovor sadrži <?php.', 'Proveri PHP handler u konfiguraciji web servera (FastCGI/mod_php).', 'Napadač čita izvorni kod, lozinke baze i logiku aplikacije.');
            foreach (CodeAnalyzer::analyze($body)['f'] as $f) { $f['title'] = '[izloženi kod] ' . $f['title']; $f['cat'] = 'Izloženi PHP kod'; $this->f[] = $f; }
        } else $this->pass(self::C_PHP, 'PHP izvorni kod nije izložen');
    }

    /** Bezopasne probe: marker reflektovanja i izazivanje poruke o grešci (bez exploita). */
    private function inputProbes(string $url): void
    {
        $sep = str_contains($url, '?') ? '&' : '?';
        $mark = 'sc' . bin2hex(random_bytes(4));
        $r = $this->http($url . $sep . '__sc=' . rawurlencode($mark . '"\'<>'));
        if (str_contains($r['body'], $mark . '"\'<>') || str_contains($r['body'], $mark . '<')) {
            $this->add('high', self::C_ERR, 'Unos se reflektuje bez enkodovanja (potencijalni XSS)', 'Znakovi < > " \' vraćeni su neizmenjeni.', 'Pri svakom ispisu: `htmlspecialchars($x, ENT_QUOTES | ENT_SUBSTITUTE, "UTF-8")` + CSP.', 'Napadač može ubaciti JavaScript koji se izvršava u browseru žrtve.');
        } elseif (str_contains($r['body'], $mark)) {
            $this->add('info', self::C_ERR, 'Parametar se reflektuje u odgovoru (enkodovan)', 'Proveri ručno različite kontekste (atribut, JavaScript, URL).');
        } else $this->pass(self::C_ERR, 'Test unos se ne reflektuje u odgovoru');
        $this->errors($r['body']);
        $this->errors($this->http($url . $sep . '__sc[]=1&id=%27')['body']);
        if (!$this->errSeen) $this->pass(self::C_ERR, 'Nema PHP/SQL poruka o greškama u odgovoru');
    }

    private function errors(string $b): void
    {
        $tests = [
            'php'   => ['~(?:Warning|Notice|Fatal error|Parse error|Deprecated):.{0,200}? in .{0,200}? on line \d+~is', 'high', 'Prikazuju se PHP greške (curi putanja i kod)', 'Produkcija: `display_errors=Off`, `log_errors=On`.', 'Putanje i delovi koda pomažu napadaču da planira napad.'],
            'trace' => ['~Stack trace:|#0 .*\.php\(\d+\)~i', 'high', 'Prikazuje se stack trace', 'Isključi debug režim (npr. `APP_DEBUG=false`).', 'Otkriva internu strukturu aplikacije.'],
            'sql'   => ['~You have an error in your SQL syntax|SQLSTATE\[|mysqli?_\w+\(\)|ORA-\d{5}|PG::\w+|unterminated quoted string|SQLite3::|Microsoft OLE DB Provider|Unclosed quotation mark|System\.Data\.SqlClient|MongoDB\\\\Driver|E11000 duplicate key~i', 'high', 'Prikazuju se greške baze podataka (indikator SQL/NoSQL Injection-a)', 'Koristi prepared statements i sakrij greške.', 'Znak da unos stiže do upita ka bazi; poruke vode napadača kroz iskorišćavanje.'],
        ];
        foreach ($tests as $k => [$re, $sev, $title, $fix, $why]) {
            if (!isset($this->errSeen[$k]) && preg_match($re, $b, $m)) {
                $this->errSeen[$k] = true;
                $this->add($sev, self::C_ERR, $title, mb_substr(trim(strip_tags($m[0])), 0, 140), $fix, $why);
            }
        }
    }

    private function sensitiveFiles(string $origin): void
    {
        $soft404 = $this->http($origin . '/' . bin2hex(random_bytes(6)) . '.php')['code'] === 200;
        if ($soft404) $this->add('info', self::C_FILES, 'Sajt vraća 200 i za nepostojeće stranice', 'Neke provere fajlova su preskočene da bi se izbegli lažni alarmi.', 'Vrati pravi 404 za nepostojeće stranice.');
        $found = 0; $checked = 0;
        foreach (self::FILES as $path => [$re, $sev, $title]) {
            if ($soft404 && preg_match($re, '')) continue;
            $checked++;
            $r = $this->http($origin . $path);
            if ($r['code'] === 200 && preg_match($re, $r['body'])) {
                $found++;
                $this->add($sev, self::C_FILES, $title, $origin . $path, 'Obriši fajl ili blokiraj pristup na nivou web servera (`deny all`).', self::FILE_WHY);
            }
        }
        if (!$found) $this->pass(self::C_FILES, "Nijedna od $checked poznatih osetljivih putanja nije izložena");
    }
}

/* ================================================================== */
/*  Prikaz izveštaja                                                   */
/* ================================================================== */
function renderCode(array $h): string
{
    $o = '<pre class="code">';
    foreach ($h['ctx'] as [$n, $txt]) {
        $o .= '<span class="' . ($n === $h['n'] ? 'hl' : 'cx') . '"><i>' . $n . '</i>' . e($txt) . "</span>\n";
    }
    return $o . '</pre>';
}

function renderFinding(array $f, bool $openAll): string
{
    $open = ($openAll || in_array($f['sev'], ['critical', 'high'], true)) ? ' open' : '';
    $o = '<details class="f ' . e($f['sev']) . '"' . $open . '><summary><span class="b">' . e(SEV_LABEL[$f['sev']]) . '</span><span class="t">' . e($f['title']) . '</span>'
       . ($f['cwe'] ? '<span class="cwe">' . e($f['cwe']) . '</span>' : '') . '</summary><div class="body">';
    if ($f['detail']) $o .= '<div class="row"><b>Pronađeno</b><p>' . fmt($f['detail']) . '</p></div>';
    if ($f['hits'])   { $o .= '<div class="row"><b>Mesta u kodu</b><div>'; foreach ($f['hits'] as $h) $o .= renderCode($h); $o .= '</div></div>'; }
    if ($f['why'])    $o .= '<div class="row"><b>Zašto je važno</b><p>' . fmt($f['why']) . '</p></div>';
    if ($f['fix'])    $o .= '<div class="row fix"><b>Kako popraviti</b><p>' . fmt($f['fix']) . '</p></div>';
    return $o . '</div></details>';
}

function ring(array $s, string $size = ''): string
{
    return '<div class="ring g-' . $s['grade'] . ' ' . $size . '" style="--p:' . (int)$s['score'] . '" role="img" aria-label="Ocena ' . (int)$s['score'] . ' od 100, razred ' . $s['grade'] . '"><span>' . (int)$s['score'] . '</span></div>';
}

function chips(array $count): string
{
    $o = '<div class="chips">';
    foreach (SEV_ORDER as $sev => $_) $o .= '<span class="chip ' . $sev . ($count[$sev] ? '' : ' zero') . '"><b>' . $count[$sev] . '</b> ' . e(SEV_LABEL[$sev]) . '</span>';
    return $o . '</div>';
}

function reportBody(array $results, bool $export = false): string
{
    $o = '';
    $sum = [];
    foreach ($results as $i => $r) { usort($results[$i]['f'], fn($a, $b) => SEV_ORDER[$a['sev']] <=> SEV_ORDER[$b['sev']]); $sum[$i] = summarize($results[$i]['f']); }

    // --- Pregled
    $o .= '<section class="card"><h2>Pregled</h2><div class="ov">';
    foreach ($results as $i => $r) {
        $o .= '<a class="ovrow" href="#t' . $i . '">' . ring($sum[$i], 'sm') . '<div><strong>' . e($r['target']) . '</strong>'
            . ($r['err'] ? '<div class="small err-t">' . e($r['err']) . '</div>' : '') . chips($sum[$i]['count']) . '</div><span class="grade g-' . $sum[$i]['grade'] . '">' . $sum[$i]['grade'] . '</span></a>';
    }
    $o .= '</div>';
    $top = [];
    foreach ($results as $i => $r) foreach ($results[$i]['f'] as $f) if (in_array($f['sev'], ['critical', 'high'], true)) $top[] = [$i, $f];
    if ($top) {
        $o .= '<h3>Prvo popravi (' . count($top) . ')</h3><ol class="top">';
        foreach (array_slice($top, 0, 8) as [$i, $f]) $o .= '<li><a href="#t' . $i . '"><span class="b mini ' . e($f['sev']) . '">' . e(SEV_LABEL[$f['sev']]) . '</span> ' . e($f['title']) . '</a></li>';
        $o .= '</ol>';
    } else $o .= '<p class="okline">✓ Nema kritičnih ni visokih problema u okviru ovih provera.</p>';
    $o .= '<p class="legend small"><b>Kako čitati:</b> KRITIČNO – popraviti odmah · VISOKO – što pre · SREDNJE – isplanirati · NISKO/INFO – poboljšanja. Ocena 90+ = A, 75+ = B, 60+ = C, 40+ = D.</p></section>';

    // --- Filter (čist CSS)
    if (!$export) {
        $o .= '<div class="filter" role="radiogroup" aria-label="Filter po ozbiljnosti">'
            . '<label class="pill"><input type="radio" name="flt" id="flt-all" checked><span>Sve</span></label>'
            . '<label class="pill"><input type="radio" name="flt" id="flt-imp"><span>Kritično + Visoko</span></label>'
            . '<label class="pill"><input type="radio" name="flt" id="flt-med"><span>Srednje</span></label>'
            . '<label class="pill"><input type="radio" name="flt" id="flt-low"><span>Nisko + Info</span></label></div>';
    }

    // --- Po metama
    foreach ($results as $i => $r) {
        $s = $sum[$i];
        $o .= '<section class="card target" id="t' . $i . '"><header class="th">' . ring($s) . '<div><h2>' . e($r['target']) . '</h2>';
        $meta = array_filter([$r['meta'] ?? '', ...($r['tech'] ?? [])]);
        if ($meta) $o .= '<div class="techs">' . implode('', array_map(fn($t) => '<span class="tech">' . e((string)$t) . '</span>', array_unique($meta))) . '</div>';
        $o .= chips($s['count']) . '<div class="small">Provera u redu: ' . count($r['ok']) . ' · problema: ' . count($r['f']) . '</div></div></header>';
        if ($r['err']) $o .= '<div class="err">' . e($r['err']) . '</div>';

        $groups = [];
        foreach ($r['f'] as $f) $groups[$f['cat']][] = $f;
        uasort($groups, fn($a, $b) => SEV_ORDER[$a[0]['sev']] <=> SEV_ORDER[$b[0]['sev']]);
        foreach ($groups as $cat => $list) {
            $o .= '<div class="cat"><h3>' . e($cat) . ' <small>' . count($list) . '</small></h3>';
            foreach ($list as $f) $o .= renderFinding($f, $export);
            $o .= '</div>';
        }
        if (!$r['f'] && !$r['err']) $o .= '<p class="okline">✓ Nisu pronađeni problemi u okviru ovih provera.</p>';
        if ($r['ok']) {
            $o .= '<details class="passed"' . ($export ? ' open' : '') . '><summary>✓ Provere koje su prošle (' . count($r['ok']) . ')</summary><ul>';
            foreach ($r['ok'] as $p) $o .= '<li><span class="small">' . e($p['cat']) . '</span> – ' . e($p['title']) . '</li>';
            $o .= '</ul></details>';
        }
        $o .= '</section>';
    }
    return $o;
}

function css(): string
{
    return <<<'CSS'
:root{--bg:#f4f5f7;--card:#fff;--tx:#1b1f24;--mut:#667085;--bd:#e3e6ea;--soft:rgba(127,127,127,.07);--ac:#2563eb}
@media(prefers-color-scheme:dark){:root{--bg:#0f1216;--card:#171b21;--tx:#e6e8eb;--mut:#9aa3ad;--bd:#2a3038}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);font:15px/1.55 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:960px;margin:0 auto;padding:24px 16px 60px}
h1{margin:0 0 4px;font-size:26px}h2{margin:0 0 6px;font-size:19px;word-break:break-all}h3{margin:18px 0 8px;font-size:15px;text-transform:uppercase;letter-spacing:.04em;color:var(--mut)}
h3 small{background:var(--soft);padding:1px 8px;border-radius:99px;margin-left:6px}
.sub{color:var(--mut);margin:0 0 18px}.small{font-size:13px;color:var(--mut)}
.card{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:18px;margin-bottom:16px}
textarea,input[type=file]{width:100%;background:transparent;color:inherit;border:1px solid var(--bd);border-radius:8px;padding:10px;font:13px ui-monospace,Menlo,monospace}
label.l{display:block;font-weight:600;margin:12px 0 4px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}@media(max-width:700px){.grid{grid-template-columns:1fr}}
button,.btn{background:var(--ac);color:#fff;border:0;border-radius:8px;padding:10px 18px;font-size:15px;cursor:pointer;text-decoration:none;display:inline-block}
.btn.sec{background:transparent;color:var(--ac);border:1px solid var(--ac);padding:7px 14px;font-size:14px}
summary{cursor:pointer}details.form>summary{font-weight:600;font-size:16px}
.err{background:#fee2e2;color:#991b1b;border-radius:8px;padding:10px 14px;margin:10px 0}.err-t{color:#b91c1c}
/* ocena */
.ring{--c:#16a34a;width:84px;height:84px;border-radius:50%;background:conic-gradient(var(--c) calc(var(--p)*1%),var(--bd) 0);display:grid;place-items:center;position:relative;flex:none}
.ring::before{content:"";position:absolute;inset:8px;border-radius:50%;background:var(--card)}.ring span{position:relative;font-weight:700;font-size:24px}
.ring.sm{width:54px;height:54px}.ring.sm::before{inset:6px}.ring.sm span{font-size:16px}
.g-A{--c:#16a34a}.g-B{--c:#65a30d}.g-C{--c:#d97706}.g-D{--c:#ea580c}.g-F{--c:#b91c1c}
.grade{font-size:28px;font-weight:800;color:var(--c);margin-left:auto}
.ov{display:flex;flex-direction:column;gap:8px}.ovrow{display:flex;gap:14px;align-items:center;padding:10px;border:1px solid var(--bd);border-radius:10px;color:inherit;text-decoration:none}
.ovrow:hover{background:var(--soft)}.ovrow strong{word-break:break-all}
.chips{display:flex;flex-wrap:wrap;gap:6px;margin:6px 0}.chip{font-size:12px;padding:2px 9px;border-radius:99px;border:1px solid;background:transparent}
.chip.zero{opacity:.35}.chip.critical{color:#b91c1c;border-color:#b91c1c}.chip.high{color:#ea580c;border-color:#ea580c}.chip.medium{color:#b45309;border-color:#d97706}.chip.low{color:#2563eb;border-color:#2563eb}.chip.info{color:var(--mut);border-color:var(--mut)}
.top{margin:6px 0 0;padding-left:20px}.top a{color:inherit;text-decoration:none}.top a:hover{text-decoration:underline}.top li{margin:3px 0}
.okline{color:#15803d;font-weight:600}.legend{margin-top:14px}
/* filter (čist CSS) */
.filter{display:flex;gap:8px;flex-wrap:wrap;margin:0 0 14px;position:sticky;top:0;background:var(--bg);padding:8px 0;z-index:5}
.pill input{position:absolute;opacity:0}.pill span{display:inline-block;padding:6px 14px;border:1px solid var(--bd);border-radius:99px;cursor:pointer;background:var(--card)}
.pill input:checked+span{background:var(--ac);color:#fff;border-color:var(--ac)}.pill input:focus-visible+span{outline:2px solid var(--ac);outline-offset:2px}
main:has(#flt-imp:checked) .f:not(.critical):not(.high),main:has(#flt-med:checked) .f:not(.medium),main:has(#flt-low:checked) .f:not(.low):not(.info){display:none}
main:has(#flt-imp:checked) .cat:not(:has(.f.critical,.f.high)),main:has(#flt-med:checked) .cat:not(:has(.f.medium)),main:has(#flt-low:checked) .cat:not(:has(.f.low,.f.info)){display:none}
main:not(:has(#flt-all:checked)) .passed{display:none}
/* mete i nalazi */
.th{display:flex;gap:16px;align-items:center;margin-bottom:6px}.techs{display:flex;flex-wrap:wrap;gap:6px;margin:4px 0}.tech{font-size:12px;background:var(--soft);padding:1px 8px;border-radius:6px}
.f{border:1px solid var(--bd);border-left:5px solid;border-radius:8px;margin:8px 0;background:var(--card)}
.f>summary{list-style:none;display:flex;gap:10px;align-items:center;padding:10px 12px}.f>summary::-webkit-details-marker{display:none}
.f>summary::after{content:"▸";margin-left:auto;color:var(--mut)}.f[open]>summary::after{content:"▾"}
.t{font-weight:600}.cwe{font-size:11px;color:var(--mut);border:1px solid var(--bd);padding:0 6px;border-radius:5px}
.b{font-size:11px;font-weight:700;padding:2px 8px;border-radius:99px;color:#fff;white-space:nowrap}.b.mini{font-size:10px}
.critical{border-left-color:#b91c1c}.critical .b,.b.critical{background:#b91c1c}.high{border-left-color:#ea580c}.high .b,.b.high{background:#ea580c}
.medium{border-left-color:#d97706}.medium .b,.b.medium{background:#d97706}.low{border-left-color:#2563eb}.low .b,.b.low{background:#2563eb}
.info{border-left-color:#6b7280}.info .b,.b.info{background:#6b7280}
.chip.critical,.chip.high,.chip.medium,.chip.low,.chip.info{border-left-width:1px}
.body{padding:2px 14px 12px}.row{display:grid;grid-template-columns:130px 1fr;gap:10px;padding:7px 0;border-top:1px dashed var(--bd)}
.row b{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--mut)}.row p{margin:0;word-break:break-word}@media(max-width:600px){.row{grid-template-columns:1fr;gap:2px}}
.row.fix p{background:rgba(22,163,74,.09);padding:6px 10px;border-radius:6px}
code{background:var(--soft);padding:1px 5px;border-radius:4px;font:13px ui-monospace,Menlo,monospace}
pre.code{margin:0 0 8px;padding:6px 0;background:#0f172a;color:#e2e8f0;border-radius:8px;overflow-x:auto;font:12.5px/1.5 ui-monospace,Menlo,monospace}
pre.code span{display:block;padding:0 12px;white-space:pre}pre.code i{display:inline-block;width:38px;color:#64748b;font-style:normal;user-select:none}
pre.code .hl{background:rgba(239,68,68,.22);border-left:3px solid #ef4444;margin-left:-3px}
.passed{margin-top:16px;border:1px solid var(--bd);border-radius:8px;padding:8px 12px}.passed summary{font-weight:600;color:#15803d}.passed ul{margin:8px 0 0;padding-left:20px}.passed li{margin:2px 0}
.exports{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:0 0 16px}
@media print{.filter,details.form,.exports,button{display:none}body{background:#fff}.card{break-inside:avoid}}
CSS;
}

/* ================================================================== */
/*  Kontroler                                                          */
/* ================================================================== */
if (isset($_GET['export'])) {
    $rep = $_SESSION['report'] ?? null;
    if (!$rep) { http_response_code(404); header('Content-Type: text/plain; charset=utf-8'); exit('Nema izveštaja. Prvo pokreni skeniranje.'); }
    $fmtX = (string)$_GET['export'];
    $name = 'seccheck-' . date('Ymd-His', $rep['time']);
    header('Cache-Control: no-store');
    if ($fmtX === 'json') {
        header('Content-Type: application/json; charset=utf-8');
        header("Content-Disposition: attachment; filename=\"$name.json\"");
        echo json_encode($rep, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    } elseif ($fmtX === 'txt') {
        header('Content-Type: text/plain; charset=utf-8');
        header("Content-Disposition: attachment; filename=\"$name.txt\"");
        echo "SecCheck izveštaj – " . date('Y-m-d H:i:s', $rep['time']) . "\n" . str_repeat('=', 70) . "\n";
        foreach ($rep['results'] as $r) {
            usort($r['f'], fn($a, $b) => SEV_ORDER[$a['sev']] <=> SEV_ORDER[$b['sev']]);
            $s = summarize($r['f']);
            echo "\n### {$r['target']}\nOcena: {$s['score']}/100 ({$s['grade']})\n";
            if ($r['err']) echo "Greška: {$r['err']}\n";
            foreach ($r['f'] as $f) {
                echo "\n[" . SEV_LABEL[$f['sev']] . "] {$f['cat']} – {$f['title']}" . ($f['cwe'] ? " ({$f['cwe']})" : '') . "\n";
                foreach (['detail' => 'Pronađeno', 'why' => 'Zašto', 'fix' => 'Popravka'] as $k => $lbl) if ($f[$k]) echo "  $lbl: " . str_replace('`', '', $f[$k]) . "\n";
                foreach ($f['hits'] as $h) foreach ($h['ctx'] as [$n, $t]) echo '    ' . ($n === $h['n'] ? '>' : ' ') . " $n| $t\n";
            }
            echo "\nProšle provere: " . count($r['ok']) . "\n";
        }
    } else {
        header('Content-Type: text/html; charset=utf-8');
        header("Content-Disposition: attachment; filename=\"$name.html\"");
        echo '<!doctype html><html lang="sr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SecCheck izveštaj</title><style>' . css() . '</style></head><body><main><h1>SecCheck izveštaj</h1><p class="sub">' . e(date('d.m.Y H:i', $rep['time'])) . '</p>' . reportBody($rep['results'], true) . '</main></body></html>';
    }
    exit;
}

header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
header('X-Frame-Options: DENY');

if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32));
$results = [];
$error = '';
$urlsIn = (string)($_POST['urls'] ?? '');
$codeIn = (string)($_POST['code'] ?? '');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $files = [];
    if (!empty($_FILES['files']['name'][0] ?? '')) {
        $n = min(count($_FILES['files']['name']), 10);
        for ($i = 0; $i < $n; $i++) {
            $nm = (string)$_FILES['files']['name'][$i];
            $label = preg_replace('/[^\w.\- ]/u', '_', basename($nm));
            $ext = strtolower(pathinfo($nm, PATHINFO_EXTENSION));
            if ($_FILES['files']['error'][$i] !== UPLOAD_ERR_OK || !is_uploaded_file($_FILES['files']['tmp_name'][$i])) { $results[] = ['target' => 'Fajl: ' . $label, 'f' => [], 'ok' => [], 'tech' => [], 'err' => 'Otpremanje nije uspelo.']; continue; }
            if (!in_array($ext, ['php', 'inc', 'phtml', 'php5', 'php7', 'txt'], true)) { $results[] = ['target' => 'Fajl: ' . $label, 'f' => [], 'ok' => [], 'tech' => [], 'err' => 'Dozvoljene ekstenzije: php, inc, phtml, txt.']; continue; }
            if ($_FILES['files']['size'][$i] > 1048576) { $results[] = ['target' => 'Fajl: ' . $label, 'f' => [], 'ok' => [], 'tech' => [], 'err' => 'Fajl je veći od 1 MB.']; continue; }
            $files[$label] = (string)file_get_contents($_FILES['files']['tmp_name'][$i]); // samo se čita, nikad se ne izvršava
        }
    }

    $urls = array_slice(array_values(array_unique(array_filter(array_map('trim', preg_split('/\R/', $urlsIn))))), 0, 5);
    if (!hash_equals($_SESSION['csrf'], (string)($_POST['csrf'] ?? ''))) {
        $error = 'Nevažeći CSRF token – osveži stranicu.';
    } elseif (time() - ($_SESSION['last'] ?? 0) < 5) {
        $error = 'Sačekaj nekoliko sekundi između skeniranja.';
    } elseif ($urls && empty($_POST['confirm'])) {
        $error = 'Za skeniranje linkova moraš potvrditi da si vlasnik sajta ili imaš dozvolu za testiranje.';
    } elseif (!$urls && trim($codeIn) === '' && !$files && !$results) {
        $error = 'Unesi bar jedan URL, zalepi PHP kod ili otpremi PHP fajl.';
    } else {
        $_SESSION['last'] = time();
        set_time_limit(240);
        foreach ($urls as $u) {
            $sc = new Scanner();
            try { $sc->scan($u); $err = ''; } catch (Throwable $ex) { $err = $ex->getMessage(); }
            $results[] = ['target' => $u, 'f' => $sc->f, 'ok' => $sc->ok, 'tech' => array_values(array_unique($sc->tech)), 'err' => $err];
        }
        foreach ($files as $label => $src) {
            $a = CodeAnalyzer::analyze($src);
            $results[] = ['target' => 'Fajl: ' . $label, 'f' => $a['f'], 'ok' => [], 'tech' => [], 'err' => '', 'meta' => $a['meta']];
        }
        if (trim($codeIn) !== '') {
            $a = CodeAnalyzer::analyze(mb_substr($codeIn, 0, 500000));
            $results[] = ['target' => 'Zalepljeni PHP kod', 'f' => $a['f'], 'ok' => [], 'tech' => [], 'err' => '', 'meta' => $a['meta']];
        }
        if ($results) $_SESSION['report'] = ['time' => time(), 'results' => $results];
    }
}
?>
<!doctype html>
<html lang="sr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SecCheck – skener bezbednosti PHP-a</title>
<style><?= css() ?></style>
</head>
<body><main>
<h1>🛡️ SecCheck</h1>
<p class="sub">Skener bezbednosti PHP sajtova i PHP koda. Neagresivne provere – koristi samo na sajtovima koje poseduješ.</p>

<?php if ($error): ?><div class="err"><?= e($error) ?></div><?php endif; ?>

<details class="card form"<?= $results ? '' : ' open' ?>>
<summary><?= $results ? 'Novo skeniranje' : 'Pokreni skeniranje' ?></summary>
<form method="post" enctype="multipart/form-data">
  <input type="hidden" name="csrf" value="<?= e($_SESSION['csrf']) ?>">
  <div class="grid">
    <div>
      <label class="l" for="urls">Linkovi (jedan po liniji, max 5)</label>
      <textarea id="urls" name="urls" rows="6" placeholder="https://moj-sajt.rs/&#10;https://moj-sajt.rs/login.php"><?= e($urlsIn) ?></textarea>
    </div>
    <div>
      <label class="l" for="code">PHP kod za statičku analizu</label>
      <textarea id="code" name="code" rows="6" placeholder="Zalepi PHP kod ovde…"><?= e($codeIn) ?></textarea>
    </div>
  </div>
  <label class="l" for="files">…ili otpremi PHP fajlove (do 10, max 1 MB; samo se čitaju, nikad ne izvršavaju)</label>
  <input id="files" type="file" name="files[]" multiple accept=".php,.inc,.phtml,.txt">
  <p><label><input type="checkbox" name="confirm" value="1"> Potvrđujem da sam vlasnik ovih sajtova ili imam izričitu dozvolu da ih testiram (važi za linkove).</label></p>
  <button type="submit">Pokreni proveru</button>
</form>
</details>

<?php if ($results): ?>
  <div class="exports"><span class="small">Izvezi izveštaj:</span>
    <a class="btn sec" href="?export=html">HTML</a><a class="btn sec" href="?export=txt">TXT</a><a class="btn sec" href="?export=json">JSON</a>
  </div>
  <?= reportBody($results) ?>
<?php endif; ?>

<p class="small">Napomena: automatski skener ne pronalazi sve ranjivosti (logičke greške, autorizacija, složeni SQLi/XSS). Statička analiza je heuristika i daje lažne alarme – svaki nalaz proveri ručno. Za kritične sisteme uradi i ručni pentest / code review.</p>
</main></body></html>
