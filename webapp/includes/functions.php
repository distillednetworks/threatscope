<?php
// ============================================================
//  ThreatScope — includes/functions.php
//  Core helpers: auth, HTTP requests, history, rate limiting
// ============================================================

require_once __DIR__ . '/../config.php';

// ─── Session ──────────────────────────────────────────────────
function ts_session_start() {
    if (session_status() === PHP_SESSION_NONE) {
        session_set_cookie_params([
            'lifetime' => SESSION_LIFETIME,
            'path'     => '/',
            'secure'   => isset($_SERVER['HTTPS']),
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
        session_start();
    }
}

// ─── Auth ─────────────────────────────────────────────────────

/**
 * Establish an authenticated session from a verified identity.
 * Called by both SAML ACS and local login after credentials are confirmed.
 */
function auth_establish_session(string $username, string $role, string $display_name, string $email = ''): void {
    // Regenerate session ID to prevent fixation attacks
    session_regenerate_id(true);
    $_SESSION['ts_user']    = $username;
    $_SESSION['ts_role']    = $role;
    $_SESSION['ts_name']    = $display_name;
    $_SESSION['ts_email']   = $email;
    $_SESSION['ts_loginat'] = time();
    $_SESSION['ts_auth']    = AUTH_MODE;
}

/**
 * Local password login — only active when AUTH_MODE = 'local'
 */

function auth_login_local(string $username, string $password): bool {
    $users = USERS;
    $uname = strtolower(trim($username));

    if (!isset($users[$uname])) {
        // Timing-safe dummy verify to prevent user enumeration
        password_verify($password, '$2y$10$invaliddummyhashfortimingsafety00000000');
        return false;
    }

    if (!password_verify($password, $users[$uname]['password_hash'])) {
        return false;
    }

    auth_establish_session(
        $uname,
        $users[$uname]['role'],
        $users[$uname]['display_name'],
        $uname . '@local'
    );

    return true;
}

function auth_check(): bool {
    ts_session_start();
    if (empty($_SESSION['ts_user'])) return false;
    if (time() - ($_SESSION['ts_loginat'] ?? 0) > SESSION_LIFETIME) {
        session_destroy();
        return false;
    }
    return true;
}

function auth_require(): void {
    if (!auth_check()) {
        // For SAML mode, redirect to the SSO initiator
        if (AUTH_MODE === 'okta') {
            header('Location: saml/login.php');
        } else {
            header('Location: index.php');
        }
        exit;
    }
}

function auth_user(): array {
    return [
        'username' => $_SESSION['ts_user']    ?? '',
        'role'     => $_SESSION['ts_role']    ?? 'analyst',
        'name'     => $_SESSION['ts_name']    ?? '',
        'email'    => $_SESSION['ts_email']   ?? '',
        'auth'     => $_SESSION['ts_auth']    ?? AUTH_MODE,
    ];
}

function auth_logout(): void {
    ts_session_start();
    session_destroy();
}

/**
 * Map Okta groups array to a ThreatScope role using config group_role_map.
 */
function saml_map_role(array $groups): string {
    $map = OKTA_SAML['group_role_map'] ?? [];
    foreach ($map as $group => $role) {
        if (in_array($group, $groups, true)) return $role;
    }
    return OKTA_SAML['default_role'] ?? 'analyst';
}

// ─── Rate limiting ────────────────────────────────────────────
function rate_limit_check(string $key, int $max, int $window_seconds): bool {
    $file = RATE_LIMIT_FILE;
    $data = [];
    if (file_exists($file)) {
        $data = json_decode(file_get_contents($file), true) ?? [];
    }

    $ip    = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $k     = $key . ':' . $ip;
    $now   = time();

    if (!isset($data[$k])) {
        $data[$k] = ['count' => 0, 'window_start' => $now];
    }

    // Reset window if expired
    if ($now - $data[$k]['window_start'] > $window_seconds) {
        $data[$k] = ['count' => 0, 'window_start' => $now];
    }

    $data[$k]['count']++;
    $allowed = $data[$k]['count'] <= $max;

    // Clean old entries
    foreach ($data as $dk => $dv) {
        if ($now - $dv['window_start'] > $window_seconds * 2) unset($data[$dk]);
    }

    @file_put_contents($file, json_encode($data), LOCK_EX);
    return $allowed;
}

// ─── HTTP client (cURL wrapper) ────────────────────────────────
function http_get(string $url, array $headers = [], bool $verify_ssl = true, int $timeout = 12): array {
    return http_request('GET', $url, null, $headers, $verify_ssl, $timeout);
}

function http_post(string $url, $body, array $headers = [], bool $verify_ssl = true, int $timeout = 12): array {
    return http_request('POST', $url, $body, $headers, $verify_ssl, $timeout);
}

function http_request(string $method, string $url, $body, array $headers, bool $verify_ssl, int $timeout): array {
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL            => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => $timeout,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_SSL_VERIFYPEER => $verify_ssl,
        CURLOPT_SSL_VERIFYHOST => $verify_ssl ? 2 : 0,
        CURLOPT_HTTPHEADER     => array_map(fn($k, $v) => "$k: $v", array_keys($headers), $headers),
        CURLOPT_CUSTOMREQUEST  => $method,
    ]);

    if ($body !== null) {
        $payload = is_string($body) ? $body : json_encode($body);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
    }

    $response   = curl_exec($ch);
    $http_code  = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error      = curl_error($ch);
    curl_close($ch);

    if ($error) {
        return ['ok' => false, 'status' => 0, 'error' => "cURL error: $error", 'data' => null];
    }

    $decoded = json_decode($response, true);
    return [
        'ok'     => $http_code >= 200 && $http_code < 300,
        'status' => $http_code,
        'data'   => $decoded ?? $response,
        'raw'    => $response,
        'error'  => $http_code >= 400 ? "HTTP $http_code" : null,
    ];
}

// ─── Indicator type detection ─────────────────────────────────
function detect_type(string $indicator): ?string {
    $q = trim($indicator);
    if (preg_match('/^(\d{1,3}\.){3}\d{1,3}$/', $q)) return 'IPv4 Address';
    if (preg_match('/^[a-fA-F0-9]{64}$/', $q))       return 'SHA-256 Hash';
    if (preg_match('/^[a-fA-F0-9]{40}$/', $q))       return 'SHA-1 Hash';
    if (preg_match('/^[a-fA-F0-9]{32}$/', $q))       return 'MD5 Hash';
    // Email before domain — must match user@domain.tld
    if (preg_match('/^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/', $q)) return 'Email Address';
    if (preg_match('/^([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}$/', $q)) return 'Domain';
    return null;
}

function is_hash(string $type): bool {
    return str_contains($type, 'Hash');
}

function is_email(string $type): bool {
    return $type === 'Email Address';
}

// ─── History ──────────────────────────────────────────────────
function history_load(): array {
    if (!file_exists(HISTORY_FILE)) return [];
    $raw = file_get_contents(HISTORY_FILE);
    if ($raw === false || trim($raw) === '') return [];
    $decoded = json_decode($raw, true);
    if (!is_array($decoded)) {
        // File is corrupt , back it up and start fresh
        @rename(HISTORY_FILE, HISTORY_FILE . '.corrupt.' . time());
        return [];
    }
    return $decoded;
}

function history_save(array $data): bool {
    $dir = dirname(HISTORY_FILE);
    if (!is_dir($dir)) {
        if (!mkdir($dir, 0750, true)) {
            error_log('[ThreatScope] history_save: cannot create directory ' . $dir);
            return false;
        }
    }
    if (!is_writable($dir) && !(file_exists(HISTORY_FILE) && is_writable(HISTORY_FILE))) {
        error_log('[ThreatScope] history_save: ' . HISTORY_FILE . ' is not writable by web server');
        return false;
    }
    // JSON_PARTIAL_OUTPUT_ON_ERROR prevents false on non-UTF8 chars;
    // JSON_UNESCAPED_UNICODE keeps readability
    $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_PARTIAL_OUTPUT_ON_ERROR);
    if ($json === false) {
        error_log('[ThreatScope] history_save: json_encode failed ‚ ' . json_last_error_msg());
        return false;
    }
    $written = file_put_contents(HISTORY_FILE, $json, LOCK_EX);
    if ($written === false) {
        error_log('[ThreatScope] history_save: file_put_contents failed for ' . HISTORY_FILE);
        return false;
    }
    return true;
}

function history_add(array $entry): string {
    $history = history_load();
    $id = bin2hex(random_bytes(8));

    // Sanitise all string values in the result payload to valid UTF-8
    // to prevent json_encode from silently dropping fields
    if (isset($entry['result'])) {
        $entry['result'] = utf8_sanitise($entry['result']);
    }

    array_unshift($history, array_merge(['id' => $id, 'timestamp' => date('c')], $entry));
    if (count($history) > HISTORY_MAX) {
        $history = array_slice($history, 0, HISTORY_MAX);
    }
    history_save($history);
    return $id;
}

/**
 * Recursively convert any non-UTF-8 strings in an array to valid UTF-8.
 * Prevents json_encode from returning false or dropping fields.
 */
function utf8_sanitise(mixed $value): mixed {
    if (is_string($value)) {
        // mb_convert_encoding with //IGNORE drops bad bytes;
        // if mbstring is unavailable, iconv is the fallback
        if (function_exists('mb_convert_encoding')) {
            return mb_convert_encoding($value, 'UTF-8', 'UTF-8');
        }
        return iconv('UTF-8', 'UTF-8//IGNORE', $value) ?: $value;
    }
    if (is_array($value)) {
        return array_map('utf8_sanitise', $value);
    }
    return $value;
}

function history_get(array $filters = []): array {
    $history = history_load();
    if (!empty($filters['type']))  $history = array_filter($history, fn($h) => ($h['query_type'] ?? '') === $filters['type']);
    if (!empty($filters['query'])) $history = array_filter($history, fn($h) => str_contains($h['query'] ?? '', $filters['query']));
    if (!empty($filters['user']))  $history = array_filter($history, fn($h) => ($h['user'] ?? '') === $filters['user']);
    $limit = min((int)($filters['limit'] ?? 100), 500);
    return array_values(array_slice($history, 0, $limit));
}

function history_get_by_id(string $id): ?array {
    foreach (history_load() as $item) {
        if (($item['id'] ?? '') === $id) return $item;
    }
    return null;
}

function history_clear(?string $user = null): void {
    if ($user === null) {
        history_save([]);
    } else {
        $history = array_filter(history_load(), fn($h) => ($h['user'] ?? '') !== $user);
        history_save(array_values($history));
    }
}

// ─── Settings (runtime overrides stored in JSON) ──────────────
function settings_load(): array {
    $defaults = [
        'misp'          => ['url' => MISP_URL,        'api_key' => MISP_API_KEY,    'verify_ssl' => MISP_VERIFY_SSL, 'enabled' => false],
        'elasticsearch' => ['url' => ELASTIC_URL,     'api_key' => ELASTIC_API_KEY, 'index' => ELASTIC_INDEX, 'enabled' => false, 'kib_url' => KIBANA_URL],
        'virustotal'    => ['api_key' => VT_API_KEY,  'enabled' => false],
        'greynoise'     => ['api_key' => GREYNOISE_API_KEY, 'enabled' => false],
        'geoip'         => ['provider' => GEOIP_PROVIDER, 'maxmind_key' => MAXMIND_API_KEY, 'enabled' => true],
        'whois'         => ['enabled' => true],
    ];

    if (file_exists(SETTINGS_FILE)) {
        $saved = json_decode(file_get_contents(SETTINGS_FILE), true) ?? [];
        foreach ($saved as $source => $vals) {
            if (isset($defaults[$source])) {
                $defaults[$source] = array_merge($defaults[$source], $vals);
            }
        }
    }

    // Auto-enable sources with credentials
    $defaults['misp']['enabled']          = !empty($defaults['misp']['url']) && !empty($defaults['misp']['api_key']);
    $defaults['elasticsearch']['enabled'] = !empty($defaults['elasticsearch']['url']) && !empty($defaults['elasticsearch']['api_key']);
    $defaults['virustotal']['enabled']    = !empty($defaults['virustotal']['api_key']);
    $defaults['greynoise']['enabled']     = !empty($defaults['greynoise']['api_key']);

    return $defaults;
}

function settings_save(array $patch): void {
    $dir = dirname(SETTINGS_FILE);
    if (!is_dir($dir)) mkdir($dir, 0750, true);

    $current = [];
    if (file_exists(SETTINGS_FILE)) {
        $current = json_decode(file_get_contents(SETTINGS_FILE), true) ?? [];
    }

    foreach ($patch as $source => $vals) {
        if (!isset($current[$source])) $current[$source] = [];
        foreach ($vals as $k => $v) {
            // Don't overwrite with masked values
            if (!str_contains((string)$v, '•')) {
                $current[$source][$k] = $v;
            }
        }
    }

    file_put_contents(SETTINGS_FILE, json_encode($current, JSON_PRETTY_PRINT), LOCK_EX);
}

function mask_key(string $key): string {
    if (empty($key)) return '';
    $visible = min(4, strlen($key));
    return str_repeat('•', max(0, strlen($key) - $visible)) . substr($key, -$visible);
}

// ─── Threat score calculation ─────────────────────────────────
function calculate_score(array $source_results): int {
    $score = 0;
    $weights = ['MALICIOUS' => 35, 'SUSPICIOUS' => 15, 'CLEAN' => -5];
    $malicious_count = 0;

    foreach ($source_results as $r) {
        if (!empty($r['skipped']) || !empty($r['error']) || empty($r['found'])) continue;
        $score += $weights[$r['verdict'] ?? ''] ?? 0;
        if (($r['verdict'] ?? '') === 'MALICIOUS') $malicious_count++;
    }

    if ($malicious_count >= 2) $score += 15;
    if ($malicious_count >= 3) $score += 10;

    return max(0, min(100, $score));
}

function score_to_risk(int $score): string {
    if ($score >= 75) return 'CRITICAL';
    if ($score >= 50) return 'HIGH';
    if ($score >= 25) return 'MEDIUM';
    return 'LOW';
}

// ─── JSON response helpers ─────────────────────────────────────
function json_response(array $data, int $status = 200): void {
    http_response_code($status);
    header('Content-Type: application/json');
    echo json_encode($data);
    exit;
}

function json_error(string $message, int $status = 400): void {
    json_response(['error' => $message], $status);
}


// ─── Domains ──────────────────────────────────────────────────

function rdapFetch(string $url): ?array
{
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL            => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_TIMEOUT        => 15,
        CURLOPT_ENCODING       => '',
        CURLOPT_HTTPHEADER     => [
            'Accept: application/rdap+json, application/json',
            'Accept-Language: en-US,en;q=0.9',
        ],
    ]);

    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($httpCode !== 200 || !$response) {
        return null;
    }

    return json_decode($response, true) ?? null;
}

function parseDates(array $data): array
{
    $dates = [];
    $eventMap = [
        'registration' => 'created',
        'expiration'   => 'expires',
        'last changed' => 'updated',
        'last update of RDAP database' => 'rdap_updated',
    ];

    foreach ($data['events'] ?? [] as $event) {
        $action = strtolower($event['eventAction'] ?? '');
        $key    = $eventMap[$action] ?? $action;
        $dates[$key] = $event['eventDate'] ?? null;
    }

    return $dates;
}


function parseRegistrar(array $data): array
{
    foreach ($data['entities'] ?? [] as $entity) {
        $roles = array_map('strtolower', $entity['roles'] ?? []);
        if (!in_array('registrar', $roles)) continue;

        $vcard = parseVcard($entity['vcardArray'][1] ?? []);

        return array_filter([
            'name'   => $entity['fn']    ?? $vcard['fn']  ?? null,
            'iana_id'=> $entity['publicIds'][0]['identifier'] ?? null,
            'url'    => $entity['links'][0]['href']        ?? null,
            'email'  => $vcard['email']                    ?? null,
            'phone'  => $vcard['tel']                      ?? null,
            'abuse_email' => findAbuseEmail($entity),
            'abuse_phone' => findAbusePhone($entity),
        ]);
    }

    return [];
}


function parseContact(array $data, string $role): array
{
    foreach ($data['entities'] ?? [] as $entity) {
        $roles = array_map('strtolower', $entity['roles'] ?? []);
        if (!in_array($role, $roles)) continue;

        $vcard = parseVcard($entity['vcardArray'][1] ?? []);

        return array_filter([
            'name'         => $vcard['fn']           ?? null,
            'org'          => $vcard['org']           ?? null,
            'email'        => $vcard['email']         ?? null,
            'phone'        => $vcard['tel']           ?? null,
            'address'      => $vcard['adr']           ?? null,
            'country'      => $vcard['country']       ?? null,
            'city'         => $vcard['city']          ?? null,
            'state'        => $vcard['state']         ?? null,
            'postal_code'  => $vcard['postal_code']   ?? null,
            'redacted'     => !empty($entity['remarks']) ? true : null,
        ]);
    }

    return [];
}


function parseVcard(array $vcardProps): array
{
    $result = [];

    foreach ($vcardProps as $prop) {
        if (!is_array($prop) || count($prop) < 4) continue;

        [$name, $params, $type, $value] = $prop;

        switch (strtolower($name)) {
            case 'fn':
                $result['fn'] = is_array($value) ? implode(' ', $value) : $value;
                break;
            case 'org':
                $result['org'] = is_array($value) ? implode(', ', $value) : $value;
                break;
            case 'email':
                $result['email'] = is_array($value) ? $value[0] : $value;
                break;
            case 'tel':
                $result['tel'] = is_array($value) ? $value[0] : $value;
                break;
            case 'adr':
                if (is_array($value)) {
                    $result['adr']         = trim(implode(', ', array_filter($value)));
                    $result['city']        = $value[3] ?? null;
                    $result['state']       = $value[4] ?? null;
                    $result['postal_code'] = $value[5] ?? null;
                    $result['country']     = $value[6] ?? null;
                }
                break;
        }
    }

    return $result;
}


function parseNameservers(array $data): array
{
    $ns = [];
    foreach ($data['nameservers'] ?? [] as $server) {
        $name = strtolower($server['ldhName'] ?? '');
        if ($name) $ns[] = $name;
    }
    return $ns;
}


function parseDnssec(array $data): ?string
{
    $delegationSigned = $data['secureDNS']['delegationSigned'] ?? null;
    if ($delegationSigned === null) return null;
    return $delegationSigned ? 'signed' : 'unsigned';
}


function findAbuseEmail(array $entity): ?string
{
    foreach ($entity['entities'] ?? [] as $sub) {
        $roles = array_map('strtolower', $sub['roles'] ?? []);
        if (in_array('abuse', $roles)) {
            $vcard = parseVcard($sub['vcardArray'][1] ?? []);
            return $vcard['email'] ?? null;
        }
    }
    return null;
}


function findAbusePhone(array $entity): ?string
{
    foreach ($entity['entities'] ?? [] as $sub) {
        $roles = array_map('strtolower', $sub['roles'] ?? []);
        if (in_array('abuse', $roles)) {
            $vcard = parseVcard($sub['vcardArray'][1] ?? []);
            return $vcard['tel'] ?? null;
        }
    }
    return null;
}
