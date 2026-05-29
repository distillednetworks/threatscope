<?php
require_once __DIR__ . '/../includes/functions.php';
require_once __DIR__ . '/../includes/sources.php';
ts_session_start();
header('Content-Type: application/json');
if (!auth_check()) json_error('Not authenticated', 401);

$user   = auth_user();
$method = $_SERVER['REQUEST_METHOD'];
$action = $_GET['action'] ?? '';

// GET settings (masked)
if ($method === 'GET' && !$action) {
    $s = settings_load();
    if (!empty($s['misp']['api_key']))          $s['misp']['api_key']          = mask_key($s['misp']['api_key']);
    if (!empty($s['elasticsearch']['api_key'])) $s['elasticsearch']['api_key'] = mask_key($s['elasticsearch']['api_key']);
    if (!empty($s['virustotal']['api_key']))    $s['virustotal']['api_key']    = mask_key($s['virustotal']['api_key']);
    if (!empty($s['greynoise']['api_key']))     $s['greynoise']['api_key']     = mask_key($s['greynoise']['api_key']);
    if (!empty($s['geoip']['maxmind_key']))     $s['geoip']['maxmind_key']     = mask_key($s['geoip']['maxmind_key']);
//    json_response($s);

    // Include data directory diagnostics so the UI can surface permission errors
    $data_dir      = dirname(HISTORY_FILE);
    $s['_diagnostics'] = [
        'data_dir'       => $data_dir,
        'data_dir_exists'  => is_dir($data_dir),
        'data_dir_writable'=> is_dir($data_dir) && is_writable($data_dir),
        'history_file_exists' => file_exists(HISTORY_FILE),
        'history_file_writable' => file_exists(HISTORY_FILE) ? is_writable(HISTORY_FILE) : is_writable($data_dir),
        'history_count'  => count(history_load()),
        'php_user'       => function_exists('posix_getpwuid') ? (posix_getpwuid(posix_geteuid())['name'] ?? 'unknown') : get_current_user(),
    ];

    json_response($s);
}

// PUT update settings (admin only)
if ($method === 'POST' && $action === 'save') {
    if ($user['role'] !== 'admin') json_error('Admin required', 403);
    $body = json_decode(file_get_contents('php://input'), true);
    if (!is_array($body)) json_error('Invalid body');
    settings_save($body);
    json_response(['success' => true]);
}

// POST test a source
if ($method === 'POST' && $action === 'test') {
    if ($user['role'] !== 'admin') json_error('Admin required', 403);
    $source = $_GET['source'] ?? '';
    $s      = settings_load();

    switch ($source) {
        case 'misp':
            if (empty($s['misp']['url']) || empty($s['misp']['api_key'])) {
                json_response(['success' => false, 'message' => 'URL and API key required']);
            }
            $res = http_get(rtrim($s['misp']['url'], '/') . '/servers/getVersion',
                ['Authorization' => $s['misp']['api_key'], 'Accept' => 'application/json'],
                $s['misp']['verify_ssl'] ?? false
            );
            if ($res['ok']) {
                json_response(['success' => true, 'message' => 'Connected — MISP v' . ($res['data']['version'] ?? 'unknown')]);
            } else {
                json_response(['success' => false, 'message' => 'Connection failed: HTTP ' . $res['status']]);
            }
            break;

        case 'elasticsearch':
            if (empty($s['elasticsearch']['url'])) json_response(['success' => false, 'message' => 'URL required']);
            $headers = !empty($s['elasticsearch']['api_key']) ? ['Authorization' => 'ApiKey ' . $s['elasticsearch']['api_key']] : [];
            $res = http_get(rtrim($s['elasticsearch']['url'], '/'), $headers, false);
            if ($res['ok']) {
                json_response(['success' => true, 'message' => 'Connected — Elasticsearch ' . ($res['data']['version']['number'] ?? 'unknown')]);
            } else {
                json_response(['success' => false, 'message' => 'Connection failed: HTTP ' . $res['status']]);
            }
            break;

        case 'virustotal':
            if (empty($s['virustotal']['api_key'])) json_response(['success' => false, 'message' => 'API key required']);
            $res = http_get('https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8', ['x-apikey' => $s['virustotal']['api_key']]);
            json_response(['success' => $res['ok'], 'message' => $res['ok'] ? 'VirusTotal API key valid' : 'Invalid API key: HTTP ' . $res['status']]);
            break;

        case 'greynoise':
            if (empty($s['greynoise']['api_key'])) json_response(['success' => false, 'message' => 'API key required']);
            $res = http_get('https://api.greynoise.io/ping', ['key' => $s['greynoise']['api_key']]);
            json_response(['success' => $res['ok'], 'message' => $res['ok'] ? 'GreyNoise API key valid' : 'Invalid API key: HTTP ' . $res['status']]);
            break;

        default:
            json_error('Unknown source');
    }
}

json_error('Not found', 404);
