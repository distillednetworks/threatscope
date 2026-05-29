<?php
// ============================================================
//  ThreatScope — api/auth.php
// ============================================================
require_once __DIR__ . '/../includes/functions.php';
ts_session_start();
header('Content-Type: application/json');

$action = $_GET['action'] ?? '';

if ($action === 'login') {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') json_error('POST required', 405);
    if (!rate_limit_check('login', RATE_LIMIT_LOGIN, 900)) json_error('Too many login attempts. Try again in 15 minutes.', 429);

    $body = json_decode(file_get_contents('php://input'), true);
    $username = trim(strtolower($body['username'] ?? ''));
    $password = $body['password'] ?? '';

    if (!$username || !$password) json_error('Username and password required');
    if (auth_login($username, $password)) {
        json_response(['success' => true, 'user' => auth_user()]);
    } else {
        json_error('Invalid credentials', 401);
    }
}

if ($action === 'logout') {
    auth_logout();
    json_response(['success' => true]);
}

if ($action === 'check') {
    json_response(['authenticated' => auth_check(), 'user' => auth_check() ? auth_user() : null]);
}

json_error('Unknown action');
