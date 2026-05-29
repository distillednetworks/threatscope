<?php
require_once __DIR__ . '/../includes/functions.php';
ts_session_start();
header('Content-Type: application/json');
if (!auth_check()) json_error('Not authenticated', 401);

$method = $_SERVER['REQUEST_METHOD'];
$user   = auth_user();
$id     = trim($_GET['id'] ?? '');

// ── GET /api/history.php?id=xxx — fetch one full result ───────
if ($method === 'GET' && $id !== '') {
    $item = history_get_by_id($id);
    if (!$item) json_error('History item not found', 404);
    if ($user['role'] !== 'admin' && ($item['user'] ?? '') !== $user['username']) {
        json_error('Forbidden', 403);
    }
    json_response($item); // exits inside
}

// ── GET /api/history.php — list history ───────────────────────
if ($method === 'GET') {
    $filters = [
        'type'  => $_GET['type']  ?? '',
        'query' => $_GET['query'] ?? '',
        'limit' => $_GET['limit'] ?? 100,
        // Non-admins only see their own history
        'user'  => $user['role'] !== 'admin' ? $user['username'] : ($_GET['user'] ?? ''),
    ];
    $items = history_get($filters);

    // Strip the full result blob from list view — only needed on detail fetch
    $list = array_map(function(array $item): array {
        $out = $item;
        unset($out['result']);
        return $out;
    }, $items);

    json_response(['count' => count($list), 'items' => $list]); // exits inside
}

// ── DELETE /api/history.php — clear history ───────────────────
if ($method === 'DELETE') {
    $clear_user = $user['role'] !== 'admin' ? $user['username'] : null;
    history_clear($clear_user);
    json_response(['success' => true]); // exits inside
}

json_error('Method not allowed', 405);
