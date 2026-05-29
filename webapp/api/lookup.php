<?php
// ============================================================
//  ThreatScope — api/lookup.php
//  Runs all configured intelligence sources in parallel via
//  curl_multi and returns aggregated results as JSON.
// ============================================================

require_once __DIR__ . '/../includes/functions.php';
require_once __DIR__ . '/../includes/sources.php';

ts_session_start();
header('Content-Type: application/json');

if (!auth_check())  json_error('Not authenticated', 401);
if ($_SERVER['REQUEST_METHOD'] !== 'POST') json_error('POST required', 405);
if (!rate_limit_check('lookup', RATE_LIMIT_LOOKUPS, 60)) json_error('Rate limit exceeded', 429);

$body = json_decode(file_get_contents('php://input'), true);
$indicator = trim($body['indicator'] ?? '');

if (empty($indicator)) json_error('indicator is required');

// Optional user-selected sources filter: array of source keys the user has enabled in the UI
$active_sources = isset($body['active_sources']) && is_array($body['active_sources'])
    ? array_map('strval', $body['active_sources'])
    : null; // null = no filter, use all configured sources

// Helper: check if a source key is active (either no filter, or key is in the list)
$source_active = function(string $key) use ($active_sources): bool {
    return $active_sources === null || in_array($key, $active_sources, true);
};

$type = detect_type($indicator);
if (!$type) json_error('Could not detect indicator type. Supported: IPv4, Domain, Email Address, MD5, SHA-1, SHA-256');

$user     = auth_user();
$settings = settings_load();
$is_hash  = is_hash($type);
$is_email = is_email($type);
$results  = [];

// ─── Run enabled sources ──────────────────────────────────────
if ($settings['misp']['enabled'] && $source_active('misp')) {
    try { $results[] = query_misp($indicator, $type, $settings['misp']); }
    catch (Exception $e) { $results[] = source_error('MISP', 0, $e->getMessage()); }
}

if ($settings['elasticsearch']['enabled'] && $source_active('elasticsearch')) {
    try { $results[] = query_elasticsearch($indicator, $type, $settings['elasticsearch']); }
    catch (Exception $e) { $results[] = source_error('Elasticsearch', 0, $e->getMessage()); }
}

// VirusTotal — not applicable for plain email addresses
if ($settings['virustotal']['enabled'] && !$is_email && $source_active('virustotal')) {
    try { $results[] = query_virustotal($indicator, $type, $settings['virustotal']['api_key']); }
    catch (Exception $e) { $results[] = source_error('VirusTotal', 0, $e->getMessage()); }
}

// GreyNoise — IP only (handled inside query_greynoise, but skip entirely for email/hash)
if ($settings['greynoise']['enabled'] && !$is_email && !$is_hash && $source_active('greynoise')) {
    try { $results[] = query_greynoise($indicator, $type, $settings['greynoise']['api_key']); }
    catch (Exception $e) { $results[] = source_error('GreyNoise', 0, $e->getMessage()); }
}

// Email blacklists — email only
if ($is_email) {
    try {
        $hibp_key = $settings['hibp']['api_key'] ?? null;
        $results[] = query_email_blacklists($indicator, $hibp_key ?: null);
    }
    catch (Exception $e) { $results[] = source_error('Email Blacklists', 0, $e->getMessage()); }
}

// GeoIP — IPv4 only
if ($type === 'IPv4 Address' && $settings['geoip']['enabled'] && $source_active('geoip')) {
    try { $geo_result = query_geoip($indicator, $settings['geoip']); }
    catch (Exception $e) { $geo_result = ['source' => 'GeoIP', 'found' => false, 'error' => $e->getMessage()]; }
}

// WHOIS — Check WhoIS or display incompatible
if ($settings['whois']['enabled'] && $source_active('whois')) {
    try { $whois_result = query_whois($indicator, $type); }
    catch (Exception $e) { $whois_result = ['source' => 'WHOIS', 'found' => false, 'error' => $e->getMessage(), 'error_detail' => $e->getMessage()]; }
}

if (empty($results) && empty($geo_result) && empty($whois_result)) {
    json_error('No intelligence sources configured. Go to Settings to add API keys.');
}

// ─── Aggregate ────────────────────────────────────────────────
$score      = calculate_score($results);
$risk_level = score_to_risk($score);

// Collect all tags
$all_tags = [];
$vt_result = null;
foreach ($results as $r) {
    if ($r['source'] === 'VirusTotal' && empty($r['error'])) $vt_result = $r;
    $all_tags = array_merge($all_tags, $r['enrichment']['tags'] ?? [], array_column($r['matches'] ?? [], 'tags')[0] ?? []);
    foreach ($r['matches'] ?? [] as $m) {
        $all_tags = array_merge($all_tags, $m['tags'] ?? []);
    }
    $all_tags = array_merge($all_tags, $r['tags'] ?? []);
}
$tags = array_values(array_unique(array_filter(array_slice($all_tags, 0, 15))));

$payload = [
    'indicator'  => $indicator,
    'type'       => $type,
    'queried_at' => date('c'),
    'score'      => $score,
    'risk_level' => $risk_level,
    'tags'       => $tags,
    'summary'    => [
        'sources_queried'    => count($results) + (!empty($geo_result) ? 1 : 0) + (!empty($whois_result) ? 1 : 0),
        'sources_matched'    => count(array_filter($results, fn($r) => !empty($r['found']) && empty($r['error']))),
        'malicious_signals'  => count(array_filter($results, fn($r) => ($r['verdict'] ?? '') === 'MALICIOUS')),
        'suspicious_signals' => count(array_filter($results, fn($r) => ($r['verdict'] ?? '') === 'SUSPICIOUS')),
    ],
    'ioc_results' => $results,
    'geo'         => $geo_result ?? null,
    'whois'       => $whois_result ?? null,
    'file_intel'  => ($is_hash && $vt_result) ? $vt_result['enrichment'] : null,
    'vt_stats'    => $vt_result['stats'] ?? null,
];

// ─── Save to history ──────────────────────────────────────────
$history_id = history_add([
    'query'            => $indicator,
    'query_type'       => $type,
    'user'             => $user['username'],
    'score'            => $score,
    'risk_level'       => $risk_level,
    'sources_queried'  => $payload['summary']['sources_queried'],
    'malicious_signals'=> $payload['summary']['malicious_signals'],
    'result'           => $payload,
]);

// history_add returns the ID on success; if the data dir is not writable
// it logs the error but we still return the lookup result to the user
$payload['history_id']    = $history_id;
$payload['history_saved'] = $history_id !== '';
echo json_encode($payload);
