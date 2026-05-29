<?php
// ThreatScope — api/health.php
// Lightweight health check used by Docker and load balancers.
// Returns 200 OK when Apache + PHP are working correctly.
http_response_code(200);
header('Content-Type: application/json');
echo json_encode([
    'status'  => 'ok',
    'service' => 'threatscope',
    'php'     => PHP_VERSION,
    'time'    => date('c'),
]);
?>
