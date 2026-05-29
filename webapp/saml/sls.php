<?php
// ============================================================
//  ThreatScope — saml/sls.php  (Single Logout Service)
//
//  Handles both SP-initiated and IdP-initiated Single Logout.
//
//  SP-initiated: User clicks logout in ThreatScope →
//    index.php?logout=1 → this file sends LogoutRequest to Okta →
//    Okta redirects back here with LogoutResponse →
//    session destroyed → redirect to login page
//
//  IdP-initiated: Okta admin forces logout →
//    Okta sends LogoutRequest here →
//    session destroyed → redirect to login page
//
//  URL must match what you configured in Okta:
//    Single Logout URL: https://YOUR-DOMAIN/saml/sls.php
// ============================================================

require_once __DIR__ . '/../includes/functions.php';
require_once __DIR__ . '/saml_helper.php';

ts_session_start();

$username = $_SESSION['ts_user'] ?? 'unknown';

try {
    $auth = saml_get_auth();

    // processSLO() handles both the request and response sides.
    // The callback runs after the local session is cleared.
    $auth->processSLO(
        false,       // $keep_local_session — false = destroy PHP session
        null,        // $requestId
        false,       // $retrieveParametersFromServer
        function() use ($username) {
            // Called after Okta confirms logout
            error_log("[ThreatScope SAML] SLO complete for: $username");
        }
    );

    $errors = $auth->getErrors();
    if (!empty($errors)) {
        error_log('[ThreatScope SAML] SLO errors: ' . implode(', ', $errors));
    }

    // Always redirect to login regardless of errors
    header('Location: ../index.php');
    exit;

} catch (Exception $e) {
    error_log('[ThreatScope SAML] SLS exception: ' . $e->getMessage());
    // Even on error, destroy the local session and redirect
    auth_logout();
    header('Location: ../index.php');
    exit;
}
