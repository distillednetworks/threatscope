<?php
// ============================================================
//  ThreatScope — saml/login.php
//  SP-initiated SSO: builds an AuthnRequest and redirects the
//  user's browser to Okta for authentication.
//
//  Entry point: linked from the login page and from auth_require()
// ============================================================

require_once __DIR__ . '/../includes/functions.php';
require_once __DIR__ . '/saml_helper.php';

ts_session_start();

// Already logged in — go straight to the app
if (auth_check()) {
    header('Location: ../index.php');
    exit;
}

// Store the originally requested URL so we can redirect back after SSO
if (!empty($_GET['return']) && filter_var($_GET['return'], FILTER_VALIDATE_URL) === false) {
    // Only allow relative paths
    $_SESSION['saml_return_url'] = ltrim($_GET['return'], '/');
}

try {
    $auth = saml_get_auth();
    // login() builds the AuthnRequest, sets the RelayState, and
    // issues a 302 redirect to Okta — execution stops here on success
    $auth->login();
} catch (Exception $e) {
    // Show a user-friendly error page rather than a raw stack trace
    $error = APP_ENV === 'development' ? htmlspecialchars($e->getMessage()) : 'SSO configuration error. Please contact your administrator.';
    http_response_code(500);
    include __DIR__ . '/error.php';
    exit;
}
