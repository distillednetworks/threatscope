<?php
// ============================================================
//  ThreatScope — saml/acs.php  (Assertion Consumer Service)
//
//  Okta POSTs the SAML response here after the user authenticates.
//  This endpoint:
//    1. Validates the SAML assertion cryptographically
//    2. Extracts user identity attributes
//    3. Maps Okta groups → ThreatScope role
//    4. Establishes a PHP session
//    5. Redirects to the application
//
//  URL must match exactly what you configured in Okta:
//    Single sign-on URL: https://YOUR-DOMAIN/saml/acs.php
// ============================================================

require_once __DIR__ . '/../includes/functions.php';
require_once __DIR__ . '/saml_helper.php';

ts_session_start();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    die('Method not allowed. This endpoint only accepts POST requests from Okta.');
}

if (empty($_POST['SAMLResponse'])) {
    http_response_code(400);
    $error = 'No SAMLResponse received. Access this page via your Okta application tile or login page.';
    include __DIR__ . '/error.php';
    exit;
}

try {
    $auth = saml_get_auth();
    $auth->processResponse();

    $errors = $auth->getErrors();
    if (!empty($errors)) {
        $detail = $auth->getLastErrorReason();
        error_log('[ThreatScope SAML] ACS errors: ' . implode(', ', $errors) . ' — ' . $detail);

        // In development show full error; in production show generic message
        $error = APP_ENV === 'production'
            ? 'SAML validation failed: ' . htmlspecialchars(implode(', ', $errors)) . ' (' . htmlspecialchars($detail) . ')'
            : 'Authentication failed. Please try again or contact your administrator.';
        http_response_code(401);
        include __DIR__ . '/error.php';
        exit;
    }

    if (!$auth->isAuthenticated()) {
        $error = 'SSO authentication was not confirmed. Please try again.';
        http_response_code(401);
        include __DIR__ . '/error.php';
        exit;
    }

    // ── Extract user attributes from the SAML assertion ──────────
    $attrs      = $auth->getAttributes();
    $cfg        = OKTA_SAML;

    // NameID is typically the user's email in Okta
    $name_id    = $auth->getNameId();

    // Helper: get first value of a SAML attribute or fallback
    $attr = function(string $key, string $fallback = '') use ($attrs, $cfg): string {
        $attr_name = $cfg[$key] ?? $key;
        $val = $attrs[$attr_name][0] ?? $attrs[$key][0] ?? '';
        return $val !== '' ? $val : $fallback;
    };

    $email      = $attr('attr_email', $name_id);
    $first_name = $attr('attr_first_name');
    $last_name  = $attr('attr_last_name');
    $groups     = $attrs[$cfg['attr_groups'] ?? 'groups'] ?? [];

    // Build display name: "First Last" or fall back to email local part
    $display_name = trim("$first_name $last_name");
    if ($display_name === '') {
        $display_name = explode('@', $email)[0];
    }

    // Username: use email address as the canonical identifier
    $username = strtolower(trim($email));
    if (empty($username)) {
        $error = 'Could not determine username from SAML response. Ensure the "email" attribute is configured in Okta.';
        http_response_code(400);
        include __DIR__ . '/error.php';
        exit;
    }

    // ── Map Okta groups to ThreatScope role ────────────────────
    $role = saml_map_role($groups);

    // ── Establish the session ──────────────────────────────────
    auth_establish_session($username, $role, $display_name, $email);

    // Log successful SSO login
    error_log("[ThreatScope SAML] Login: $username ($role) from " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));

    // ── Redirect ───────────────────────────────────────────────
    // Honor a stored return URL (e.g. from a deep-link before login)
    $return = $_SESSION['saml_return_url'] ?? '';
    unset($_SESSION['saml_return_url']);

    // Validate return URL is a safe relative path (prevent open redirect)
    $redirect = '../index.php';
    if ($return && preg_match('/^[a-zA-Z0-9_\-\/\.]+\.php$/', $return)) {
        $redirect = '../' . $return;
    }

    header('Location: ' . $redirect);
    exit;

} catch (Exception $e) {
    error_log('[ThreatScope SAML] ACS exception: ' . $e->getMessage());
    $error = APP_ENV === 'development'
        ? 'SAML exception: ' . htmlspecialchars($e->getMessage())
        : 'An unexpected error occurred during authentication. Please try again.';
    http_response_code(500);
    include __DIR__ . '/error.php';
    exit;
}
