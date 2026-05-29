<?php
// ============================================================
//  ThreatScope — saml/metadata.php
//
//  Generates the Service Provider metadata XML that you can
//  optionally upload to Okta instead of manually configuring
//  each field.
//
//  URL: https://YOUR-DOMAIN/saml/metadata.php
//
//  Usage in Okta:
//    Application → Sign On → "Identity Provider metadata" section
//    → Import from URL → paste this file's URL
// ============================================================

require_once __DIR__ . '/saml_helper.php';

use OneLogin\Saml2\Metadata;
use OneLogin\Saml2\Error;

try {
    $auth     = saml_get_auth();
    $settings = $auth->getSettings();
    $metadata = $settings->getSPMetadata();

    // Validate the generated metadata
    $errors = $settings->validateMetadata($metadata);
    if (!empty($errors)) {
        throw new Error('Invalid metadata: ' . implode(', ', $errors), Error::METADATA_SP_INVALID);
    }

    header('Content-Type: application/xml');
    header('Content-Disposition: inline; filename="threatscope-sp-metadata.xml"');
    // Prevent caching so Okta always gets the latest version
    header('Cache-Control: no-store, no-cache, must-revalidate');
    echo $metadata;

} catch (Exception $e) {
    http_response_code(500);
    header('Content-Type: text/plain');
    echo 'Metadata generation failed: ' . htmlspecialchars($e->getMessage()) . "\n";
    echo 'Check your OKTA_SAML configuration in config.php';
}
