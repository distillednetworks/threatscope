<?php
// ============================================================
//  ThreatScope — saml/saml_helper.php
//  Builds and returns a configured OneLogin\Saml2\Auth instance
//  using the OKTA_SAML values from config.php.
// ============================================================

require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../config.php';

use OneLogin\Saml2\Auth;
use OneLogin\Saml2\Utils;

function saml_get_auth(): Auth {
    $cfg = OKTA_SAML;

    $settings = [
        'strict' => $cfg['strict'],
        'debug'  => $cfg['debug'],

        // ── Service Provider (this app) ───────────────────────
        'sp' => [
            'entityId'                 => $cfg['sp_entity_id'],
            'assertionConsumerService' => [
                'url'     => $cfg['sp_acs_url'],
                'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
            ],
            'singleLogoutService'      => [
                'url'     => $cfg['sp_sls_url'],
                'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
            ],
            'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
            'x509cert'     => $cfg['sp_certificate']   ?? '',
            'privateKey'   => $cfg['sp_private_key']   ?? '',
        ],

        // ── Identity Provider (Okta) ──────────────────────────
        'idp' => [
            'entityId'            => $cfg['idp_entity_id'],
            'singleSignOnService' => [
                'url'     => $cfg['idp_sso_url'],
                'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
            ],
            'singleLogoutService' => [
                'url'     => $cfg['idp_slo_url'] ?: $cfg['idp_sso_url'],
                'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
            ],
            'x509cert' => $cfg['idp_x509_cert'],
        ],

        // ── Security ──────────────────────────────────────────
        'security' => [
            'nameIdEncrypted'         => false,
            'authnRequestsSigned'     => $cfg['authn_requests_signed'] ?? false,
            'logoutRequestSigned'     => false,
            'logoutResponseSigned'    => false,
            'signMetadata'            => false,
            'wantMessagesSigned'      => false,
            'wantAssertionsSigned'    => true,   // Okta signs assertions
            'wantNameId'              => true,
            'wantNameIdEncrypted'     => false,
            'wantAssertionsEncrypted' => false,
            'allowRepeatAttributeName'=> true,
            'rejectUnsolicitedResponsesWithInResponseTo' => false,
        ],
    ];

    return new Auth($settings);
}
