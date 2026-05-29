<?php
// ============================================================
//  ThreatScope — includes/sources.php
//  All external intelligence source integrations
// ============================================================

require_once __DIR__ . '/functions.php';

// ─── MISP ─────────────────────────────────────────────────────
function query_misp(string $indicator, string $type, array $cfg): array {
    $type_map = [
        'IPv4 Address' => ['ip-src','ip-dst','ip-src|port','ip-dst|port'],
        'Domain'       => ['domain','hostname','domain|ip'],
        'Email Address'=> ['email-src','email-dst','email-src-display-name','email-subject','email-reply-to','whois-registrant-email'],
        'MD5 Hash'     => ['md5'],
        'SHA-1 Hash'   => ['sha1'],
        'SHA-256 Hash' => ['sha256'],
    ];

    $body = [
        'returnFormat'      => 'json',
        'value'             => $indicator,
        'type'              => $type_map[$type] ?? [],
        'includeEventTags'  => true,
        'includeContext'    => true,
        'limit'             => 20,
    ];

    $res = http_post(
        rtrim($cfg['url'], '/') . '/attributes/restSearch',
        $body,
        ['Authorization' => $cfg['api_key'], 'Accept' => 'application/json', 'Content-Type' => 'application/json'],
        $cfg['verify_ssl'] ?? false
    );

    if (!$res['ok']) {
        return source_error('MISP', $res['status'], $res['error']);
    }

    $attributes = $res['data']['response']['Attribute'] ?? [];
    if (empty($attributes)) {
        return ['source' => 'MISP', 'found' => false, 'verdict' => 'CLEAN', 'summary' => 'No matches found', 'matches' => []];
    }

    $matches = [];
    $all_tags = [];
    foreach ($attributes as $attr) {
        $tags = array_column($attr['Tag'] ?? [], 'name');
        $all_tags = array_merge($all_tags, $tags);
        $matches[] = [
            'value'      => $attr['value'],
            'type'       => $attr['type'],
            'category'   => $attr['category'],
            'comment'    => $attr['comment'] ?? '',
            'event_id'   => $attr['event_id'],
            'event_info' => $attr['Event']['info'] ?? '',
            'tags'       => $tags,
            'timestamp'  => date('c', (int)($attr['timestamp'] ?? 0)),
            'to_ids'     => $attr['to_ids'] ?? false,
        ];
    }

    $is_malicious = !empty(array_filter($all_tags, fn($t) =>
        str_contains($t, 'malicious') || str_contains($t, 'malware') || str_contains($t, 'tlp:red')
    ));

    $event_count = count(array_unique(array_column($matches, 'event_id')));
    return [
        'source'      => 'MISP',
        'found'       => true,
        'verdict'     => $is_malicious ? 'MALICIOUS' : 'SUSPICIOUS',
        'match_count' => count($matches),
        'matches'     => $matches,
        'summary'     => count($matches) . ' attribute match(es) across ' . $event_count . ' event(s)',
    ];
}

// ─── Elasticsearch ────────────────────────────────────────────
function query_elasticsearch(string $indicator, string $type, array $cfg): array {
    $index = $cfg['index'] ?: 'ioc-*';
    if ($type == 'Domain') {
      $domainindicator = '*' . $indicator . '*';
      $query = [
        'query' => [
            'query_string' => [
                'query' => $domainindicator,
                'fields' => ['threat.indicator.name', 'stix.value']
            ],
        ],
        'size' => 10,
        'sort' => [['@timestamp' => ['order' => 'desc']]],
      ];
    } else {
      $query = [
        'query' => [
            'bool' => [
                'should' => [
                    ['match' => ['threat.indicator.name'   => $indicator]],
                    ['match' => ['stix.value'              => $indicator]],
                ],
                'minimum_should_match' => 1,
            ],
        ],
        'size' => 10,
        'sort' => [['@timestamp' => ['order' => 'desc']]],
      ];
    }

    $res = http_post(
        rtrim($cfg['url'], '/') . "/$index/_search",
        $query,
        ['Authorization' => 'ApiKey ' . $cfg['api_key'], 'Content-Type' => 'application/json'],
        false
    );

    if (!$res['ok']) {
        return source_error('Elasticsearch', $res['status'], $res['error']);
    }

    $hits = $res['data']['hits']['hits'] ?? [];
    if (empty($hits)) {
        return ['source' => 'Elasticsearch', 'found' => false, 'verdict' => 'CLEAN', 'summary' => 'No IOC matches in ' . $index, 'matches' => []];
    }

    $matches = [];
    $kiburl = $config['kib_url']
    foreach ($hits as $hit) {
        $src = $hit['_source'];
        $format_index = urlencode($hit['_index']);
        $format_id = urlencode($hit['_id']);
        $matches[] = [
            'indicator'    => $src['threat']['indicator']['name'] ?? $src['stix']['value'] ?? $indicator,
            'type'         => $src['threat']['indicator']['type'] ?? $src['stix']['type'] ?? $type,
            'threat_level' => $src['threat']['indicator']['confidence'] ?? $src['threat_level'] ?? $src['severity'] ?? 'unknown',
            'tags'         => $src['tags'] ?? $src['labels'] ?? [],
            'source'       => $src['threat']['indicator']['provider'] ?? $src['feed'] ?? 'unknown',
            'first_seen'   => $src['indicator']['first_seen'] ?? $src['first_seen'] ?? null,
            'last_seen'    => $src['indicator']['last_seen'] ?? $src['last_seen'] ?? null,
            'description'  => $src['description'] ?? $src['threat']['feed']['name'] ?? '',
            'details'      => '<a href="' . $kiburl . '/app/discover#/doc/security-solution-default/' . $format_index . '?id=' . $format_id . '">Details</a>',
        ];
    }

    $levels = ['critical' => 4, 'high' => 3, 'medium' => 2, 'low' => 1, 'unknown' => 0];
    $top = array_reduce($matches, function($carry, $m) use ($levels) {
        return ($levels[$m['threat_level']] ?? 0) > ($levels[$carry] ?? 0) ? $m['threat_level'] : $carry;
    }, 'unknown');

    $total = $res['data']['hits']['total']['value'] ?? count($hits);
    return [
        'source'      => 'Elasticsearch',
        'found'       => true,
        'verdict'     => in_array($top, ['critical','high']) ? 'MALICIOUS' : 'SUSPICIOUS',
        'match_count' => count($hits),
        'matches'     => $matches,
        'summary'     => count($hits) . ' IOC match(es) in ' . $index . " ($total total)",
    ];
}

// ─── VirusTotal ────────────────────────────────────────────────
function query_virustotal(string $indicator, string $type, string $api_key): array {
    $endpoints = [
        'IPv4 Address' => "https://www.virustotal.com/api/v3/ip_addresses/$indicator",
        'Domain'       => "https://www.virustotal.com/api/v3/domains/$indicator",
        'MD5 Hash'     => "https://www.virustotal.com/api/v3/files/$indicator",
        'SHA-1 Hash'   => "https://www.virustotal.com/api/v3/files/$indicator",
        'SHA-256 Hash' => "https://www.virustotal.com/api/v3/files/$indicator",
    ];

    if (!isset($endpoints[$type])) {
        return source_error('VirusTotal', 0, 'Unsupported type');
    }

    $res = http_get($endpoints[$type], ['x-apikey' => $api_key]);

    if (!$res['ok']) {
        return source_error('VirusTotal', $res['status'], $res['error']);
    }

    $attrs = $res['data']['data']['attributes'] ?? [];
    $stats = $attrs['last_analysis_stats'] ?? [];
    $malicious  = (int)($stats['malicious']  ?? 0);
    $suspicious = (int)($stats['suspicious'] ?? 0);
    $harmless   = (int)($stats['harmless']   ?? 0);
    $undetected = (int)($stats['undetected'] ?? 0);
    $total      = $malicious + $suspicious + $harmless + $undetected;

    $verdict = $malicious > 5 ? 'MALICIOUS' : ($malicious > 0 || $suspicious > 3 ? 'SUSPICIOUS' : 'CLEAN');

    // Top detections
    $analysis  = $attrs['last_analysis_results'] ?? [];
    $detections = [];
    foreach ($analysis as $engine => $result) {
        if (in_array($result['category'] ?? '', ['malicious','suspicious'])) {
            $detections[] = ['engine' => $engine, 'category' => $result['category'], 'result' => $result['result'] ?? ''];
        }
    }
    $detections = array_slice($detections, 0, 10);

    // Type-specific enrichment
    $enrichment = [];
    if ($type === 'IPv4 Address') {
        $enrichment = [
            'country'    => $attrs['country'] ?? null,
            'asn'        => $attrs['asn'] ?? null,
            'as_owner'   => $attrs['as_owner'] ?? null,
            'network'    => $attrs['network'] ?? null,
            'reputation' => $attrs['reputation'] ?? null,
        ];
    } elseif ($type === 'Domain') {
        $enrichment = [
            'registrar'    => $attrs['registrar'] ?? null,
            'created'      => isset($attrs['creation_date']) ? date('Y-m-d', $attrs['creation_date']) : null,
            'reputation'   => $attrs['reputation'] ?? null,
            'categories'   => $attrs['categories'] ? implode(', ', array_values($attrs['categories'])) : null,
        ];
    } else {
        $enrichment = [
            'name'           => $attrs['meaningful_name'] ?? ($attrs['names'][0] ?? null),
            'type'           => $attrs['type_description'] ?? null,
            'size'           => isset($attrs['size']) ? round($attrs['size'] / 1024, 1) . ' KB' : null,
            'md5'            => $attrs['md5'] ?? null,
            'sha1'           => $attrs['sha1'] ?? null,
            'sha256'         => $attrs['sha256'] ?? null,
            'first_seen'     => isset($attrs['first_submission_date']) ? date('Y-m-d', $attrs['first_submission_date']) : null,
            'last_analysed'  => isset($attrs['last_analysis_date']) ? date('Y-m-d', $attrs['last_analysis_date']) : null,
            'tags'           => $attrs['tags'] ?? [],
        ];
    }

    $gui_type = $type === 'IPv4 Address' ? 'ip-address' : ($type === 'Domain' ? 'domain' : 'file');
    return [
        'source'     => 'VirusTotal',
        'found'      => true,
        'verdict'    => $verdict,
        'stats'      => compact('malicious','suspicious','harmless','undetected','total'),
        'detections' => $detections,
        'enrichment' => $enrichment,
        'vt_link'    => "https://www.virustotal.com/gui/$gui_type/$indicator",
        'summary'    => "$malicious/$total engines flagged as malicious",
        'matches'    => [],
    ];
}

// ─── GreyNoise ────────────────────────────────────────────────
function query_greynoise(string $indicator, string $type, string $api_key): array {
    if ($type !== 'IPv4 Address') {
        return ['source' => 'GreyNoise', 'skipped' => true, 'reason' => 'GreyNoise only supports IPv4 lookups'];
    }

    $res = http_get(
        "https://api.greynoise.io/v3/noise/context/$indicator",
        ['key' => $api_key]
    );

    if ($res['status'] === 404) {
        return ['source' => 'GreyNoise', 'found' => false, 'verdict' => 'CLEAN', 'noise' => false, 'riot' => false, 'summary' => 'IP not observed in internet-wide scan data', 'matches' => []];
    }

    if (!$res['ok']) {
        // Try community endpoint
        $res2 = http_get("https://api.greynoise.io/v3/community/$indicator", ['key' => $api_key]);
        if (!$res2['ok']) return source_error('GreyNoise', $res['status'], $res['error']);
        $res = $res2;
    }

    $d = $res['data'];
    $classification = $d['classification'] ?? 'unknown';
    $verdict = $classification === 'malicious' ? 'MALICIOUS' : ($classification === 'benign' ? 'CLEAN' : ($d['noise'] ? 'SUSPICIOUS' : 'CLEAN'));

    return [
        'source'         => 'GreyNoise',
        'found'          => true,
        'verdict'        => $verdict,
        'noise'          => $d['noise'] ?? false,
        'riot'           => $d['riot'] ?? false,
        'classification' => $classification,
        'name'           => $d['name'] ?? null,
        'last_seen'      => $d['last_seen'] ?? null,
        'first_seen'     => $d['first_seen'] ?? null,
        'country'        => $d['metadata']['country'] ?? null,
        'city'           => $d['metadata']['city'] ?? null,
        'organization'   => $d['metadata']['organization'] ?? null,
        'asn'            => $d['metadata']['asn'] ?? null,
        'os'             => $d['metadata']['os'] ?? null,
        'tags'           => $d['tags'] ?? [],
        'cve'            => $d['cve'] ?? [],
        'summary'        => ($d['noise'] ?? false)
            ? "Observed in internet scanning — $classification classification"
            : 'Not observed in background noise scanning',
        'matches'        => [],
    ];
}

// ─── GeoIP ────────────────────────────────────────────────────
function query_geoip(string $ip, array $cfg): array {
    if ($cfg['provider'] === 'maxmind' && !empty($cfg['maxmind_key'])) {
        return query_geoip_maxmind($ip, $cfg['maxmind_key']);
    }
    return query_geoip_ipapi($ip);
}

function query_geoip_ipapi(string $ip): array {
    $fields = 'status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,hosting,proxy,mobile';
    $res = http_get("http://ip-api.com/json/$ip?fields=$fields");

    if (!$res['ok'] || ($res['data']['status'] ?? '') === 'fail') {
        return ['source' => 'GeoIP', 'found' => false, 'error' => $res['data']['message'] ?? 'Lookup failed'];
    }

    $d = $res['data'];
    return [
        'source'       => 'GeoIP',
        'found'        => true,
        'provider'     => 'ip-api.com',
        'country'      => $d['country'] ?? null,
        'country_code' => $d['countryCode'] ?? null,
        'region'       => $d['regionName'] ?? null,
        'city'         => $d['city'] ?? null,
        'postal_code'  => $d['zip'] ?? null,
        'lat'          => $d['lat'] ?? null,
        'lon'          => $d['lon'] ?? null,
        'timezone'     => $d['timezone'] ?? null,
        'isp'          => $d['isp'] ?? null,
        'org'          => $d['org'] ?? null,
        'asn'          => $d['as'] ?? null,
        'asn_name'     => $d['asname'] ?? null,
        'rdns'         => $d['reverse'] ?? null,
        'hosting'      => $d['hosting'] ?? false,
        'proxy'        => $d['proxy'] ?? false,
        'mobile'       => $d['mobile'] ?? false,
    ];
}

function query_geoip_maxmind(string $ip, string $key): array {
    $parts = explode(':', $key, 2);
    $account_id = $parts[0]; $license = $parts[1] ?? '';
    $auth = base64_encode("$account_id:$license");

    $res = http_get(
        "https://geoip.maxmind.com/geoip/v2.1/city/$ip",
        ['Authorization' => "Basic $auth"]
    );

    if (!$res['ok']) return ['source' => 'GeoIP', 'found' => false, 'error' => 'MaxMind lookup failed'];

    $d = $res['data'];
    return [
        'source'       => 'GeoIP',
        'found'        => true,
        'provider'     => 'MaxMind',
        'country'      => $d['country']['names']['en'] ?? null,
        'country_code' => $d['country']['iso_code'] ?? null,
        'region'       => $d['subdivisions'][0]['names']['en'] ?? null,
        'city'         => $d['city']['names']['en'] ?? null,
        'postal_code'  => $d['postal']['code'] ?? null,
        'lat'          => $d['location']['latitude'] ?? null,
        'lon'          => $d['location']['longitude'] ?? null,
        'timezone'     => $d['location']['time_zone'] ?? null,
        'org'          => $d['traits']['organization'] ?? null,
        'asn'          => isset($d['traits']['autonomous_system_number']) ? 'AS' . $d['traits']['autonomous_system_number'] : null,
        'asn_name'     => $d['traits']['autonomous_system_organization'] ?? null,
        'isp'          => $d['traits']['isp'] ?? null,
        'hosting'      => $d['traits']['is_hosting_provider'] ?? false,
        'proxy'        => ($d['traits']['is_anonymous_proxy'] ?? false) || ($d['traits']['is_tor_exit_node'] ?? false),
    ];
}

// ─── WHOIS (via RDAP with fallback chain) ─────────────────────
function query_whois(string $indicator, string $type): array {
    if ($type === 'Email Address') {
        return ['source' => 'WHOIS', 'found' => false, 'skipped' => true, 'reason' => 'WHOIS not applicable for email addresses'];
    }
    if (is_hash($type)) {
        return ['source' => 'WHOIS', 'found' => false, 'skipped' => true, 'reason' => 'WHOIS not applicable for file hashes'];
    }

    if ($type === 'IPv4 Address') {
        return whois_ip($indicator);
    }
    if ($type == 'Domain') {
        return whois_domain($indicator);
    }
    return ['source' => 'WHOIS', 'found' => false, 'skipped' => true, 'reason' => 'Unknown Data Type'];
}

function whois_ip(string $ip): array {
    // Try ARIN first, then RDAP bootstrap
    $urls = [
        "https://rdap.arin.net/registry/ip/$ip",
        "https://rdap.db.ripe.net/ip/$ip",
        "https://rdap.apnic.net/ip/$ip",
    ];

    $res = null;
    $tried = [];
    foreach ($urls as $url) {
        $r = http_get($url, [], false, 10);
        $tried[] = $url;
        if ($r['ok'] && is_array($r['data'])) { $res = $r; break; }
        // 404 from ARIN means not in ARIN — try next RIR
        if ($r['status'] !== 404 && $r['status'] !== 0) break;
    }

    if (!$res || !$res['ok']) {
        return [
            'source'        => 'WHOIS',
            'found'         => false,
            'error'         => true,
            'error_message' => 'RDAP lookup failed for this IP — all RIR endpoints returned errors',
        ];
    }

    $d      = $res['data'];
    $events = $d['events'] ?? [];
    $get_event = fn(string $a) => array_reduce($events, fn($c, $e) =>
        ($e['eventAction'] ?? '') === $a ? substr($e['eventDate'] ?? '', 0, 10) : $c, null);

    // Dig registrant from nested entities
    $registrant = null;
    foreach ($d['entities'] ?? [] as $e) {
        if (in_array('registrant', $e['roles'] ?? []) || in_array('administrative', $e['roles'] ?? [])) {
            foreach ($e['vcardArray'][1] ?? [] as $v) {
                if ($v[0] === 'fn') { $registrant = $v[3]; break 2; }
            }
        }
    }

    return [
        'source'     => 'WHOIS',
        'found'      => true,
        'provider'   => 'RDAP',
        'record_type'=> 'IP Network',
        'handle'     => $d['handle'] ?? null,
        'network'    => trim(($d['startAddress'] ?? '') . ' – ' . ($d['endAddress'] ?? ''), ' –'),
        'name'       => $d['name'] ?? null,
        'country'    => $d['country'] ?? null,
        'org'        => $registrant,
        'registered' => $get_event('registration'),
        'updated'    => $get_event('last changed'),
        'type'       => $d['ipVersion'] ?? ($d['ipVersion'] ? ['IPv' . $d['ipVersion']] : []),
    ];
}

function whois_domain(string $domain): array {

    $domain = strtolower(trim($domain));
    $tld    = substr($domain, strrpos($domain, '.') + 1);

    // Get RDAP base URL from IANA bootstrap
    $bootstrap = rdapFetch('https://data.iana.org/rdap/dns.json');
    if (!$bootstrap) {
        return ['error' => 'Failed to fetch IANA RDAP bootstrap data'];
    }

    $rdapBase = null;
    foreach ($bootstrap['services'] as $service) {
        if (in_array($tld, $service[0])) {
            $rdapBase = rtrim($service[1][0], '/');
            break;
        }
    }

    if (!$rdapBase) {
        return [
            'source'        => 'WHOIS',
            'found'         => false,
            'error'         => true,
            'error_message' => 'RDAP lookup failed — No RDAP server found for .' . $tld,
        ];
    }

    // Query the registry directly
    $data = rdapFetch("{$rdapBase}/domain/{$domain}");
    if (!$data) {
        return [
            'source'        => 'WHOIS',
            'found'         => false,
            'error'         => true,
            'error_message' => 'RDAP lookup failed — Failed to fetch RDAP data for ' . $domain,
        ];
    }

    return [
        'source'      => 'WHOIS',
        'found'       => true,
        'provider'    => $rdapBase,
        'record_type' => 'Domain',
        'status'      => implode('<br>', $data['status']) ?? [],
        'registrar'   => implode('<br>', parseRegistrar($data)) ?? 'Unknown',
        'registrant'  => parseContact($data, 'registrant') ?? 'REDACTED (privacy protection)',
        'registered'  => parseDates($data)['created'] ?? 'Unkown',
        'expires'     => parseDates($data)['expires'] ?? 'Unkown',
        'updated'     => parseDates($data)['updated'] ?? 'Unkown',
        'nameservers' => implode('<br>', parseNameservers($data)),
        'dnssec'      => parseDnssec($data),
        'admin_email' => parseContact($data, 'administrative') ?? 'Unknown',
        'tech_email'  => parseContact($data, 'technical') ?? 'Unknown',
        'abuse_email' => parseRegistrar($data)['abuse_email'] ?? 'Unkown',
    ];
}

// ─── Helper: standardised error result ────────────────────────
function source_error(string $source, int $status, string $error): array {
    $message = match(true) {
        $status === 401 => 'Authentication failed — check API key',
        $status === 403 => 'Access forbidden — check permissions',
        $status === 404 => 'Indicator not found in this source',
        $status === 429 => 'Rate limit exceeded',
        default         => "Query failed: $error",
    };
    return ['source' => $source, 'error' => true, 'error_message' => $message, 'found' => false, 'verdict' => null, 'matches' => []];
}

// ─── Email: public blacklist checks ───────────────────────────
/**
 * Checks an email address against multiple free public reputation sources:
 *   - SURBL (domain in email checked via DNS)
 *   - Spamhaus DBL (domain blacklist via DNS)
 *   - StopForumSpam API (known spam registrant emails)
 *   - HaveIBeenPwned API (data breach exposure — optional key)
 *   - EmailRep.io (free reputation API)
 *   - Abstract disposable email detection (free tier)
 */
function query_email_blacklists(string $email, ?string $hibp_key = null): array {
    $parts  = explode('@', strtolower($email), 2);
    $user   = $parts[0];
    $domain = $parts[1] ?? '';
    $matches = [];
    $verdicts = [];

    // ── 1. DNS-based SURBL check on email domain ──────────────
    $surbl_lookup = $domain . '.multi.surbl.org';
    $surbl_hit    = checkdnsrr($surbl_lookup, 'A');
    if ($surbl_hit) {
        $matches[]  = ['list' => 'SURBL', 'type' => 'Domain blacklist', 'detail' => "$domain listed in SURBL multi blocklist", 'severity' => 'high'];
        $verdicts[] = 'MALICIOUS';
    }

    // ── 2. Spamhaus DBL check on email domain ─────────────────
    $dbl_lookup = $domain . '.dbl.spamhaus.org';
    $dbl_hit    = checkdnsrr($dbl_lookup, 'A');
    if ($dbl_hit) {
        // Resolve to get specific list code
        $dbl_ip = gethostbyname($dbl_lookup);
        $dbl_meaning = match(true) {
            str_starts_with($dbl_ip, '127.0.1.2')  => 'Spammed domain',
            str_starts_with($dbl_ip, '127.0.1.4')  => 'Phishing domain',
            str_starts_with($dbl_ip, '127.0.1.5')  => 'Malware domain',
            str_starts_with($dbl_ip, '127.0.1.6')  => 'Botnet C&C domain',
            str_starts_with($dbl_ip, '127.0.1.102') => 'Abused legit spam domain',
            default => 'Listed in Spamhaus DBL',
        };
        $matches[]  = ['list' => 'Spamhaus DBL', 'type' => 'Domain blacklist', 'detail' => "$domain — $dbl_meaning", 'severity' => 'high'];
        $verdicts[] = 'MALICIOUS';
    }

    // ── 3. StopForumSpam — checks full email address ──────────
    $sfs_res = http_get("https://api.stopforumspam.org/api?email=" . urlencode($email) . "&json=1");
    if ($sfs_res['ok'] && isset($sfs_res['data']['email'])) {
        $sfs = $sfs_res['data']['email'];
        if (!empty($sfs['appears'])) {
            $freq  = $sfs['frequency'] ?? 0;
            $lastseen = $sfs['lastseen'] ?? 'unknown';
            $matches[]  = ['list' => 'StopForumSpam', 'type' => 'Spam/Abuse registry', 'detail' => "Reported $freq time(s), last seen $lastseen", 'severity' => 'medium'];
            $verdicts[] = $freq > 5 ? 'MALICIOUS' : 'SUSPICIOUS';
        }
    }

    // ── 4. EmailRep.io — free reputation API ─────────────────
    $erep_res = http_get(
        "https://emailrep.io/" . urlencode($email),
        ['User-Agent' => 'ThreatScope/1.0', 'Key' => 'anonymous']
    );
    $erep_data = null;
    if ($erep_res['ok'] && is_array($erep_res['data'])) {
        $erep = $erep_res['data'];
        $erep_data = [
            'reputation'    => $erep['reputation'] ?? 'unknown',
            'suspicious'    => $erep['suspicious'] ?? false,
            'references'    => $erep['references'] ?? 0,
            'blacklisted'   => $erep['details']['blacklisted'] ?? false,
            'malicious_activity' => $erep['details']['malicious_activity'] ?? false,
            'credentials_leaked' => $erep['details']['credentials_leaked'] ?? false,
            'data_breach'   => $erep['details']['data_breach'] ?? false,
            'disposable'    => $erep['details']['disposable'] ?? false,
            'free_provider' => $erep['details']['free_provider'] ?? false,
            'profiles'      => $erep['details']['profiles'] ?? [],
            'first_seen'    => $erep['details']['first_seen'] ?? null,
            'last_seen'     => $erep['details']['last_seen'] ?? null,
            'days_since_domain_creation' => $erep['details']['days_since_domain_creation'] ?? null,
            'spam'          => $erep['details']['spam'] ?? false,
        ];

        if ($erep_data['blacklisted'] || $erep_data['malicious_activity']) {
            $matches[]  = ['list' => 'EmailRep.io', 'type' => 'Email reputation', 'detail' => "Reputation: {$erep_data['reputation']} — blacklisted/malicious activity flagged", 'severity' => 'high'];
            $verdicts[] = 'MALICIOUS';
        } elseif ($erep_data['suspicious'] || $erep_data['spam']) {
            $matches[]  = ['list' => 'EmailRep.io', 'type' => 'Email reputation', 'detail' => "Reputation: {$erep_data['reputation']} — flagged as suspicious/spam", 'severity' => 'medium'];
            $verdicts[] = 'SUSPICIOUS';
        } elseif ($erep_data['disposable']) {
            $matches[]  = ['list' => 'EmailRep.io', 'type' => 'Disposable email', 'detail' => "Disposable/temporary email provider detected", 'severity' => 'low'];
            $verdicts[] = 'SUSPICIOUS';
        }

        if ($erep_data['credentials_leaked'] || $erep_data['data_breach']) {
            $matches[] = ['list' => 'EmailRep.io', 'type' => 'Credential leak', 'detail' => 'Credentials or data associated with this email have been leaked', 'severity' => 'medium'];
            if (empty($verdicts)) $verdicts[] = 'SUSPICIOUS';
        }
    }

    // ── 5. HaveIBeenPwned (optional — requires API key) ──────
    $hibp_data = null;
    if ($hibp_key) {
        $hibp_res = http_get(
            "https://haveibeenpwned.com/api/v3/breachedaccount/" . urlencode($email) . "?truncateResponse=false",
            ['hibp-api-key' => $hibp_key, 'User-Agent' => 'ThreatScope/1.0']
        );
        if ($hibp_res['ok'] && is_array($hibp_res['data'])) {
            $breaches    = $hibp_res['data'];
            $breach_names = array_column($breaches, 'Name');
            $breach_dates = array_column($breaches, 'BreachDate');
            $total_pwn    = count($breaches);
            $hibp_data = [
                'breach_count' => $total_pwn,
                'breaches'     => array_map(fn($b) => [
                    'name'        => $b['Name'],
                    'date'        => $b['BreachDate'],
                    'description' => strip_tags($b['Description'] ?? ''),
                    'data_classes'=> $b['DataClasses'] ?? [],
                    'is_sensitive'=> $b['IsSensitive'] ?? false,
                ], array_slice($breaches, 0, 10)),
            ];
            $matches[] = [
                'list'     => 'HaveIBeenPwned',
                'type'     => 'Data breach',
                'detail'   => "Found in $total_pwn breach(es): " . implode(', ', array_slice($breach_names, 0, 5)) . ($total_pwn > 5 ? '…' : ''),
                'severity' => $total_pwn > 3 ? 'high' : 'medium',
            ];
            $verdicts[] = 'SUSPICIOUS';
        } elseif ($hibp_res['status'] === 404) {
            // Not found in any breach — good
            $hibp_data = ['breach_count' => 0, 'breaches' => []];
        }
    }

    // ── 6. Disposable email domain check (DNS-free heuristic) ─
    $disposable_domains = [
        'mailinator.com','guerrillamail.com','guerrillamail.net','trashmail.com',
        'temp-mail.org','throwam.com','yopmail.com','sharklasers.com','guerrillamailblock.com',
        'grr.la','guerrillamail.info','guerrillamail.biz','guerrillamail.de','guerrillamail.org',
        'spam4.me','10minutemail.com','10minutemail.net','tempr.email','dispostable.com',
        'mailnull.com','spamgourmet.com','trashmail.at','trashmail.io','trashmail.me',
        'maildrop.cc','harakirimail.com','spamherelots.com','fakeinbox.com','throwam.com',
        'tempmailaddress.com','getairmail.com','discard.email','spamfree24.org',
    ];
    if (in_array($domain, $disposable_domains)) {
        $already_flagged = !empty(array_filter($matches, fn($m) => $m['list'] === 'EmailRep.io' && str_contains($m['type'], 'Disposable')));
        if (!$already_flagged) {
            $matches[]  = ['list' => 'Disposable DB', 'type' => 'Disposable email', 'detail' => "$domain is a known disposable/temporary email provider", 'severity' => 'low'];
            $verdicts[] = 'SUSPICIOUS';
        }
    }

    // ── Determine overall verdict ─────────────────────────────
    $overall = 'CLEAN';
    if (in_array('MALICIOUS', $verdicts))   $overall = 'MALICIOUS';
    elseif (in_array('SUSPICIOUS', $verdicts)) $overall = 'SUSPICIOUS';

    // ── Domain-level enrichment ────────────────────────────────
    $mx_records = [];
    if (getmxrr($domain, $mx_hosts)) {
        $mx_records = array_slice($mx_hosts, 0, 3);
    }

    $domain_age_label = null;
    if ($erep_data && isset($erep_data['days_since_domain_creation'])) {
        $days = (int)$erep_data['days_since_domain_creation'];
        $domain_age_label = $days < 30 ? "⚠ Very new ($days days)" : ($days < 180 ? "New ($days days)" : "$days days old");
    }

    return [
        'source'      => 'Email Blacklists',
        'found'       => !empty($matches),
        'verdict'     => $overall,
        'match_count' => count($matches),
        'matches'     => $matches,
        'email_data'  => [
            'address'     => $email,
            'local_part'  => $user,
            'domain'      => $domain,
            'mx_records'  => $mx_records,
            'domain_age'  => $domain_age_label,
        ],
        'emailrep'    => $erep_data,
        'hibp'        => $hibp_data,
        'surbl_hit'   => $surbl_hit,
        'dbl_hit'     => $dbl_hit,
        'summary'     => !empty($matches)
            ? count($matches) . ' blacklist hit(s) — ' . $overall
            : 'No blacklist matches found',
    ];
}
