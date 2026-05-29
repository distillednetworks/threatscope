<?php

function getDomainWhois(string $domain): array
{
    $domain = strtolower(trim($domain));
    $tld    = substr($domain, strrpos($domain, '.') + 1);

    // Step 1: Get RDAP base URL from IANA bootstrap
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
        return ['error' => "No RDAP server found for .{$tld}"];
    }

    // Step 2: Query the registry directly
    $data = rdapFetch("{$rdapBase}/domain/{$domain}");
    if (!$data) {
        return ['error' => "Failed to fetch RDAP data for {$domain}"];
    }

    // Step 3: Parse into clean array
    return parseRdapResponse($data);
}


function rdapFetch(string $url): ?array
{
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL            => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_TIMEOUT        => 15,
        CURLOPT_ENCODING       => '',
        CURLOPT_HTTPHEADER     => [
            'Accept: application/rdap+json, application/json',
            'Accept-Language: en-US,en;q=0.9',
        ],
    ]);

    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($httpCode !== 200 || !$response) {
        return null;
    }

    return json_decode($response, true) ?? null;
}


function parseRdapResponse(array $data): array
{
    $whois = [
        'domain'      => $data['ldhName']       ?? null,
        'status'      => $data['status']         ?? [],
        'dates'       => parseDates($data),
        'registrar'   => parseRegistrar($data),
        'registrant'  => parseContact($data, 'registrant'),
        'admin'       => parseContact($data, 'administrative'),
        'tech'        => parseContact($data, 'technical'),
        'nameservers' => parseNameservers($data),
        'dnssec'      => parseDnssec($data),
        'raw'         => $data,
    ];

    return array_filter($whois, fn($v) => $v !== null && $v !== []);
}


function parseDates(array $data): array
{
    $dates = [];
    $eventMap = [
        'registration' => 'created',
        'expiration'   => 'expires',
        'last changed' => 'updated',
        'last update of RDAP database' => 'rdap_updated',
    ];

    foreach ($data['events'] ?? [] as $event) {
        $action = strtolower($event['eventAction'] ?? '');
        $key    = $eventMap[$action] ?? $action;
        $dates[$key] = $event['eventDate'] ?? null;
    }

    return $dates;
}


function parseRegistrar(array $data): array
{
    foreach ($data['entities'] ?? [] as $entity) {
        $roles = array_map('strtolower', $entity['roles'] ?? []);
        if (!in_array('registrar', $roles)) continue;

        $vcard = parseVcard($entity['vcardArray'][1] ?? []);

        return array_filter([
            'name'   => $entity['fn']    ?? $vcard['fn']  ?? null,
            'iana_id'=> $entity['publicIds'][0]['identifier'] ?? null,
            'url'    => $entity['links'][0]['href']        ?? null,
            'email'  => $vcard['email']                    ?? null,
            'phone'  => $vcard['tel']                      ?? null,
            'abuse_email' => findAbuseEmail($entity),
            'abuse_phone' => findAbusePhone($entity),
        ]);
    }

    return [];
}


function parseContact(array $data, string $role): array
{
    foreach ($data['entities'] ?? [] as $entity) {
        $roles = array_map('strtolower', $entity['roles'] ?? []);
        if (!in_array($role, $roles)) continue;

        $vcard = parseVcard($entity['vcardArray'][1] ?? []);

        return array_filter([
            'name'         => $vcard['fn']           ?? null,
            'org'          => $vcard['org']           ?? null,
            'email'        => $vcard['email']         ?? null,
            'phone'        => $vcard['tel']           ?? null,
            'address'      => $vcard['adr']           ?? null,
            'country'      => $vcard['country']       ?? null,
            'city'         => $vcard['city']          ?? null,
            'state'        => $vcard['state']         ?? null,
            'postal_code'  => $vcard['postal_code']   ?? null,
            'redacted'     => !empty($entity['remarks']) ? true : null,
        ]);
    }

    return [];
}


function parseVcard(array $vcardProps): array
{
    $result = [];

    foreach ($vcardProps as $prop) {
        if (!is_array($prop) || count($prop) < 4) continue;

        [$name, $params, $type, $value] = $prop;

        switch (strtolower($name)) {
            case 'fn':
                $result['fn'] = is_array($value) ? implode(' ', $value) : $value;
                break;
            case 'org':
                $result['org'] = is_array($value) ? implode(', ', $value) : $value;
                break;
            case 'email':
                $result['email'] = is_array($value) ? $value[0] : $value;
                break;
            case 'tel':
                $result['tel'] = is_array($value) ? $value[0] : $value;
                break;
            case 'adr':
                if (is_array($value)) {
                    $result['adr']         = trim(implode(', ', array_filter($value)));
                    $result['city']        = $value[3] ?? null;
                    $result['state']       = $value[4] ?? null;
                    $result['postal_code'] = $value[5] ?? null;
                    $result['country']     = $value[6] ?? null;
                }
                break;
        }
    }

    return $result;
}


function parseNameservers(array $data): array
{
    $ns = [];
    foreach ($data['nameservers'] ?? [] as $server) {
        $name = strtolower($server['ldhName'] ?? '');
        if ($name) $ns[] = $name;
    }
    return $ns;
}


function parseDnssec(array $data): ?string
{
    $delegationSigned = $data['secureDNS']['delegationSigned'] ?? null;
    if ($delegationSigned === null) return null;
    return $delegationSigned ? 'signed' : 'unsigned';
}


function findAbuseEmail(array $entity): ?string
{
    foreach ($entity['entities'] ?? [] as $sub) {
        $roles = array_map('strtolower', $sub['roles'] ?? []);
        if (in_array('abuse', $roles)) {
            $vcard = parseVcard($sub['vcardArray'][1] ?? []);
            return $vcard['email'] ?? null;
        }
    }
    return null;
}


function findAbusePhone(array $entity): ?string
{
    foreach ($entity['entities'] ?? [] as $sub) {
        $roles = array_map('strtolower', $sub['roles'] ?? []);
        if (in_array('abuse', $roles)) {
            $vcard = parseVcard($sub['vcardArray'][1] ?? []);
            return $vcard['tel'] ?? null;
        }
    }
    return null;
}


// --- Usage ---
$result = getDomainWhois('espn.com');
print_r($result);
