<?php
require_once __DIR__ . '/../includes/functions.php';
ts_session_start();
if (!auth_check()) { http_response_code(401); die('Not authenticated'); }

$format = $_GET['format'] ?? '';
$id     = $_GET['id'] ?? '';
$user   = auth_user();

// ─── CSV export of history ─────────────────────────────────────
if ($format === 'csv') {
    $filters = $user['role'] !== 'admin' ? ['user' => $user['username']] : [];
    $filters['limit'] = 500;
    $items = history_get($filters);

    header('Content-Type: text/csv');
    header('Content-Disposition: attachment; filename="threatscope-history-' . date('Ymd-His') . '.csv"');

    $out = fopen('php://output', 'w');
    fputcsv($out, ['Timestamp','Query','Type','Analyst','Score','Risk Level','Sources Queried','Malicious Signals']);
    foreach ($items as $item) {
        fputcsv($out, [
            $item['timestamp'], $item['query'], $item['query_type'],
            $item['user'], $item['score'], $item['risk_level'],
            $item['sources_queried'], $item['malicious_signals'],
        ]);
    }
    fclose($out);
    exit;
}

// ─── JSON export of a single result ───────────────────────────
if ($format === 'json' && $id) {
    $item = history_get_by_id($id);
    if (!$item) { http_response_code(404); die('Not found'); }
    if ($user['role'] !== 'admin' && $item['user'] !== $user['username']) { http_response_code(403); die('Forbidden'); }

    $safe_name = preg_replace('/[^a-z0-9_\-]/i', '_', $item['query']);
    header('Content-Type: application/json');
    header('Content-Disposition: attachment; filename="threatscope-' . $safe_name . '.json"');
    echo json_encode($item['result'], JSON_PRETTY_PRINT);
    exit;
}

// ─── PDF export ────────────────────────────────────────────────
if ($format === 'pdf' && $id) {
    $item = history_get_by_id($id);
    if (!$item) { http_response_code(404); die('Not found'); }
    if ($user['role'] !== 'admin' && $item['user'] !== $user['username']) { http_response_code(403); die('Forbidden'); }

    // Requires TCPDF or FPDF — check if TCPDF is available via Composer
    $tcpdf_path = __DIR__ . '/../vendor/tecnickcom/tcpdf/tcpdf.php';
    if (!file_exists($tcpdf_path)) {
        // Fallback: generate HTML that the browser can print-to-PDF
        generate_print_html($item);
        exit;
    }

    require_once $tcpdf_path;
    generate_tcpdf($item);
    exit;
}

function generate_print_html(array $item): void {
    $r          = $item['result'];
    $risk_colors = ['CRITICAL' => '#c0392b', 'HIGH' => '#e67e22', 'MEDIUM' => '#d29922', 'LOW' => '#27ae60'];
    $risk_color  = $risk_colors[$r['risk_level'] ?? ''] ?? '#666';
    $vd_colors   = ['MALICIOUS' => '#c0392b', 'SUSPICIOUS' => '#e67e22', 'CLEAN' => '#27ae60'];
    $safe_q      = htmlspecialchars($item['query']);
    $generated   = date('Y-m-d H:i:s T');

    header('Content-Type: text/html; charset=UTF-8');
    echo <<<HTML
<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>ThreatScope Report — {$safe_q}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=IBM+Plex+Sans:wght@400;500;600&display=swap');
  *{box-sizing:border-box;margin:0;padding:0} body{font-family:'IBM Plex Sans',sans-serif;font-size:13px;color:#111;background:#fff;padding:20px}
  .header{background:#0d1117;color:#58a6ff;padding:18px 24px;border-radius:6px;margin-bottom:18px;display:flex;justify-content:space-between;align-items:center}
  .header h1{font-size:16px;font-family:'JetBrains Mono',monospace;letter-spacing:.05em} .header .meta{font-size:10px;color:#8b949e;text-align:right}
  .indicator{background:#f4f6f8;border:1px solid #dde;border-radius:6px;padding:14px 18px;margin-bottom:14px}
  .indicator .value{font-family:'JetBrains Mono',monospace;font-size:18px;color:#0d1117;font-weight:600}
  .indicator .sub{font-size:11px;color:#666;margin-top:4px}
  .score-banner{display:flex;align-items:center;gap:14px;background:#f8f9fa;border:1px solid #dde;border-radius:6px;padding:14px 18px;margin-bottom:14px}
  .score-num{font-family:'JetBrains Mono',monospace;font-size:36px;font-weight:700;color:{$risk_color}}
  .section{margin-bottom:16px;border:1px solid #e0e0e0;border-radius:6px;overflow:hidden}
  .section-header{background:#f4f6f8;padding:8px 14px;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.07em;color:#444;border-bottom:1px solid #e0e0e0}
  .kv{display:flex;padding:6px 14px;border-bottom:1px solid #f0f0f0}
  .kv:last-child{border-bottom:none} .kv .k{color:#666;min-width:150px;font-size:12px} .kv .v{font-size:12px;color:#111;font-family:'JetBrains Mono',monospace}
  .ioc-row{display:flex;align-items:center;gap:10px;padding:7px 14px;border-bottom:1px solid #f0f0f0;font-size:12px}
  .ioc-row:last-child{border-bottom:none}
  .badge{font-size:10px;font-family:'JetBrains Mono',monospace;padding:2px 7px;border-radius:3px;font-weight:600}
  .tag{font-size:10px;font-family:'JetBrains Mono',monospace;padding:2px 7px;border-radius:3px;background:#e8f0fe;color:#2c5ee8;margin:2px 2px 2px 0;display:inline-block}
  .footer{margin-top:20px;font-size:10px;color:#aaa;text-align:center;border-top:1px solid #eee;padding-top:12px}
  .no-print{background:#f0f9ff;border:1px solid #bee3f8;border-radius:6px;padding:10px 14px;margin-bottom:16px;font-size:12px;color:#2b6cb0}
  @media print{.no-print{display:none}}
</style>
</head><body>
<div class="no-print">📄 To save as PDF: use your browser's <strong>File → Print → Save as PDF</strong> option. &nbsp;&nbsp;<button onclick="window.print()" style="padding:4px 12px;cursor:pointer;background:#2b6cb0;color:#fff;border:none;border-radius:4px">Print / Save PDF</button></div>
<div class="header">
  <div><h1>🔭 THREATSCOPE</h1><div style="font-size:10px;color:#8b949e;margin-top:3px">Threat Intelligence Report</div></div>
  <div class="meta">Generated: {$generated}<br>Analyst: {$item['user']}</div>
</div>
<div class="indicator">
  <div class="value">{$safe_q}</div>
  <div class="sub">Type: {$item['query_type']} &nbsp;·&nbsp; Queried: {$item['timestamp']}</div>
</div>
<div class="score-banner">
  <div class="score-num">{$r['score']}</div>
  <div>
    <div style="font-size:16px;font-weight:600;color:{$risk_color}">{$r['risk_level']} RISK</div>
    <div style="font-size:12px;color:#666;margin-top:4px">{$r['summary']['malicious_signals']} malicious signal(s) · {$r['summary']['sources_queried']} sources queried</div>
  </div>
</div>
HTML;

    // IOC Results
    if (!empty($r['ioc_results'])) {
        echo '<div class="section"><div class="section-header">IOC Match Results</div>';
        foreach ($r['ioc_results'] as $src) {
            $verdict = $src['error'] ? 'ERROR' : ($src['verdict'] ?? 'N/A');
            $vc = $vd_colors[$verdict] ?? '#666';
            $bg = $vc . '20';
            $summary = htmlspecialchars($src['summary'] ?? $src['error_message'] ?? ($src['found'] ? 'Match found' : 'No match'));
            echo "<div class='ioc-row'><span class='badge' style='background:{$bg};color:{$vc}'>{$verdict}</span><span style='font-weight:500;min-width:130px'>{$src['source']}</span><span style='color:#555'>{$summary}</span></div>";
        }
        echo '</div>';
    }

    // Geo
    if (!empty($r['geo']['found'])) {
        $g = $r['geo'];
        echo "<div class='section'><div class='section-header'>Geolocation</div>";
        $gfields = ['Country' => ($g['country']??'').' ('.($g['country_code']??'').')', 'City / Region' => trim(($g['city']??'').', '.($g['region']??''), ', '), 'ASN' => $g['asn']??'', 'Organization' => $g['org']??$g['isp']??'', 'Timezone' => $g['timezone']??'', 'Hosting' => ($g['hosting']??false)?'Yes':'No', 'Proxy/VPN' => ($g['proxy']??false)?'⚠ Detected':'Not detected'];
        foreach ($gfields as $k => $v) {
            if ($v) echo "<div class='kv'><div class='k'>{$k}</div><div class='v'>".htmlspecialchars($v)."</div></div>";
        }
        echo '</div>';
    }

    // WHOIS
    if (!empty($r['whois']['found'])) {
        $w = $r['whois'];
        echo "<div class='section'><div class='section-header'>WHOIS / Registry</div>";
        $skip = ['source','found','provider'];
        foreach ($w as $k => $v) {
            if (in_array($k,$skip)||!$v) continue;
            echo "<div class='kv'><div class='k'>".htmlspecialchars(ucfirst($k))."</div><div class='v'>".htmlspecialchars($v)."</div></div>";
        }
        echo '</div>';
    }

    // Tags
    if (!empty($r['tags'])) {
        echo "<div class='section'><div class='section-header'>Tags</div><div style='padding:10px 14px'>";
        foreach ($r['tags'] as $t) echo "<span class='tag'>".htmlspecialchars($t)."</span>";
        echo "</div></div>";
    }

    echo '<div class="footer">ThreatScope · For authorized use only · Handle as TLP:AMBER</div></body></html>';
}

function generate_tcpdf(array $item): void {
    // Full TCPDF implementation if library is installed
    $r = $item['result'];
    $pdf = new TCPDF('P','mm','A4',true,'UTF-8',false);
    $pdf->SetCreator('ThreatScope');
    $pdf->SetAuthor($item['user']);
    $pdf->SetTitle('ThreatScope Report — ' . $item['query']);
    $pdf->setPrintHeader(false);
    $pdf->setPrintFooter(false);
    $pdf->AddPage();
    $pdf->SetFont('helvetica','B',14);
    $pdf->SetTextColor(88,166,255);
    $pdf->Cell(0,10,'THREATSCOPE — Threat Intelligence Report',0,1,'L');
    $pdf->SetFont('helvetica','',10);
    $pdf->SetTextColor(100,100,100);
    $pdf->Cell(0,6,'Indicator: ' . $item['query'] . '   |   Risk: ' . $r['risk_level'] . '   |   Score: ' . $r['score'],0,1,'L');
    $pdf->Output('threatscope-' . preg_replace('/[^a-z0-9]/i','_',$item['query']) . '.pdf','D');
}

http_response_code(400);
echo 'Invalid export format';
