<?php
require_once __DIR__ . '/includes/functions.php';
ts_session_start();

// ─── Logout ───────────────────────────────────────────────────
if (isset($_GET['logout'])) {
    if (AUTH_MODE === 'okta' && auth_check()) {
        // SP-initiated Single Logout via Okta
        require_once __DIR__ . '/saml/saml_helper.php';
        $username = auth_user()['username'];
        auth_logout(); // destroy local session first
        try {
            $auth = saml_get_auth();
            $auth->logout(); // redirects to Okta SLO — exits
        } catch (Exception $e) {
            // If SLO fails, just go back to login page
        }
    } else {
        auth_logout();
    }
    header('Location: index.php');
    exit;
}

// ─── Local login POST (only when AUTH_MODE = 'local') ─────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'login') {
    header('Content-Type: application/json');

    if (AUTH_MODE !== 'local') {
        echo json_encode(['success' => false, 'error' => 'Local login is disabled. Use SSO.']);
        exit;
    }
    if (!rate_limit_check('login', RATE_LIMIT_LOGIN, 900)) {
        echo json_encode(['success' => false, 'error' => 'Too many login attempts. Try again in 15 minutes.']);
        exit;
    }
    $username = trim(strtolower($_POST['username'] ?? ''));
    $password = $_POST['password'] ?? '';
    if (auth_login_local($username, $password)) {
        echo json_encode(['success' => true, 'user' => auth_user()]);
    } else {
        echo json_encode(['success' => false, 'error' => 'Invalid credentials']);
    }
    exit;
}

$logged_in = auth_check();
$user      = $logged_in ? auth_user() : null;
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ThreatScope — Threat Intelligence Portal</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap" rel="stylesheet">
<link rel="stylesheet" href="assets/css/app.css">
</head>
<body>

<?php if (!$logged_in): ?>
<!-- ═══════════════════════════════════════ LOGIN PAGE ═══ -->
<div class="login-page">
  <div class="login-card">
    <div class="login-logo">
      <div class="logo-icon"><img src="assets/img/logo-home.jpg" width=300px/></div>
    </div>

    <?php if (AUTH_MODE === 'okta'): ?>
      <!-- SSO button (should rarely be seen since we redirect above) -->
      <a href="saml/login.php" class="btn-primary full-width" style="display:block;text-align:center;text-decoration:none;padding:11px">
        Sign in with Okta →
      </a>
    <?php else: ?>
      <!-- Local login form -->
      <div class="form-group">
        <label class="form-label">Username</label>
        <input type="text" id="login-user" class="form-input" placeholder="analyst@org.local" autocomplete="username">
      </div>
      <div class="form-group">
        <label class="form-label">Password</label>
        <input type="password" id="login-pass" class="form-input" placeholder="••••••••" autocomplete="current-password">
      </div>
      <button class="btn-primary full-width" id="login-btn" onclick="doLogin()">Sign in</button>
      <div id="login-err" class="login-err"></div>
    <?php endif; ?>
  </div>
</div>

<?php else: ?>
<!-- ══════════════════════════════════════════ APP SHELL ═══ -->
<div id="app">
  <!-- Topbar -->
  <div class="topbar">
    <div class="topbar-left">
      <div class="logo">
        <div class="logo-icon">🔭</div>
        <div class="logo-header">
          <span class="logo-text">THREATSCOPE</span>
          <span class="logo-subtext">v<?php echo APP_VERSION ?></span>
        </div>
      </div>
      <nav class="topnav">
        <button class="nav-btn active" data-view="lookup" onclick="switchView('lookup', this)">🔍 Lookup</button>
        <button class="nav-btn" data-view="history" onclick="switchView('history', this)">📋 History</button>
        <button class="nav-btn" data-view="settings" onclick="switchView('settings', this)">⚙️ Settings</button>
      </nav>
    </div>
    <div class="topbar-right">
      <div class="user-pill">
        <div class="user-dot"></div>
        <?= htmlspecialchars($user['name'] ?: $user['username']) ?>
        <?php if ($user['role'] === 'admin'): ?><span class="role-badge">admin</span><?php endif; ?>
        <?php if (($user['auth'] ?? AUTH_MODE) === 'okta'): ?><span class="role-badge" style="background:rgba(63,185,80,.15);color:var(--green)">SSO</span><?php endif; ?>
      </div>
      <a href="?logout=1" class="btn-ghost">logout</a>
    </div>
  </div>

  <!-- Main content -->
  <div class="main-wrap">

    <!-- ══════════════ LOOKUP VIEW ══════════════ -->
    <div id="view-lookup" class="view active">
      <h1 class="page-title">Threat Intelligence Lookup</h1>
      <p class="page-sub">Query an IP address, domain, email, or file hash across all configured intelligence sources</p>

      <!-- Source status badges -->
      <div id="source-badges" class="source-badges"></div>

      <!-- Search bar -->
      <div class="search-bar">
        <input type="text" id="query-input" class="search-input" placeholder="1.1.1.1 · malicious.com · email@mail.com · d41d8cd98f00b204e9800998ecf8427e" oninput="updateTypeBadge()" onkeydown="if(event.key==='Enter')doLookup()">
        <button class="btn-search" id="search-btn" onclick="doLookup()">Analyze →</button>
      </div>
      <div id="type-badge-wrap" style="min-height:24px;margin-top:6px;margin-bottom:16px"></div>

      <!-- Error -->
      <div id="lookup-error" class="error-box" style="display:none"></div>

      <!-- Loading -->
      <div id="lookup-loading" style="display:none;text-align:center;padding:48px 0">
        <div style="font-family:var(--mono);font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);margin-bottom:12px">Querying sources</div>
        <div class="dots-loader"><div></div><div></div><div></div></div>
      </div>

      <!-- Empty state -->
      <div id="lookup-empty" class="empty-state">
        <div class="empty-icon">🔭</div>
        <div>Enter an indicator above to begin</div>
        <div class="empty-sub">Supports IPv4 · Domain · Email · MD5 · SHA-1 · SHA-256</div>
      </div>

      <!-- Results -->
      <div id="lookup-results" style="display:none"></div>
    </div>

    <!-- ══════════════ HISTORY VIEW ══════════════ -->
    <div id="view-history" class="view">
      <div class="view-header">
        <div>
          <h1 class="page-title">Lookup History</h1>
          <p class="page-sub" id="history-count">Loading…</p>
        </div>
        <div class="btn-row">
          <button class="btn-ghost" onclick="exportCSV()">⬇ Export CSV</button>
          <button class="btn-ghost btn-danger" onclick="clearHistory()">🗑 Clear</button>
          <button class="btn-ghost" onclick="loadHistory()">↻ Refresh</button>
        </div>
      </div>
      <div class="filter-row">
        <input type="text" class="form-input" id="hist-filter" placeholder="Filter by query or analyst…" oninput="filterHistory()" style="max-width:280px;font-family:var(--mono)">
        <select class="form-input" id="hist-type" onchange="filterHistory()" style="max-width:160px">
          <option value="">All types</option>
          <option value="IPv4 Address">IPv4</option>
          <option value="Domain">Domain</option>
          <option value="MD5 Hash">MD5</option>
          <option value="SHA-1 Hash">SHA-1</option>
          <option value="SHA-256 Hash">SHA-256</option>
        </select>
      </div>
      <div id="history-list"></div>
    </div>

    <!-- ══════════════ SETTINGS VIEW ══════════════ -->
    <div id="view-settings" class="view">
      <div class="view-header">
        <div>
          <h1 class="page-title">Settings</h1>
          <p class="page-sub">View intelligence source connections and API keys.  Edit config.php to update values.</p>
        </div>
        <div class="btn-row">
<!--          <span id="save-ok" style="display:none;font-size:12px;color:var(--green)">✓ Saved</span>
          <button class="btn-primary" onclick="saveSettings()">Save Settings</button>
-->        </div>
      </div>
      <div id="storage-diagnostic"></div>
      <div id="settings-panels"></div>
      <div class="security-note">
        <strong>Security note:</strong> API keys are stored in <code>config.php</code> on the server and masked in all responses.
        Ensure this directory is not web-accessible.
        Always use HTTPS in production.
      </div>
    </div>

  </div><!-- /main-wrap -->
</div><!-- /app -->
<?php endif; ?>

<script src="assets/js/app.js"></script>
<?php if ($logged_in): ?>
<script>
  // Pass PHP session user to JS
  window.TS_USER = <?= json_encode($user) ?>;
  document.addEventListener('DOMContentLoaded', function() {
    loadSourceStatus();
    loadSettings();
    //loadHistory(); - Loads on deman when clicked instead of preloading
  });
</script>
<?php endif; ?>
</body>
</html>
