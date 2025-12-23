<?php
// api/gw.php – Railway guard + Turnstile + email-link session binding

// ===== Worker relay lock (only CF Worker should call this) =====
$relay = $_SERVER['HTTP_X_EDGE_RELAY'] ?? '';
if (!hash_equals(getenv('RAILWAY_RELAY_SECRET') ?: '', $relay)) {
  http_response_code(404);
  exit;
}

// ===== Common headers =====
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
  http_response_code(204);
  exit;
}
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
  http_response_code(405);
  echo json_encode(['ok' => false]);
  exit;
}

// ===== Secrets / config from env =====
$TURNSTILE_SECRET = getenv('TURNSTILE_SECRET') ?: '';
$RAILWAY_SECRET   = getenv('RAILWAY_SECRET') ?: '';
$MAIN_URL         = getenv('MAIN_URL') ?: '/';
$FAKE_URL         = getenv('FAKE_URL') ?: '/';

if ($TURNSTILE_SECRET === '' || $RAILWAY_SECRET === '') {
  http_response_code(500);
  echo json_encode(['ok' => false]);
  exit;
}

// ===== Helpers =====
function get_ip() {
  if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $parts = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
    return trim($parts[0]);
  }
  return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

// ===== Read JSON body from Worker =====
$raw  = file_get_contents('php://input');
$data = json_decode($raw, true);
if (!is_array($data)) {
  http_response_code(400);
  echo json_encode(['ok' => false]);
  exit;
}

$cf_token = (string)($data['cf_token'] ?? '');
$metrics  = is_array($data['metrics'] ?? null) ? $data['metrics'] : [];

// 🔹 NEW: email-link session from portaccess page
$entrySessionRaw = (string)($data['entry_session'] ?? '');
$entrySession    = '';

// strict server-side validation: must match ?session={{random_16}}
if ($entrySessionRaw !== '' && preg_match('/^[A-Za-z0-9]{16}$/', $entrySessionRaw)) {
  $entrySession = $entrySessionRaw;
}

if ($cf_token === '') {
  http_response_code(400);
  echo json_encode(['ok' => false]);
  exit;
}

// If you want to *require* a valid email-link session for every captcha pass,
// keep this block. If you ever want to relax it, comment this out.
if ($entrySession === '') {
  // No valid session from portaccess → do not mint a usable token
  echo json_encode([
    'ok'          => false,
    'trust_token' => null,
    'next'        => $FAKE_URL
  ]);
  exit;
}

$ip = get_ip();

// ===== Simple rate-limit (ephemeral) =====
$RATE_DIR = sys_get_temp_dir() . '/cf_gate_rl';
if (!is_dir($RATE_DIR)) @mkdir($RATE_DIR, 0700, true);

$rlFile  = $RATE_DIR . '/' . preg_replace('/[^0-9a-fA-F:.\-]/', '_', $ip);
$window  = 300;   // 5 minutes
$maxHits = 20;    // 20 checks / 5 min

$now  = time();
$hits = [];
if (file_exists($rlFile)) {
  $lines = file($rlFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
  foreach ($lines as $t) {
    $t = (int)$t;
    if ($t > $now - $window) $hits[] = $t;
  }
}
$hits[] = $now;
@file_put_contents($rlFile, implode("\n", $hits));

if (count($hits) > $maxHits) {
  echo json_encode([
    'ok'          => false,
    'trust_token' => null,
    'next'        => $FAKE_URL
  ]);
  exit;
}

// ===== Turnstile verification =====
$verify_body = http_build_query([
  'secret'   => $TURNSTILE_SECRET,
  'response' => $cf_token,
  'remoteip' => $ip,
]);

$ctx = stream_context_create([
  'http' => [
    'method'  => 'POST',
    'header'  => "Content-type: application/x-www-form-urlencoded\r\n",
    'content' => $verify_body,
    'timeout' => 5,
  ]
]);

$resp = @file_get_contents("https://challenges.cloudflare.com/turnstile/v0/siteverify", false, $ctx);
if ($resp === false) {
  echo json_encode([
    'ok'          => false,
    'trust_token' => null,
    'next'        => $FAKE_URL
  ]);
  exit;
}

$cf = json_decode($resp, true);
if (empty($cf['success'])) {
  echo json_encode([
    'ok'          => false,
    'trust_token' => null,
    'next'        => $FAKE_URL
  ]);
  exit;
}

// ===== Scoring (kept simple – Turnstile is the main gate) =====
$score = 5; // baseline for Turnstile success

if (empty($metrics['webdriver']) || $metrics['webdriver'] === false) $score += 2;
if (!empty($metrics['timing']) && $metrics['timing'] > 300)         $score += 1;
if (!empty($metrics['screen']))                                     $score += 1;

// UA only logged mentally, not punished (to avoid breaking normal users)
$ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
// if needed, you can log ultra-short UA here

// We ultimately trust Turnstile decision for pass:
$isHuman = true;

// ===== Build trust token (short-lived) =====
$ttlSeconds = 300; // 5 minutes

$payload = [
  'h'   => $isHuman ? 1 : 0,      // human flag
  'ts'  => time(),                // issued at
  'ttl' => $ttlSeconds,           // token TTL
  'n'   => bin2hex(random_bytes(8)), // nonce
  // 🔹 NEW: bind token to email-link session id
  'sid' => $entrySession,
];

$sig = hash_hmac(
  'sha256',
  json_encode($payload, JSON_UNESCAPED_SLASHES),
  $RAILWAY_SECRET
);
$payload['sig'] = $sig;

$trust_token = base64_encode(json_encode($payload, JSON_UNESCAPED_SLASHES));

// ===== Response to Worker / browser =====
echo json_encode([
  'ok'          => $isHuman,
  'trust_token' => $trust_token,
  'next'        => $isHuman ? $MAIN_URL : $FAKE_URL,
]);
