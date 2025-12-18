<?php
// verify-human.php  (Railway guard + scoring)

$TURNSTILE_SECRET = "0x4AAAAAACEAdSoSffFlw4Y93xBl0UFbgsc";

// HMAC secret (from env or fallback)
$RAILWAY_SECRET = getenv('RAILWAY_SECRET');
if (!$RAILWAY_SECRET) {
    $RAILWAY_SECRET = "YY93xBl0UFbgsY93xBl0UY93xBl0UFbgscFbgscc93xBl0UFbgsc";
}

// Simple rate-limit storage (ephemeral file-based, per container)
$RATE_DIR = sys_get_temp_dir() . '/cf_gate_rl';
if (!is_dir($RATE_DIR)) {
    @mkdir($RATE_DIR, 0700, true);
}

// CORS: allow only your Zoho domain
header("Access-Control-Allow-Origin: https://portalaccess.zoholandingpage.com");
header("Access-Control-Allow-Credentials: true");
header("Access-Control-Allow-Methods: POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type");
header("Content-Type: application/json; charset=utf-8");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['ok' => false, 'error' => 'Invalid method']);
    exit;
}

// Helper
function get_ip() {
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $parts = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        return trim($parts[0]);
    }
    return $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
}

// Read JSON body
$raw = file_get_contents('php://input');
$data = json_decode($raw, true);
if (!is_array($data)) {
    echo json_encode(['ok' => false, 'error' => 'Invalid payload']);
    exit;
}

$cf_token = $data['cf_token'] ?? '';
$metrics  = $data['metrics'] ?? [];

if (empty($cf_token)) {
    echo json_encode(['ok' => false, 'error' => 'Missing token']);
    exit;
}

// --------- Rate limit (per IP) ---------
$ip       = get_ip();
$rlFile   = $RATE_DIR . '/' . preg_replace('/[^0-9a-fA-F:.\-]/', '_', $ip);
$window   = 300;   // 5 minutes
$maxHits  = 20;    // 20 verifications per window

$now = time();
$hits = [];

if (file_exists($rlFile)) {
    $lines = file($rlFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $t) {
        $t = (int)$t;
        if ($t > $now - $window) {
            $hits[] = $t;
        }
    }
}

$hits[] = $now;
file_put_contents($rlFile, implode("\n", $hits));

if (count($hits) > $maxHits) {
    // Too chatty ⇒ low score, don't expose details
    echo json_encode(['ok' => false, 'error' => 'Verification failed']);
    exit;
}

// --------- Verify with Cloudflare Turnstile ---------
$verify_body = http_build_query([
    'secret'   => $TURNSTILE_SECRET,
    'response' => $cf_token,
    'remoteip' => $ip,
]);

$context = stream_context_create([
    'http' => [
        'method'  => 'POST',
        'header'  => "Content-type: application/x-www-form-urlencoded\r\n",
        'content' => $verify_body,
        'timeout' => 5,
    ]
]);

$resp = @file_get_contents("https://challenges.cloudflare.com/turnstile/v0/siteverify", false, $context);
if ($resp === false) {
    echo json_encode(['ok' => false, 'error' => 'Verification failed']);
    exit;
}

$cf = json_decode($resp, true);
$cf_success = !empty($cf['success']);
$cf_error_codes = $cf['error-codes'] ?? [];

// --------- Scoring ---------
$score = 0;

// 1) Turnstile result
if ($cf_success) {
    $score += 5;
} else {
    // Hard fail from CF: don't trust, but don't expose reason
    echo json_encode(['ok' => false, 'error' => 'Verification failed']);
    exit;
}

// 2) Basic metrics (JS presence, timing)
if (empty($metrics['webdriver']) || $metrics['webdriver'] === false) {
    $score += 2; // likely not headless
}
if (!empty($metrics['timing']) && $metrics['timing'] > 300) {
    $score += 1; // not instantly scripted
}
if (!empty($metrics['screen'])) {
    $score += 1; // has screen info
}

// 3) User-Agent sanity
$ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
if ($ua === '' || strlen($ua) < 10) {
    // suspicious: empty or tiny UA
    $score -= 3;
}

// Threshold
$isHuman = ($score >= 5);

// --------- Build trust token (short-lived) ---------
$ttlSeconds = 300; // 5 minutes lifetime from issued time

$payload = [
    'h'   => $isHuman ? 1 : 0,
    'ts'  => time(),
    'ip'  => $ip,
    'ua'  => substr($ua, 0, 180), // truncated for size
    'ttl' => $ttlSeconds,
    'n'   => bin2hex(random_bytes(8)),
];

$signature = hash_hmac('sha256', json_encode($payload, JSON_UNESCAPED_SLASHES), $RAILWAY_SECRET);
$payload['sig'] = $signature;

$trust_token = base64_encode(json_encode($payload, JSON_UNESCAPED_SLASHES));

echo json_encode([
    'ok'          => $isHuman,
    'trust_token' => $trust_token
]);
