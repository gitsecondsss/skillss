<?php
// verify-human.php  (Railway guard)

// Turnstile secret (server-side)
$TURNSTILE_SECRET = "0x4AAAAAACEAdSoSffFlw4Y93xBl0UFbgsc";

// HMAC secret (from env or fallback)
$RAILWAY_SECRET = getenv('RAILWAY_SECRET');
if (!$RAILWAY_SECRET) {
    $RAILWAY_SECRET = "YY93xBl0UFbgsY93xBl0UY93xBl0UFbgscFbgscc93xBl0UFbgsc";
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

// Verify with Cloudflare Turnstile
$verify_body = http_build_query([
    'secret'   => $TURNSTILE_SECRET,
    'response' => $cf_token,
    'remoteip' => $_SERVER['REMOTE_ADDR'] ?? ''
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

// Simple scoring logic (opaque to the client)
$score = 0;
if ($cf_success) {
    $score += 3;
}
if (empty($metrics['webdriver']) || $metrics['webdriver'] === false) {
    $score += 2;
}
if (!empty($metrics['timing']) && $metrics['timing'] > 300) {
    $score += 2;
}
if (!empty($metrics['screen'])) {
    $score += 1;
}

$isHuman = ($score >= 5);

// Build trust token (opaque, for future use if needed)
$payload = [
    'h'  => $isHuman ? 1 : 0,
    'ts' => time(),
    'n'  => bin2hex(random_bytes(8)),
];

$signature = hash_hmac('sha256', json_encode($payload), $RAILWAY_SECRET);
$payload['sig'] = $signature;

$trust_token = base64_encode(json_encode($payload));

echo json_encode([
    'ok'          => $isHuman,
    'trust_token' => $trust_token
]);
