<?php
// validate-token.php – check trust_token for Zoho main page

$RAILWAY_SECRET = getenv('RAILWAY_SECRET');
if (!$RAILWAY_SECRET) {
    $RAILWAY_SECRET = "YY93xBl0UFbgsY93xBl0UY93xBl0UFbgscFbgscc93xBl0UFbgsc";
}

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
if (!is_array($data) || empty($data['trust_token'])) {
    echo json_encode(['ok' => false, 'error' => 'Missing token']);
    exit;
}

$token   = $data['trust_token'];
$decoded = base64_decode($token, true);
if ($decoded === false) {
    echo json_encode(['ok' => false, 'error' => 'Bad base64']);
    exit;
}

$payload = json_decode($decoded, true);
if (!is_array($payload) || empty($payload['sig'])) {
    echo json_encode(['ok' => false, 'error' => 'Bad payload']);
    exit;
}

$sig = $payload['sig'];
unset($payload['sig']);

$expected = hash_hmac('sha256', json_encode($payload, JSON_UNESCAPED_SLASHES), $RAILWAY_SECRET);
if (!hash_equals($expected, $sig)) {
    echo json_encode(['ok' => false, 'error' => 'Signature mismatch']);
    exit;
}

// Basic checks: human + TTL
$now      = time();
$issuedAt = (int)($payload['ts'] ?? 0);
$ttl      = (int)($payload['ttl'] ?? 300);
$h        = (int)($payload['h'] ?? 0);

if ($h !== 1) {
    echo json_encode(['ok' => false, 'error' => 'Not human']);
    exit;
}

if ($issuedAt <= 0 || $ttl <= 0 || ($now - $issuedAt) > $ttl) {
    echo json_encode(['ok' => false, 'error' => 'Expired']);
    exit;
}

echo json_encode(['ok' => true]);
