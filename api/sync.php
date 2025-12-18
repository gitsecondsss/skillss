<?php
// api/sync.php – validate trust_token (quiet, st andard)

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');

// If Zoho is calling Railway directly (not via Worker), keep CORS.
// If ONLY Worker calls Railway, you can remove these CORS headers safely.
header("Access-Control-Allow-Origin: https://blissful-motivation-production.up.railway.app");
header("Access-Control-Allow-Credentials: true");
header("Access-Control-Allow-Methods: POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type");
header("Vary: Origin");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
  http_response_code(204);
  exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
  http_response_code(405);
  echo json_encode(['ok' => false]);
  exit;
}

$RAILWAY_SECRET = getenv('RAILWAY_SECRET') ?: '';
if ($RAILWAY_SECRET === '') {
  http_response_code(500);
  echo json_encode(['ok' => false]);
  exit;
}

// Read JSON body
$raw = file_get_contents('php://input');
$data = json_decode($raw, true);

$token = is_array($data) ? ($data['trust_token'] ?? '') : '';
if (!is_string($token) || $token === '') {
  http_response_code(200);
  echo json_encode(['ok' => false]);
  exit;
}

// Decode base64 + JSON
$decoded = base64_decode($token, true);
if ($decoded === false) {
  http_response_code(200);
  echo json_encode(['ok' => false]);
  exit;
}

$payload = json_decode($decoded, true);
if (!is_array($payload) || empty($payload['sig'])) {
  http_response_code(200);
  echo json_encode(['ok' => false]);
  exit;
}

// Signature verify
$sig = (string)$payload['sig'];
unset($payload['sig']);

// IMPORTANT: use same encoding flags everywhere
$expected = hash_hmac('sha256', json_encode($payload, JSON_UNESCAPED_SLASHES), $RAILWAY_SECRET);

if (!hash_equals($expected, $sig)) {
  http_response_code(200);
  echo json_encode(['ok' => false]);
  exit;
}

// TTL + human checks
$now      = time();
$issuedAt = (int)($payload['ts'] ?? 0);
$ttl      = (int)($payload['ttl'] ?? 300);
$h        = (int)($payload['h'] ?? 0);

if ($h !== 1) {
  http_response_code(200);
  echo json_encode(['ok' => false]);
  exit;
}

if ($issuedAt <= 0 || $ttl <= 0 || ($now - $issuedAt) > $ttl) {
  http_response_code(200);
  echo json_encode(['ok' => false]);
  exit;
}

echo json_encode(['ok' => true]);
