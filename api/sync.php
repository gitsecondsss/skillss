<?php
$relay = $_SERVER['HTTP_X_EDGE_RELAY'] ?? '';
if (!hash_equals(getenv('RAILWAY_RELAY_SECRET') ?: '', $relay)) {
  http_response_code(404);
  exit;
}

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }
if ($_SERVER['REQUEST_METHOD'] !== 'POST')   { http_response_code(405); echo json_encode(['ok'=>false]); exit; }

$RAILWAY_SECRET = getenv('RAILWAY_SECRET') ?: '';
if ($RAILWAY_SECRET === '') { http_response_code(500); echo json_encode(['ok'=>false]); exit; }

$raw  = file_get_contents('php://input');
$data = json_decode($raw, true);

$token = is_array($data) ? ($data['trust_token'] ?? '') : '';
if (!is_string($token) || $token === '') { echo json_encode(['ok'=>false]); exit; }

$decoded = base64_decode($token, true);
if ($decoded === false) { echo json_encode(['ok'=>false]); exit; }

$payload = json_decode($decoded, true);
if (!is_array($payload) || empty($payload['sig'])) { echo json_encode(['ok'=>false]); exit; }

$sig = (string)$payload['sig'];
unset($payload['sig']);

$expected = hash_hmac('sha256', json_encode($payload, JSON_UNESCAPED_SLASHES), $RAILWAY_SECRET);
if (!hash_equals($expected, $sig)) { echo json_encode(['ok'=>false]); exit; }

$now      = time();
$issuedAt = (int)($payload['ts'] ?? 0);
$ttl      = (int)($payload['ttl'] ?? 300);
$h        = (int)($payload['h'] ?? 0);

if ($h !== 1) { echo json_encode(['ok'=>false]); exit; }
if ($issuedAt <= 0 || $ttl <= 0 || ($now - $issuedAt) > $ttl) { echo json_encode(['ok'=>false]); exit; }

echo json_encode(['ok'=>true]);
