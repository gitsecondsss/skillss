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

$TURNSTILE_SECRET = getenv('TURNSTILE_SECRET') ?: '';
$RAILWAY_SECRET   = getenv('RAILWAY_SECRET') ?: '';
$MAIN_URL         = getenv('MAIN_URL') ?: '/';
$FAKE_URL         = getenv('FAKE_URL') ?: '/';

if ($TURNSTILE_SECRET === '' || $RAILWAY_SECRET === '') {
  http_response_code(500);
  echo json_encode(['ok'=>false]);
  exit;
}

function get_ip() {
  if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $parts = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
    return trim($parts[0]);
  }
  return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

$raw  = file_get_contents('php://input');
$data = json_decode($raw, true);
if (!is_array($data)) { http_response_code(400); echo json_encode(['ok'=>false]); exit; }

$cf_token = (string)($data['cf_token'] ?? '');
$metrics  = is_array($data['metrics'] ?? null) ? $data['metrics'] : [];

if ($cf_token === '') { http_response_code(400); echo json_encode(['ok'=>false]); exit; }

$ip = get_ip();

/* simple rate-limit (ephemeral) */
$RATE_DIR = sys_get_temp_dir() . '/cf_gate_rl';
if (!is_dir($RATE_DIR)) @mkdir($RATE_DIR, 0700, true);
$rlFile  = $RATE_DIR . '/' . preg_replace('/[^0-9a-fA-F:.\-]/', '_', $ip);
$window  = 300;
$maxHits = 20;

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
if (count($hits) > $maxHits) { echo json_encode(['ok'=>false,'next'=>$FAKE_URL]); exit; }

/* Turnstile verify */
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
if ($resp === false) { echo json_encode(['ok'=>false,'next'=>$FAKE_URL]); exit; }

$cf = json_decode($resp, true);
if (empty($cf['success'])) { echo json_encode(['ok'=>false,'next'=>$FAKE_URL]); exit; }

/* score */
$score = 5;
if (empty($metrics['webdriver']) || $metrics['webdriver'] === false) $score += 2;
if (!empty($metrics['timing']) && $metrics['timing'] > 300)         $score += 1;
if (!empty($metrics['screen']))                                     $score += 1;

$ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
if ($ua === '' || strlen($ua) < 10) $score -= 3;

$isHuman = ($score >= 5);

/* trust token */
$ttlSeconds = 300;
$payload = [
  'h'   => $isHuman ? 1 : 0,
  'ts'  => time(),
  'ttl' => $ttlSeconds,
  'n'   => bin2hex(random_bytes(8)),
];

$sig = hash_hmac('sha256', json_encode($payload, JSON_UNESCAPED_SLASHES), $RAILWAY_SECRET);
$payload['sig'] = $sig;

$trust_token = base64_encode(json_encode($payload, JSON_UNESCAPED_SLASHES));

echo json_encode([
  'ok'          => $isHuman,
  'trust_token' => $trust_token,
  'next'        => $isHuman ? $MAIN_URL : $FAKE_URL,
]);
