<?php
// index.php – Captcha gate on Railway
?><!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Verification</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>

  <style>
    * { box-sizing: border-box; }
    html, body {
      margin: 0;
      padding: 0;
      height: 100%;
      font-family: "Segoe UI", system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
      background: #f3f3f3;
    }
    body { display:flex; align-items:center; justify-content:center; }
    .guard-wrap {
      background:#fff;
      padding:14px 28px;
      border-radius:8px;
      box-shadow:0 10px 30px rgba(0,0,0,.08);
      max-width:420px;
      width:100%;
      text-align:center;
    }
    .guard-title { font-size:18px; font-weight:600; margin-bottom:8px; }
    .guard-sub { font-size:13px; color:#666; margin-bottom:18px; }
    .bot-preview { font-size:12px; color:#999; margin-top:14px; line-height:1.4; }
    .cf-turnstile { display:flex; justify-content:center; }
    .cf-turnstile iframe { margin:0 auto !important; display:block !important; }
  </style>
</head>

<body>
  <div class="guard-wrap">
    <div class="guard-title">Checking your browser…</div>
    <p class="guard-sub">Please complete the security check to continue.</p>

    <div class="cf-turnstile"
      data-sitekey="0x4AAAAAACEAdYvsKv0_uuH2"
      data-callback="onHumanVerified"></div>

    <div class="bot-preview">
      Automatic previews may show this page for security checks. No action is required.
    </div>
  </div>

<script>
function collectMetrics(){
  try {
    return {
      ua: navigator.userAgent,
      lang: navigator.language,
      tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
      screen: (screen?.width && screen?.height) ? (screen.width + "x" + screen.height) : "",
      colorDepth: screen.colorDepth || "",
      webdriver: navigator.webdriver === true,
      timing: performance.now ? performance.now() : 0
    };
  } catch(e){ return {}; }
}

function onHumanVerified(cfToken){
  if (!cfToken) return;

  fetch("/api/gw.php", { // ✅ relative (no Railway URL exposed)
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ cf_token: cfToken, metrics: collectMetrics() })
  })
  .then(r => r.json())
  .then(res => {
    if (res?.trust_token) sessionStorage.setItem("trust_token", res.trust_token);
    // ✅ server decides where to go; client doesn't know urls in code
    window.location.href = res?.next || "/";
  })
  .catch(() => {
    window.location.href = "/"; // neutral fallback
  });
}
</script>
</body>
</html>
