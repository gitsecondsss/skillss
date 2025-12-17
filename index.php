<?php
// index.php – bare Turnstile test
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Turnstile Test</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">

  <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
</head>
<body style="font-family:Segoe UI,system-ui,sans-serif;padding:40px;">

  <h2>Turnstile Test</h2>
  <p>If everything works, you should see a Turnstile widget below. When you solve it, an alert will pop.</p>

  <div id="cf-turnstile"
       data-sitekey="0x4AAAAAACEAdYvsKv0_uuH2"
       data-callback="onHumanVerified">
  </div>

  <script>
    function onHumanVerified(token){
      alert("Turnstile OK. Token starts with: " + String(token).slice(0, 10));
    }
  </script>

</body>
</html>
