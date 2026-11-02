import { createHash } from 'node:crypto';

/*
 * The status page of the relay emulator: one self-contained HTML document, with its style and its script inline and no
 * address of any other site in it. The script asks the emulator it came from for `Switch.GetStatus` once a second and
 * paints the answer; everything it shows is set with `textContent`. The content security policy names the hash of the
 * inline style and script, so nothing else can run, and allows requests to the page's own origin only.
 */

const STYLE = `
:root{color-scheme:light dark;--bg:#f3f4f6;--card:#ffffff;--fg:#111418;--muted:#566070;--line:#dfe3e8;--open-fg:#05612e;--open-bg:#d7f3e2;--closed-fg:#3f4756;--closed-bg:#e9ecf0;--bad:#b42318}
@media (prefers-color-scheme:dark){:root{--bg:#0d0f12;--card:#161a1f;--fg:#eef1f5;--muted:#9aa4b2;--line:#272d35;--open-fg:#6ee7a0;--open-bg:#0f3622;--closed-fg:#b6bfcc;--closed-bg:#222830;--bad:#ff8a80}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{width:min(30rem,100% - 2rem);margin:1rem 0;background:var(--card);border:1px solid var(--line);border-radius:1rem;padding:1.5rem}
h1{margin:0;font-size:1rem;font-weight:600}
.sub{margin:.125rem 0 1.25rem;color:var(--muted);font-size:.875rem}
.panel{border-radius:.75rem;padding:2rem 1rem;text-align:center;transition:background-color .2s,color .2s}
.panel.open{background:var(--open-bg);color:var(--open-fg)}
.panel.closed{background:var(--closed-bg);color:var(--closed-fg)}
.state{margin:0;font-size:clamp(3rem,16vw,5rem);font-weight:800;letter-spacing:.04em;line-height:1}
.countdown{margin:.75rem 0 0;min-height:1.5em;font-size:1.25rem;font-variant-numeric:tabular-nums}
dl{margin:1.25rem 0 0;display:grid;gap:.5rem}
dl div{display:flex;justify-content:space-between;gap:1rem;border-top:1px solid var(--line);padding-top:.5rem}
dt{color:var(--muted)}
dd{margin:0;font-variant-numeric:tabular-nums;overflow-wrap:anywhere;text-align:right}
.link{margin:1rem 0 0;font-size:.8125rem;color:var(--muted)}
.link.down{color:var(--bad)}
@media (prefers-reduced-motion:reduce){.panel{transition:none}}
`;

const SCRIPT = `
(function () {
  'use strict';
  var panel = document.getElementById('panel');
  var state = document.getElementById('state');
  var countdown = document.getElementById('countdown');
  var lastAt = document.getElementById('last-at');
  var lastJti = document.getElementById('last-jti');
  var lastIss = document.getElementById('last-iss');
  var link = document.getElementById('link');
  var requestId = 0;
  var output = false;
  var remaining = null;
  var received = 0;

  function pad(value) { return value < 10 ? '0' + value : String(value); }
  function clock(seconds) {
    var date = new Date(seconds * 1000);
    return pad(date.getHours()) + ':' + pad(date.getMinutes()) + ':' + pad(date.getSeconds());
  }

  function paint() {
    var left = remaining === null ? null : remaining - (performance.now() - received) / 1000;
    var open = output && (left === null || left > 0);
    panel.className = 'panel ' + (open ? 'open' : 'closed');
    state.textContent = open ? 'OPEN' : 'CLOSED';
    if (!open) countdown.textContent = '';
    else countdown.textContent = left === null ? 'held open' : 'closes in ' + left.toFixed(1) + ' s';
  }

  function apply(result) {
    output = result.output === true;
    var timed = typeof result.timer_started_at === 'number' && typeof result.timer_duration === 'number' && typeof result.umis_now === 'number';
    remaining = timed ? Math.max(0, result.timer_started_at + result.timer_duration - result.umis_now) : null;
    received = performance.now();
    var last = result.umis_last;
    if (last && typeof last.at === 'number') {
      lastAt.textContent = clock(last.at);
      lastJti.textContent = last.jti ? String(last.jti) : 'unsigned';
      lastIss.textContent = last.iss ? String(last.iss) : '-';
    }
    link.textContent = 'live, updated every second';
    link.className = 'link';
    paint();
  }

  function down() {
    link.textContent = 'no connection to the emulator';
    link.className = 'link down';
  }

  function poll() {
    requestId += 1;
    fetch('/rpc', {
      method: 'POST',
      cache: 'no-store',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ id: requestId, src: 'umis-status-page', method: 'Switch.GetStatus', params: { id: 0 } })
    })
      .then(function (response) { return response.json(); })
      .then(function (answer) { if (answer && answer.result) apply(answer.result); else down(); })
      .catch(down);
  }

  poll();
  setInterval(poll, 1000);
  setInterval(paint, 100);
})();
`;

const BODY = `
<main>
  <h1>UMIS relay emulator</h1>
  <p class="sub">Shelly Gen3 RPC, switch 0</p>
  <section id="panel" class="panel closed" aria-live="polite">
    <p id="state" class="state">CLOSED</p>
    <p id="countdown" class="countdown"></p>
  </section>
  <dl>
    <div><dt>Last command</dt><dd id="last-at">none yet</dd></div>
    <div><dt>jti</dt><dd id="last-jti">-</dd></div>
    <div><dt>iss</dt><dd id="last-iss">-</dd></div>
  </dl>
  <p id="link" class="link">connecting</p>
</main>
`;

const digest = (text: string): string => `'sha256-${createHash('sha256').update(text, 'utf8').digest('base64')}'`;

/** The page and the headers it is served with. */
export const STATUS_PAGE: { readonly html: string; readonly headers: Readonly<Record<string, string>> } = {
  html: `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>UMIS relay emulator</title>
<link rel="icon" href="data:,">
<style>${STYLE}</style>
</head>
<body>${BODY}<script>${SCRIPT}</script>
</body>
</html>
`,
  headers: {
    'content-type': 'text/html; charset=utf-8',
    'content-security-policy': [
      "default-src 'none'",
      `script-src ${digest(SCRIPT)}`,
      `style-src ${digest(STYLE)}`,
      "connect-src 'self'",
      'img-src data:',
      "base-uri 'none'",
      "form-action 'none'",
      "frame-ancestors 'none'",
    ].join('; '),
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
    'referrer-policy': 'no-referrer',
    'cache-control': 'no-store',
  },
};
