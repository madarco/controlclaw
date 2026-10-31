
(async () => {
  const $ = (id) => document.getElementById(id);
  const fail = (msg) => { $('h').textContent = 'Could not open the browser'; for (let i = 1; i <= 2; i++) $('s' + i).className = ''; $('err').textContent = msg; $('err').className = 'err show'; };
  const t = new URLSearchParams(location.hash.slice(1)).get('t');
  history.replaceState(null, '', location.pathname);
  if (!t) {
    // The sidebar's Browser link: no ticket, but a browser already signed in to this agent (or
    // holding a live-view pass) may watch, which is what Caddy asks /__cc/verify-view for.
    try {
      const v = await fetch('/__cc/verify-view', { credentials: 'same-origin', cache: 'no-store' });
      if (v.ok) { $('s1').className = 'done'; $('s2').className = 'active'; location.replace(${NOVNC_URL}); return; }
    } catch (e) { /* fall through to the message below */ }
    fail('Press Screen on this agent in your ControlClaw console to open its browser.'); return;
  }
  let d, ok;
  try {
    const r = await fetch('/__cc/view-session', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token: t }) });
    d = await r.json().catch(() => ({})); ok = r.ok;
  } catch (e) { fail('Could not reach the agent. Press Screen again in your ControlClaw console.'); return; }
  if (!ok) { fail(d.error || 'This view has expired. Press Screen again in your ControlClaw console.'); return; }
  $('s1').className = 'done'; $('s2').className = 'active';
  location.replace(${NOVNC_URL});
})();