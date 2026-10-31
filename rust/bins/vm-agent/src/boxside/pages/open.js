
(async () => {
  const $ = (id) => document.getElementById(id);
  const ERRORS = ${OPEN_ERRORS};
  const fail = (msg) => { $('h').textContent = 'Could not open the agent'; $('s1').className = ''; $('err').textContent = msg; $('err').className = 'err show'; $('back').style.display = 'inline-block'; };
  const h = new URLSearchParams(location.hash.slice(1));
  const i = h.get('i'), e = h.get('e');
  history.replaceState(null, '', location.pathname);
  if (e) { fail(ERRORS[e] || ERRORS.invalid); return; }
  if (!i) { fail('This page only works from the Open button in your ControlClaw console.'); return; }
  let d, ok;
  try {
    const r = await fetch('/__cc/open/begin', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    d = await r.json().catch(() => ({})); ok = r.ok;
  } catch (err) { fail('Could not reach the agent. Try again from your ControlClaw console.'); return; }
  if (!ok || !d.firewall || !d.c) { fail(d.error || ERRORS.no_firewall); return; }
  const f = document.createElement('form');
  f.method = 'POST'; f.action = d.firewall + '/__cc/open';
  for (const [k, v] of [['intent', i], ['c', d.c]]) { const x = document.createElement('input'); x.type = 'hidden'; x.name = k; x.value = v; f.appendChild(x); }
  document.body.appendChild(f);
  f.submit();
})();