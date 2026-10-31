
(async () => {
  const $ = (id) => document.getElementById(id);
  const wait = (ms) => new Promise((r) => setTimeout(r, ms));
  const step = (n) => { for (let i = 1; i <= 3; i++) { const el = $('s' + i); el.className = i < n ? 'done' : i === n ? 'active' : ''; } };
  const fail = (msg) => { $('h').textContent = 'Could not open the agent'; for (let i = 1; i <= 3; i++) $('s' + i).className = ''; $('err').textContent = msg; $('err').className = 'err show'; $('back').style.display = 'inline-block'; };
  const notPaired = (next, why) => { $('h').textContent = "Couldn't pair this browser"; $('s1').className = 'done'; $('s2').className = ''; $('s3').className = ''; $('note').textContent = (why ? 'The agent is running, but ' + why + '. ' : '') + 'Continue anyway opens OpenClaw, which will ask you to approve this browser. Or click Open again in your ControlClaw console.'; $('note').style.display = 'block'; $('back').style.display = 'inline-block'; $('anyway').href = next || '/'; $('anyway').style.display = 'inline-block'; };
  const t = new URLSearchParams(location.hash.slice(1)).get('t');
  history.replaceState(null, '', location.pathname);
  if (!t) { fail('This page only works from the Open button in your ControlClaw console.'); return; }
  const started = Date.now();
  let d, ok;
  try {
    const r = await fetch('/__cc/session', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token: t }) });
    d = await r.json().catch(() => ({})); ok = r.ok;
  } catch (e) { fail('Could not reach the agent. Try again from your ControlClaw console.'); return; }
  if (!ok) { fail(d.error || 'This link has expired. Open the agent from your ControlClaw console again.'); return; }
  await wait(Math.max(0, 500 - (Date.now() - started)));
  step(2);
  ${FORGET_PREVIOUS_GATEWAY_JS}
  // One of this box's own pages: go there, and only to a path on this box under /__cc/.
  const PAGES = ${LOGIN_PAGE_TITLES};
  const own = (p) => typeof p === 'string' && p.startsWith('/') && !p.startsWith('//') && !p.includes(String.fromCharCode(92));
  if (PAGES[d.view] && own(d.next) && d.next.startsWith('/__cc/')) { $('h').textContent = PAGES[d.view]; step(3); location.replace(d.next); return; }
  if (d.view === 'direct' && own(d.next)) { step(3); location.replace(d.next); return; }
  if (d.paired === false) { notPaired(own(d.next) ? d.next : '/', d.pairError); return; }
  await wait(450);
  step(3); await wait(350);
  location.replace(own(d.next) ? d.next : '/');
})();