(() => {
  const $ = (id) => document.getElementById(id);
  const TEXT = ${TEXT};
  const STEP = { done: 'border-allow-border bg-allow-soft text-allow-fg', now: 'border-brand bg-brand text-white', todo: 'border-line bg-surface text-ink-2' };
  const steps = (s1, s2, s3) => [s1, s2, s3].forEach((st, i) => {
    const li = document.querySelector('[data-step="' + (i + 1) + '"]');
    const dot = li.firstElementChild;
    dot.className = 'grid h-7 w-7 shrink-0 place-items-center rounded-full border text-[12.5px] font-semibold ' + STEP[st];
    dot.textContent = st === 'done' ? '✓' : String(i + 1);
    if (st === 'now') li.setAttribute('aria-current', 'step'); else li.removeAttribute('aria-current');
  });
  // Over the code: installing (a spinner), expired or failed ("New code" goes to the console,
  // which starts the link again), linked (a check and Back to console).
  const over = (kind, title, text) => {
    $('over').hidden = !kind;
    $('over-spin').hidden = kind !== 'wait';
    $('over-ok').hidden = kind !== 'ok';
    $('over-new').hidden = kind !== 'again';
    $('over-back').hidden = kind !== 'ok';
    $('over-title').textContent = title || '';
    $('over-text').textContent = text || '';
  };
  let last = '';
  const tick = async () => {
    let d;
    try {
      const r = await fetch('/__cc/whatsapp/qr', { credentials: 'same-origin' });
      if (r.status === 401) {
        over('again', 'Your session expired', 'Open WhatsApp again from your ControlClaw console.');
        $('over-new').textContent = 'Open the console';
        $('lead').textContent = '';
        return;
      }
      d = await r.json();
    } catch (e) { setTimeout(tick, 4000); return; }
    if (d.state === 'qr' && d.qrDataUrl) {
      if (d.qrDataUrl !== last) { last = d.qrDataUrl; const img = new Image(); img.alt = 'WhatsApp link code'; img.width = 256; img.height = 256; img.className = 'h-full w-full'; img.src = d.qrDataUrl; $('qr').replaceChildren(img); }
      over(null);
      steps('done', 'now', 'todo');
      $('lead').textContent = 'The code changes on its own every few seconds. Scan the newest one.';
    } else if (d.state === 'connected') {
      over('ok', 'WhatsApp is linked', 'You can close this tab.');
      steps('done', 'done', 'done');
      $('h').textContent = 'WhatsApp is linked';
      $('lead').textContent = '';
      return;
    } else if (d.state === 'expired' || d.state === 'failed') {
      over('again', d.state === 'expired' ? 'The code expired' : 'The link did not work', d.message || 'New code starts the link again in your ControlClaw console.');
      steps('done', 'now', 'todo');
      $('lead').textContent = '';
      return;
    } else if (d.state === 'installing') {
      $('qr').replaceChildren();
      over('wait', 'Getting a code', TEXT.installing);
      steps('done', 'todo', 'todo');
      $('lead').textContent = '';
    } else {
      $('qr').replaceChildren();
      // Idle, or a state this page does not know: the console's start may not have landed yet, so
      // keep asking.
      over('again', 'No link is waiting', d.message || TEXT[d.state] || TEXT.idle);
      steps('todo', 'todo', 'todo');
      $('lead').textContent = '';
    }
    setTimeout(tick, 2500);
  };
  steps('done', 'now', 'todo');
  over('wait', 'Getting a code', '');
  tick();
})();
