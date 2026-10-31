
(() => {
  const $ = (id) => document.getElementById(id);
  const TEXT = ${TEXT};
  let last = '';
  const tick = async () => {
    let d;
    try {
      const r = await fetch('/__cc/whatsapp/qr', { credentials: 'same-origin' });
      if (r.status === 401) { $('err').textContent = 'Your session on this agent has expired. Open WhatsApp again from your ControlClaw console.'; $('err').className = 'err show'; return; }
      d = await r.json();
    } catch (e) { setTimeout(tick, 4000); return; }
    if (d.state === 'qr' && d.qrDataUrl) {
      if (d.qrDataUrl !== last) { last = d.qrDataUrl; const img = new Image(); img.alt = 'WhatsApp link code'; img.width = 256; img.height = 256; img.src = d.qrDataUrl; $('qr').replaceChildren(img); }
      $('lead').textContent = 'On your phone, open WhatsApp, go to Linked devices, and scan this code.';
    } else {
      $('qr').replaceChildren();
      $('lead').textContent = TEXT[d.state] || d.message || TEXT.idle;
      if (d.state === 'connected') { $('h').textContent = 'WhatsApp is linked'; return; }
    }
    if (d.state !== 'expired' && d.state !== 'failed') setTimeout(tick, 2500);
  };
  tick();
})();