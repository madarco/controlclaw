
  const plain = $('code'), go = $('go'), line = $('line'), otp = $('otp');
  const boxes = [0, 1, 2, 3, 4, 5].map((i) => $('d' + i));
  plain.hidden = true; plain.required = false; plain.removeAttribute('pattern');
  otp.hidden = false;
  let busy = false;
  const digits = (s) => String(s || '').replace(/[^0-9]/g, '');
  const sync = () => { plain.value = boxes.map((b) => b.value).join(''); go.disabled = busy || plain.value.length !== 6; };
  const fill = (i, d) => { for (const ch of d) { if (i > 5) break; boxes[i++].value = ch; } sync(); boxes[Math.min(i, 5)].focus(); };
  const idle = () => { busy = false; otp.className = 'otp'; for (const b of boxes) b.readOnly = false; go.textContent = 'Continue'; line.hidden = true; sync(); };
  boxes.forEach((b, i) => {
    b.addEventListener('focus', () => b.select());
    b.addEventListener('input', () => { const d = digits(b.value); b.value = ''; if (d.length >= 6) fill(0, d.slice(0, 6)); else if (d) fill(i, d); else sync(); });
    b.addEventListener('paste', (ev) => {
      ev.preventDefault();
      if (busy) return;
      const d = digits(ev.clipboardData && ev.clipboardData.getData('text'));
      if (d.length >= 6) fill(0, d.slice(0, 6)); else if (d) fill(i, d);
    });
    b.addEventListener('keydown', (ev) => {
      if (busy) return;
      if (ev.key === 'Backspace') {
        ev.preventDefault();
        if (b.value) b.value = ''; else if (i > 0) { boxes[i - 1].value = ''; boxes[i - 1].focus(); }
        sync();
      } else if (ev.key === 'ArrowLeft' && i > 0) { ev.preventDefault(); boxes[i - 1].focus(); }
      else if (ev.key === 'ArrowRight' && i < 5) { ev.preventDefault(); boxes[i + 1].focus(); }
    });
  });
  $('f').addEventListener('submit', (ev) => {
    if (busy || plain.value.length !== 6) { ev.preventDefault(); return; }
    busy = true;
    otp.className = 'otp busy';
    for (const b of boxes) { b.readOnly = true; if (b.blur) { b.setSelectionRange(1, 1); b.blur(); } }
    go.disabled = true;
    go.innerHTML = '<span class="spin"></span>Confirming…';
    line.innerHTML = '<span class="spin"></span>Checking the code with your firewall…';
    line.hidden = false;
    $('err').className = 'err';
  });
  // Back from the firewall to a page the browser kept: ready again, not stuck busy.
  addEventListener('pageshow', (ev) => { if (ev.persisted) { for (const b of boxes) b.value = ''; idle(); } });
  sync();
  boxes[0].focus();