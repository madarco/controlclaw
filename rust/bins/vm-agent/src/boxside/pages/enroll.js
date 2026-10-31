
(() => {
  const $ = (id) => document.getElementById(id);
  const NAMES = ${CHANNEL_NAMES};
  const h = new URLSearchParams(location.hash.slice(1));
  const p = h.get('p'), via = h.get('via'), e = h.get('e'), left = h.get('left');
  if (!p) { location.replace('/__cc/open#e=code_expired'); return; }
  $('p').value = p;
  // Keep the pending id in the fragment for a reload, drop the rest.
  history.replaceState(null, '', location.pathname + '#p=' + encodeURIComponent(p) + (via ? '&via=' + encodeURIComponent(via) : ''));
  if (via && NAMES[via]) $('lead').textContent = ${LEAD_START} + NAMES[via] + ${LEAD_END};
  if (e === 'invalid_code') { $('err').textContent = 'Wrong code. ' + (left === '1' ? '1 try left.' : (left || 'A few') + ' tries left.'); $('err').className = 'err show'; }
  ${CODE_BOXES_JS}
})();