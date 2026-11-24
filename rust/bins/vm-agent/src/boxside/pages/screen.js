// The Screen page: the agent's Chrome (noVNC's RFB, loaded from this agent after the view check)
// in the shell's main panel. Kept in a module so noVNC's own module can be imported once the
// browser holds a view pass; before that its files answer 401.
const RFB_URL = ${RFB_URL};
const WS_PATH = ${WS_PATH};
const $ = (id) => document.getElementById(id);
const stage = $('stage'), view = $('view'), screen = $('screen');
let rfb = null, RFB = null, viewOnly = false, cssFull = false, denied = false, tries = 0, reload = false;

const STATES = {
  connecting: ['Connecting', 'bg-muted-foreground', 'border-line bg-bg-2 text-ink-2'],
  live: ['Live', 'bg-allow', 'border-allow-border bg-allow-soft text-allow-fg'],
  off: ['Disconnected', 'bg-ask', 'border-ask-border bg-ask-soft text-ask-fg'],
  denied: ['Not signed in', 'bg-block', 'border-block-border bg-block-soft text-block-fg'],
};
function setState(s) {
  const [text, dot, pill] = STATES[s];
  $('state-text').textContent = text;
  $('state-dot').className = 'h-[6px] w-[6px] rounded-full ' + dot;
  $('state').className = 'inline-flex h-[24px] shrink-0 items-center gap-1.5 rounded-full border px-2.5 text-[12px] font-semibold ' + pill;
  $('mode').hidden = s !== 'live';
  $('full').hidden = s !== 'live' && !isFull();
  $('reconnect').hidden = s !== 'off';
  $('reconnect-text').textContent = reload ? 'Reload page' : 'Reconnect';
}
function message(title, text, opts) {
  $('msg').hidden = false;
  $('msg-title').textContent = title;
  $('msg-text').textContent = text;
  $('msg-spin').hidden = !(opts && opts.spin);
  $('msg-console').hidden = !(opts && opts.console);
}
function notSignedIn(text) {
  denied = true;
  setState('denied');
  message('Not signed in to this screen', text || 'Press Screen on this agent in your ControlClaw console to open its browser here.', { console: true });
}

async function connect() {
  setState('connecting');
  message('Connecting to the live view', 'The agent’s browser appears here in a moment.', { spin: true });
  // Asked on every connect, not only the first: a pass or session that ended while watching makes
  // Caddy refuse the WebSocket too, and noVNC reports that as a plain disconnect.
  let status = 0;
  try { status = (await fetch(RFB_URL, { credentials: 'same-origin', cache: 'no-store' })).status; } catch (e) { /* network */ }
  if (status === 401 || status === 403) { notSignedIn(); return; }
  if (!RFB) {
    try {
      // A failed module import is cached for the page. The first retry asks for a fresh URL; if a
      // module rfb.js imports failed, that stays cached too, so after a second failure only a
      // reload of the page helps.
      RFB = (await import(tries++ ? RFB_URL + '?r=' + tries : RFB_URL)).default;
    } catch (e) {
      reload = tries > 1;
      setState('off');
      message('Could not reach the agent', reload
        ? 'The live view still did not load. Reload the page to try again.'
        : 'The live view did not load. Reconnect to try again.', {});
      return;
    }
  }
  if (rfb) { try { rfb.disconnect(); } catch (e) { /* already closed */ } }
  screen.textContent = '';
  const url = (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + WS_PATH;
  rfb = new RFB(screen, url);
  rfb.scaleViewport = true;
  rfb.resizeSession = false;
  rfb.viewOnly = viewOnly;
  rfb.background = 'transparent';
  rfb.addEventListener('connect', () => { $('msg').hidden = true; setState('live'); rfb.focus(); });
  rfb.addEventListener('disconnect', () => {
    rfb = null;
    // A refused pass also ends in a disconnect: keep "Not signed in" and its console link.
    if (denied) return;
    setState('off');
    message('The live view stopped', 'The connection to the agent’s browser closed. Reconnect to see it again.', {});
  });
  rfb.addEventListener('securityfailure', () => notSignedIn('This pass no longer opens the screen. Press Screen again in your ControlClaw console.'));
}

function setViewOnly(on) {
  viewOnly = on;
  $('use').setAttribute('aria-pressed', String(!on));
  $('watch').setAttribute('aria-pressed', String(on));
  if (rfb) rfb.viewOnly = on;
}
$('use').addEventListener('click', () => setViewOnly(false));
$('watch').addEventListener('click', () => setViewOnly(true));
$('reconnect').addEventListener('click', () => {
  if (reload) { location.reload(); return; }
  denied = false;
  connect();
});

// Full screen: the Fullscreen API on the stage where there is one; elsewhere (iPhone Safari) the
// stage fills the viewport with CSS. Esc or the button returns.
const FULL_STAGE = ['fixed', 'inset-0', 'z-50', 'rounded-none', 'border-0'];
const FULL_VIEW = ['flex-1', 'aspect-auto', 'max-h-none'];
function isFull() { return document.fullscreenElement === stage || cssFull; }
function paintFull() {
  const on = isFull();
  // The Fullscreen API sizes the stage itself; the classes make the view fill it either way.
  for (const c of FULL_VIEW) view.classList.toggle(c, on);
  for (const c of FULL_STAGE) stage.classList.toggle(c, cssFull);
  document.documentElement.classList.toggle('overflow-hidden', cssFull);
  $('full-text').textContent = on ? 'Exit full screen' : 'Full screen';
  $('full').setAttribute('aria-pressed', String(on));
  if (rfb) rfb.focus();
}
$('full').addEventListener('click', async () => {
  if (isFull()) {
    if (document.fullscreenElement) await document.exitFullscreen().catch(() => {});
    cssFull = false;
    paintFull();
    return;
  }
  if (stage.requestFullscreen && document.fullscreenEnabled) {
    try { await stage.requestFullscreen(); return; } catch (e) { /* fall back to CSS below */ }
  }
  cssFull = true;
  paintFull();
});
document.addEventListener('fullscreenchange', paintFull);
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && cssFull) { cssFull = false; paintFull(); }
}, true);

(async () => {
  const t = new URLSearchParams(location.hash.slice(1)).get('t');
  if (location.hash) history.replaceState(null, '', location.pathname);
  if (t) {
    // From the console's Screen button: swap the one-shot pass for the view cookie.
    let d = {}, ok = false;
    try {
      const r = await fetch('/__cc/view-session', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token: t }) });
      d = await r.json().catch(() => ({})); ok = r.ok;
    } catch (e) {
      notSignedIn('Could not reach the agent. Press Screen again in your ControlClaw console.');
      return;
    }
    if (!ok) { notSignedIn(d.error || 'This pass has expired. Press Screen again in your ControlClaw console.'); return; }
  }
  // From the sidebar, an old link or a reload: noVNC's files are behind Caddy's view check, which
  // takes this agent's session or the view pass (a cookie only sent under /__cc/novnc). If the
  // import is refused, the browser is not signed in.
  connect();
})();
