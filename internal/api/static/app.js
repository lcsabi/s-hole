const $ = id => document.getElementById(id);
const fmt = n => Number(n).toLocaleString();
// esc makes a value safe inside HTML text and inside a quoted attribute.
const esc = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
// Strip the FQDN trailing dot for display: queries are logged as the
// wire-format name ("sub.doubleclick.net."), but the dot is noise in the UI.
const stripDot = s => String(s).replace(/\.$/, '');

// Render a client cell for the log and Top Clients: the config client_names
// label (if one resolved) on top, with the stored (masked) value beneath;
// just the masked value when no label resolved. The label is server-side
// config, but esc() both anyway so a stray "<" in either never breaks out.
const clientCell = (value, label) => label
  ? `<div>${esc(label)}</div><div class="client-ip">${esc(value)}</div>`
  : esc(value);

function setTbody(id, html) { $(id).innerHTML = html; }

// ── Collapsible panels ────────────────────────────────────
// Only the three panels that own a dedicated /api/* fetch are collapsible,
// so collapsing one also skips its poll (the stat cards, Top Clients, and
// Sources all ride the single /api/stats call, so hiding them saves nothing).
// The collapsed set persists per panel in localStorage, keyed by the body id.
const COLLAPSE_KEY = 'shole.collapsed';
let collapsed = {};
try { collapsed = JSON.parse(localStorage.getItem(COLLAPSE_KEY)) || {}; } catch (e) {}
const isCollapsed = id => !!collapsed[id];

function applyCollapsed(id) {
  const on = !!collapsed[id];
  const body = $(id);
  if (body) body.hidden = on;
  const btn = document.querySelector(`[data-collapse="${id}"]`);
  if (btn) {
    btn.classList.toggle('collapsed', on);
    btn.setAttribute('aria-expanded', String(!on));
    btn.title = on ? 'Expand' : 'Collapse';
  }
}

function refreshPanel(id) {
  // Refetch just the just-expanded panel so it fills immediately instead of
  // waiting for the next 3 s tick.
  if (id === 'history-body') refreshHistory();
  else if (id === 'queries-table') refreshQueries();
  else refresh();
}

function togglePanel(id) {
  collapsed[id] = !collapsed[id];
  try { localStorage.setItem(COLLAPSE_KEY, JSON.stringify(collapsed)); } catch (e) {}
  applyCollapsed(id);
  if (!collapsed[id]) refreshPanel(id);
}

// ── Recent Queries filter ─────────────────────────────────
// The filter runs server-side in SQL over the stored columns, so it can only
// match what the query_log.clients mode wrote. The state lives in
// sessionStorage, not localStorage: a typed domain search is query data, and
// it must not stay in the browser profile after the tab is closed. A stale
// filter is safe because the active-filter row below is always visible and
// the empty state names the filter. The client filter is gated on the
// client mode: 'drop' stores no client, so the picker is hidden.
const QUERY_FILTER_KEY = 'shole.queryFilter';
let queryFilter = { domain: '', status: 'all', client: '' };
try { localStorage.removeItem(QUERY_FILTER_KEY); } catch (e) {} // left by older versions
try {
  const saved = JSON.parse(sessionStorage.getItem(QUERY_FILTER_KEY));
  if (saved && typeof saved === 'object') {
    if (typeof saved.domain === 'string') queryFilter.domain = saved.domain.trim();
    if (['all', 'true', 'false', 'unresolved', 'upstream-error'].includes(saved.status)) queryFilter.status = saved.status;
    if (typeof saved.client === 'string') queryFilter.client = saved.client;
  }
} catch (e) {}

function saveQueryFilter() {
  try { sessionStorage.setItem(QUERY_FILTER_KEY, JSON.stringify(queryFilter)); } catch (e) {}
}

const queryFilterActive = () =>
  !!queryFilter.domain || !!queryFilter.client || queryFilter.status !== 'all';

// Set the shared query-filter params (domain, client, and the exclusive
// status picker) on p. The recent-query view and the export both call it, so
// a filtered export stays exactly the filtered view in bulk: one change here
// moves both.
function applyFilterParams(p) {
  if (queryFilter.domain) p.set('domain', queryFilter.domain);
  if (queryFilter.client) p.set('client', queryFilter.client);
  // The status control is one exclusive picker over two server params:
  // blocked true/false, or a failure outcome.
  if (queryFilter.status === 'true' || queryFilter.status === 'false') p.set('blocked', queryFilter.status);
  else if (queryFilter.status !== 'all') p.set('outcome', queryFilter.status);
}

function queriesURL() {
  const p = new URLSearchParams({ limit: '50' });
  applyFilterParams(p);
  return '/api/queries?' + p.toString();
}

// Build the export URL for the current filter. It shares queriesURL's filter
// params through applyFilterParams but drops ?limit= (export streams the whole
// filtered log) and adds ?format=.
function exportURL(format) {
  const p = new URLSearchParams();
  applyFilterParams(p);
  p.set('format', format);
  return '/api/queries/export?' + p.toString();
}

// Point the export links at the current filter, and grey them when there is
// no stored history (nothing to export). The settings are known once
// /api/stats has answered; until then the links stay enabled rather than
// falsely greying a working export.
function updateExportControls() {
  const off = privacy !== null && !storedHistory();
  for (const format of ['csv', 'json']) {
    const a = $('export-' + format);
    if (!a) continue;
    a.classList.toggle('disabled', off);
    a.setAttribute('aria-disabled', off ? 'true' : 'false');
    if (off) {
      a.removeAttribute('href');
      a.title = 'No stored history to export (query_log.database is "off" or query_log.mode is "none")';
    } else {
      a.href = exportURL(format);
      a.title = 'Download the current filter as ' + format.toUpperCase();
    }
  }
}

// Show the active-filter row and describe the current filter in words. Kept
// visible whenever a filter is set, so a restored filter is never a mystery.
function renderFilterBar() {
  updateExportControls();
  const active = queryFilterActive();
  $('qf-bar').hidden = !active;
  if (!active) return;
  const parts = [];
  if (queryFilter.domain) parts.push(`domain contains "${queryFilter.domain}"`);
  if (queryFilter.status === 'true') parts.push('blocked only');
  else if (queryFilter.status === 'false') parts.push('allowed only');
  else if (queryFilter.status === 'unresolved') parts.push('unresolved only');
  else if (queryFilter.status === 'upstream-error') parts.push('upstream errors only');
  if (queryFilter.client) parts.push(`client ${queryFilter.client}`);
  $('qf-summary').textContent = 'Filtering: ' + parts.join(', ');
}

// Push the current filter state into the controls (used on load and on clear).
function syncFilterControls() {
  $('qf-domain').value = queryFilter.domain;
  for (const b of $('qf-status').children) {
    b.classList.toggle('active', b.dataset.status === queryFilter.status);
  }
  ensureClientOption(queryFilter.client);
  $('qf-client').value = queryFilter.client;
}

// Keep a selected client selectable before the first stats response arrives,
// and for a client that is not in the current Top Clients list.
function ensureClientOption(value) {
  if (!value) return;
  const sel = $('qf-client');
  if (![...sel.options].some(o => o.value === value)) {
    const o = document.createElement('option');
    o.value = value;
    o.textContent = value;
    sel.appendChild(o);
  }
}

// Populate the client picker from Top Clients and gate it on the privacy mode.
// Under 'drop' no client is stored, so hide the picker and clear any restored
// client filter (it cannot match). Otherwise list the known clients; a still
// selected value that is not in the list is kept as an option so a filter for a
// less-chatty device survives.
function updateClientPicker(privacy, clients) {
  const sel = $('qf-client');
  if (privacy === 'drop') {
    sel.hidden = true;
    if (queryFilter.client) {
      queryFilter.client = '';
      saveQueryFilter();
      renderFilterBar();
      refreshQueries();
    }
    return;
  }
  sel.hidden = false;
  const values = clients.map(c => c.name).filter(Boolean);
  const sig = values.join('|') + '::' + queryFilter.client;
  if (sel.dataset.sig === sig) return;
  sel.dataset.sig = sig;
  const opts = ['<option value="">All clients</option>'];
  for (const c of clients) {
    if (!c.name) continue;
    const text = c.label ? `${c.label} (${c.name})` : c.name;
    opts.push(`<option value="${esc(c.name)}">${esc(text)}</option>`);
  }
  if (queryFilter.client && !values.includes(queryFilter.client)) {
    opts.push(`<option value="${esc(queryFilter.client)}">${esc(queryFilter.client)}</option>`);
  }
  sel.innerHTML = opts.join('');
  sel.value = queryFilter.client;
}

// Per-row status badge. The server computes q.outcome from the stored row
// (see QueryRow.Outcome), so the failure rule stays in Go and SQL and the
// dashboard just maps the label to a badge.
function outcomeBadge(q) {
  switch (q.outcome) {
    case 'blocked':
      // A CNAME block: the name is on no list, but it points to a domain
      // that is (CL 117). The row never holds that target domain.
      return q.blocked_by === 'cname'
        ? '<span class="badge badge-block" title="The name points (CNAME) to a blocked domain">BLOCK · CNAME</span>'
        : '<span class="badge badge-block">BLOCK</span>';
    case 'unresolved': return '<span class="badge badge-unresolved">UNRESOLVED</span>';
    case 'upstream_error': return '<span class="badge badge-upstream">UPSTREAM ERR</span>';
    default: return '<span class="badge badge-allow">ALLOW</span>';
  }
}

// Fetch and render the recent-queries table for the current filter. Split out
// of refresh() so a filter change can refetch at once, not on the next tick.
async function refreshQueries() {
  if (isCollapsed('queries-table')) return;
  try {
    const { queries } = await fetch(queriesURL()).then(r => r.json());
    const rows = queries || [];
    setTbody('queries', rows.length
      ? rows.map(q => {
        const badge = outcomeBadge(q);
        const t = new Date(q.ts).toLocaleTimeString();
        return `<tr>
          <td class="muted num">${t}</td>
          <td class="mono">${clientCell(q.client_ip, q.label)}</td>
          <td class="mono">${esc(stripDot(q.domain))}</td>
          <td>${badge}</td>
        </tr>`;
      }).join('')
      : `<tr><td colspan="4" class="empty">${queryFilterActive()
          ? 'No queries match the filter'
          : historyEmptyText()}</td></tr>`);
  } catch (e) { console.error('queries fetch failed:', e); }
}

// ── What s-hole records ───────────────────────────────────
// privacy is the /api/stats "privacy" object: the query_log mode and
// clients settings, whether the database and the log file are on, and the
// retention. null until the first stats response.
let privacy = null;

// storedHistory reports whether s-hole keeps a query history: the database
// is on and the mode records queries. The Recent Queries panel, the export,
// the Stored list, and the 7d graph need it.
const storedHistory = () => !!privacy && privacy.database && privacy.mode !== 'none';

// historyEmptyText explains an empty Recent Queries panel by its setting.
function historyEmptyText() {
  if (!privacy) return 'Loading…';
  if (privacy.mode === 'none') return 'No queries are recorded (query_log.mode is "none").';
  if (!privacy.database) return 'No query history is stored (query_log.database is "off").';
  return 'No queries recorded yet';
}

// renderPrivacy shows what s-hole records in the header, a badge when it
// records which device asked, and the privacy and security warnings in
// effect: the same list the stats line repeats in the log.
function renderPrivacy(p, warnings) {
  privacy = p;
  $('rec-mode').textContent = p.mode === 'none' ? 'nothing' : p.mode === 'blocked' ? 'blocked queries' : 'all queries';
  $('rec-clients').textContent = p.clients;
  let hist = 'off';
  if (storedHistory()) hist = p.retention_days > 0 ? `${p.retention_days} days` : 'forever';
  $('rec-history').textContent = hist;
  const badge = $('rec-badge');
  if (p.mode !== 'none' && p.clients === 'full') {
    badge.className = 'badge badge-block';
    badge.textContent = 'PER-DEVICE HISTORY ON';
    badge.title = 'query_log.clients is "full": s-hole records which device sent each query';
    badge.hidden = false;
  } else if (p.mode !== 'none' && p.clients === 'subnet') {
    badge.className = 'badge badge-unresolved';
    badge.textContent = 'SUBNETS RECORDED';
    badge.title = 'query_log.clients is "subnet": s-hole records the subnet of each device';
    badge.hidden = false;
  } else {
    badge.hidden = true;
  }

  const list = warnings || [];
  $('warn-panel').hidden = list.length === 0;
  $('warn-count').textContent = list.length ? `(${list.length})` : '';
  $('warn-list').innerHTML = list.map(w => {
    const i = w.indexOf(': ');
    return i > 0
      ? `<li><code>${esc(w.slice(0, i))}</code>: ${esc(w.slice(i + 2))}</li>`
      : `<li>${esc(w)}</li>`;
  }).join('');

  // The 7d graph and the Stored list read the stored history; hide them
  // when there is none, and fall back to what memory holds.
  const stored = storedHistory();
  $('history-7d').hidden = !stored;
  $('domains-stored').hidden = !stored;
  if (!stored && historyWindow !== '24h') selectHistoryWindow('24h');
  if (!stored && domainsMode !== 'start') selectDomainsMode('start');
  updateExportControls();
}

// ── Query-volume chart ────────────────────────────────────
let historyWindow = '24h';
let historySeries = [];
// Where the series comes from: 'memory' (per-minute counts for the last 24
// hours) or 'database' (the stored history, for the 7d window).
// historyLogging is the query_log.mode the series reflects; both sources
// follow it. Under 'blocked' the series holds blocked queries only, so the
// graph draws one labeled blocked line. Under 'none' s-hole records no
// counts over time, so the graph shows a note instead. It is '' until the
// first answer.
let historySource = 'memory';
let historyLogging = '';

// hexA turns a #rrggbb color (read from the theme CSS variables) into an
// rgba() string, matching how the rest of the sheet writes translucent fills.
function hexA(hex, a) {
  const h = hex.replace('#', '');
  const r = parseInt(h.substring(0, 2), 16);
  const g = parseInt(h.substring(2, 4), 16);
  const b = parseInt(h.substring(4, 6), 16);
  return `rgba(${r},${g},${b},${a})`;
}

async function refreshHistory() {
  if (isCollapsed('history-body')) return;
  try {
    const data = await fetch(`/api/history?window=${historyWindow}&bucket=1h`).then(r => r.json());
    historySeries = data.series || [];
    historySource = data.source || 'memory';
    historyLogging = data.logging || 'none';
    drawHistory();
  } catch (e) { console.error('history fetch failed:', e); }
}

// Layout paddings shared by the drawing and the hover hit-test.
const CHART_PAD = { l: 44, r: 12, t: 12, b: 24 };

function drawHistory() {
  const canvas = $('history-canvas');
  const empty = $('history-empty');
  const series = historySeries;
  const mode = historyLogging;

  // Label the graph honestly for the mode: when only blocked queries are
  // logged, hide the Total swatch and note it, so the single line is not
  // read as total traffic.
  const blockedOnly = mode === 'blocked';
  $('legend-total').hidden = blockedOnly;
  // Cache hits are allowed queries, so they are never logged under
  // "blocked"; hide the Cached swatch with Total in that mode. Failures are
  // allowed queries too (a blocked query never forwards), so hide the two
  // failure swatches the same way.
  $('legend-cached').hidden = blockedOnly;
  $('legend-unresolved').hidden = blockedOnly;
  $('legend-upstream').hidden = blockedOnly;
  const where = historySource === 'memory' ? 'counts only, kept in memory, last 24 hours' : 'stored history';
  $('history-note').textContent = blockedOnly
    ? where + '; blocked queries only (query_log.mode is "blocked")'
    : where;

  // Under "none" s-hole records no counts over time (the per-minute graph
  // follows query_log.mode), so say why the graph is empty instead of
  // drawing a flat line that reads as a quiet network.
  const off = mode === 'none';
  $('history-legend').hidden = off;
  if (off) {
    $('history-note').textContent = '';
    canvas.hidden = true;
    empty.hidden = false;
    empty.textContent = 'The graph is off: query_log.mode is "none", so s-hole does not record when queries occur. To turn it on, set query_log.mode to "blocked" or "all".';
    return;
  }

  // No series yet (the first poll has not answered). A quiet network still
  // gets a real zero-filled series, a flat line at the baseline.
  if (!series.length) {
    canvas.hidden = true;
    empty.hidden = false;
    empty.textContent = 'Loading…';
    return;
  }
  canvas.hidden = false;
  empty.hidden = true;

  const wrap = canvas.parentElement;
  const dpr = window.devicePixelRatio || 1;
  const cssW = wrap.clientWidth, cssH = wrap.clientHeight;
  canvas.width = Math.round(cssW * dpr);
  canvas.height = Math.round(cssH * dpr);
  const ctx = canvas.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, cssW, cssH);

  const css = getComputedStyle(document.documentElement);
  const color = (name, fallback) => (css.getPropertyValue(name).trim() || fallback);
  const red = color('--red', '#f87171');
  const violet = color('--violet', '#c4b5fd');
  const teal = color('--teal', '#2dd4bf');
  const amber = color('--amber', '#fbbf24');
  const orange = color('--orange', '#fb923c');
  const muted = color('--muted', '#64748b');
  const border = color('--border', '#252836');

  const { l: padL, r: padR, t: padT, b: padB } = CHART_PAD;
  const plotW = cssW - padL - padR, plotH = cssH - padT - padB;
  const n = series.length;

  // Under "blocked" the stored history holds only blocked rows (total ==
  // blocked), so draw the blocked line alone and scale to it; under "all"
  // (and for the in-memory counts) the total line is the envelope, so scale
  // to total.
  const drawTotal = mode === 'all';
  const maxKey = drawTotal ? 'total' : 'blocked';
  let max = 0;
  for (const b of series) if (b[maxKey] > max) max = b[maxKey];
  if (max < 1) max = 1; // avoid divide-by-zero; a flat idle line sits at 0

  const x = i => padL + (n === 1 ? plotW / 2 : plotW * i / (n - 1));
  const y = v => padT + plotH * (1 - v / max);

  // Baseline + max gridline with y labels.
  ctx.font = '10px system-ui';
  ctx.textBaseline = 'middle';
  ctx.strokeStyle = border;
  ctx.lineWidth = 1;
  ctx.fillStyle = muted;
  ctx.textAlign = 'right';
  for (const gv of [0, max]) {
    const gy = y(gv);
    ctx.beginPath();
    ctx.moveTo(padL, gy);
    ctx.lineTo(padL + plotW, gy);
    ctx.stroke();
    ctx.fillText(fmt(gv), padL - 6, gy);
  }

  const drawSeries = (key, stroke, fill) => {
    ctx.beginPath();
    ctx.moveTo(x(0), y(0));
    for (let i = 0; i < n; i++) ctx.lineTo(x(i), y(series[i][key]));
    ctx.lineTo(x(n - 1), y(0));
    ctx.closePath();
    ctx.fillStyle = fill;
    ctx.fill();
    ctx.beginPath();
    for (let i = 0; i < n; i++) {
      const px = x(i), py = y(series[i][key]);
      i ? ctx.lineTo(px, py) : ctx.moveTo(px, py);
    }
    ctx.strokeStyle = stroke;
    ctx.lineWidth = 1.5;
    ctx.stroke();
  };
  // Draw total (the envelope) first, then cached, then the failure lines,
  // then blocked on top. Cached and the two failure series are only present
  // under "all" (they are allowed queries); each is a subset of the
  // forwarded remainder, so all scale to the same total max and never
  // overshoot the envelope. Failures draw last of the "all"-only series so
  // a spike stays visible over cached.
  if (drawTotal) drawSeries('total', violet, hexA(violet, 0.12));
  if (drawTotal) drawSeries('cached', teal, hexA(teal, 0.14));
  if (drawTotal) drawSeries('unresolved', amber, hexA(amber, 0.16));
  if (drawTotal) drawSeries('upstream_error', orange, hexA(orange, 0.16));
  drawSeries('blocked', red, hexA(red, 0.16));

  // A few thinned x-axis time labels. The first and last labels align to
  // their tick from the inside, so the canvas edge does not cut them off;
  // the others center on their tick.
  ctx.fillStyle = muted;
  ctx.textBaseline = 'top';
  const labels = Math.min(6, n);
  for (let k = 0; k < labels; k++) {
    const i = labels === 1 ? 0 : Math.round(k * (n - 1) / (labels - 1));
    const d = new Date(series[i].start * 1000);
    const lbl = historyWindow === '24h'
      ? d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      : d.toLocaleDateString([], { month: 'short', day: 'numeric' });
    ctx.textAlign = labels === 1 ? 'center'
      : k === 0 ? 'left' : k === labels - 1 ? 'right' : 'center';
    ctx.fillText(lbl, x(i), padT + plotH + 6);
  }
}

function setupHistoryHover() {
  const canvas = $('history-canvas');
  const tip = $('history-tip');
  canvas.addEventListener('mousemove', ev => {
    const series = historySeries;
    const n = series.length;
    if (!n) { tip.hidden = true; return; }
    const rect = canvas.getBoundingClientRect();
    const plotW = rect.width - CHART_PAD.l - CHART_PAD.r;
    const mx = ev.clientX - rect.left;
    let i = n === 1 ? 0 : Math.round((mx - CHART_PAD.l) / (plotW / (n - 1)));
    i = Math.max(0, Math.min(n - 1, i));
    const b = series[i];
    const d = new Date(b.start * 1000);
    const when = historyWindow === '24h'
      ? d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      : d.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit' });
    const extraLines = historyLogging === 'blocked'
      ? ''
      : `<br><span style="color:var(--violet)">total ${fmt(b.total)}</span>`
        + `<br><span style="color:var(--teal)">cached ${fmt(b.cached)}</span>`
        + `<br><span style="color:var(--amber)">unresolved ${fmt(b.unresolved)}</span>`
        + `<br><span style="color:var(--orange)">upstream error ${fmt(b.upstream_error)}</span>`;
    tip.innerHTML = `<strong>${when}</strong>${extraLines}`
      + `<br><span style="color:var(--red)">blocked ${fmt(b.blocked)}</span>`;
    tip.hidden = false;
    const wrapW = canvas.parentElement.clientWidth;
    let left = mx + 12;
    if (left + tip.offsetWidth + 8 > wrapW) left = mx - tip.offsetWidth - 12;
    tip.style.left = Math.max(0, left) + 'px';
    tip.style.top = (ev.clientY - rect.top + 8) + 'px';
  });
  canvas.addEventListener('mouseleave', () => { tip.hidden = true; });
}

// Render the per-source blocklist health from /api/stats. A source is
// STALE when it is served from its on-disk cache after a failed fetch, or
// has never loaded (zero last_refresh, shown as "never").
function renderSources(sources) {
  const list = sources || [];
  $('sources-count').textContent = list.length ? `(${list.length})` : '';
  setTbody('sources', list.length
    ? list.map(s => {
        let label = s.url;
        try { const u = new URL(s.url); label = u.hostname + u.pathname; } catch (e) {}
        const never = new Date(s.last_refresh).getFullYear() < 1970;
        const when = never
          ? '<span class="muted">never</span>'
          : new Date(s.last_refresh).toLocaleString();
        const status = s.stale
          ? '<span class="badge badge-block">STALE</span>'
          : '<span class="badge badge-allow">OK</span>';
        return `<tr>
          <td class="mono">${esc(label)}</td>
          <td class="muted num">${fmt(s.count)}</td>
          <td class="muted">${when}</td>
          <td>${status}</td>
        </tr>`;
      }).join('')
    : '<tr><td colspan="4" class="empty">No blocklist sources configured</td></tr>');
}

// Render the DNS-over-TLS status in the header from /api/stats. The server
// computes the state and the days left (so the browser clock does not
// matter); the dashboard maps them to a badge. The line is hidden while
// DoT is off. The tooltip lists the certificate names, the expiry, and the
// last reload error, if any.
function renderDoT(dot) {
  const meta = $('dot-meta');
  if (!dot || !dot.enabled) {
    meta.hidden = true;
    return;
  }
  meta.hidden = false;
  const days = dot.expires_in_days;
  const dayText = days === 1 ? '1 day' : `${days} days`;
  let cls = 'badge-allow', text = 'OK', detail = `${dayText} left`;
  switch (dot.state) {
    case 'expiring':
      cls = 'badge-unresolved'; text = 'EXPIRES SOON'; detail = `${dayText} left`;
      break;
    case 'expired':
      cls = 'badge-block'; text = 'EXPIRED'; detail = 'renew the certificate and reload';
      break;
    case 'reload_failed':
      cls = 'badge-block'; text = 'RELOAD FAILED'; detail = 'still serving the previous certificate';
      break;
  }
  const el = $('dot-status');
  el.className = 'badge ' + cls;
  el.textContent = text;
  $('dot-detail').textContent = detail;
  const lines = [
    `Certificate for: ${(dot.names || []).join(', ') || 'unknown'}`,
    `Expires: ${new Date(dot.not_after).toLocaleString()}`,
  ];
  if (dot.last_reload) lines.push(`Last reload: ${new Date(dot.last_reload).toLocaleString()}`);
  if (dot.last_reload_error) lines.push(`Last reload error: ${dot.last_reload_error}`);
  meta.title = lines.join('\n');
}

// 'start' = in-memory tally from /api/stats (resets on restart);
// 'all' = the stored tally from /api/top-blocked (SQLite, survives restart).
let domainsMode = 'start';

function renderTopDomains(domains, emptyMsg) {
  setTbody('top-domains', domains.length
    ? domains.map(e =>
      `<tr><td class="mono">${esc(stripDot(e.name))}</td><td class="muted num">${fmt(e.count)}</td></tr>`
    ).join('')
    : `<tr><td colspan="2" class="empty">${emptyMsg}</td></tr>`);
  $('domains-count').textContent = domains.length ? `(${domains.length})` : '';
}

// Fetch and render the stored list independently of the stats poll so
// the toggle updates instantly on click and on each refresh tick.
async function refreshTopDomainsAllTime() {
  try {
    const { domains } = await fetch('/api/top-blocked?limit=10').then(r => r.json());
    renderTopDomains(domains || [], 'No blocked queries in the stored history');
  } catch (e) { console.error('top-blocked fetch failed:', e); }
}

async function refresh() {
  try {
    const s = await fetch('/api/stats').then(r => r.json());
    $('uptime').textContent = s.uptime;
    $('last-refresh').textContent = new Date().toLocaleTimeString();
    $('stat-total').textContent = fmt(s.total_queries);
    $('stat-blocked').textContent = fmt(s.blocked_count);
    $('stat-cname').textContent = fmt(s.cname_blocked_count) + ' through CNAME';
    $('stat-pct').textContent = s.blocked_pct.toFixed(1) + '%';
    $('stat-cache').textContent = s.cache_hit_pct.toFixed(1) + '%';
    $('stat-blocklist').textContent = fmt(s.blocklist_size);

    const p = s.privacy || { mode: 'none', clients: 'drop', database: false, file: 'off', retention_days: 0 };
    renderPrivacy(p, s.warnings);

    if (!isCollapsed('domains-table')) {
      if (domainsMode === 'all') {
        await refreshTopDomainsAllTime();
      } else {
        renderTopDomains(s.top_domains || [], p.mode === 'none'
          ? 'Not recorded (query_log.mode is "none")'
          : 'No blocked queries yet');
      }
    }

    // The Top Clients panel describes itself from the query_log settings.
    // "none" records nothing and "drop" records no client, so the panel
    // says so instead of showing blank rows. "subnet" keeps the list but
    // notes the entries are subnet-masked. "full" is the plain list.
    const clientMode = p.mode === 'none' ? 'drop' : p.clients;
    const clients = s.top_clients || [];
    const cap = $('clients-cap');
    if (clientMode === 'drop') {
      cap.textContent = p.mode === 'none'
        ? 'No queries are recorded (query_log.mode is "none").'
        : 'Clients are not recorded (query_log.clients is "drop").';
      cap.hidden = false;
      setTbody('top-clients', '<tr><td colspan="2" class="empty">Clients not recorded</td></tr>');
      $('clients-count').textContent = '';
    } else {
      if (clientMode === 'subnet') {
        cap.textContent = 'Clients are subnet-masked (query_log.clients is "subnet").';
        cap.hidden = false;
      } else {
        cap.hidden = true;
      }
      setTbody('top-clients', clients.length
        ? clients.map(e =>
          `<tr><td class="mono">${clientCell(e.name, e.label)}</td><td class="muted num">${fmt(e.count)}</td></tr>`
        ).join('')
        : '<tr><td colspan="2" class="empty">No queries yet</td></tr>');
      $('clients-count').textContent = clients.length ? `(${clients.length})` : '';
    }
    updateClientPicker(clientMode, clients);

    renderSources(s.sources || []);
    renderDoT(s.dot);
  } catch (e) { console.error('stats fetch failed:', e); }

  refreshHistory();
  await refreshQueries();
}

async function reloadBlocklists() {
  try {
    const res = await fetch('/api/reload', { method: 'POST' });
    if (!res.ok) { flash('✗ Request failed', false); return; }
    const body = await res.json();
    flash(body.status === 'reload queued'
      ? '✓ Reload queued: it runs after the current reload'
      : '✓ Reload triggered', true);
  } catch (e) { flash('✗ ' + e.message, false); }
}

async function addAllowlist(e) {
  e.preventDefault();
  const input = $('wl-input');
  const domain = input.value.trim();
  if (!domain) return;
  try {
    const res = await fetch('/api/allowlist', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain }),
    });
    if (res.ok) { input.value = ''; flash(`✓ ${domain} allowlisted`, true); }
    else if (res.status === 400 || res.status === 409) flash('✗ ' + (await res.text()).trim(), false, 10000);
    else flash('✗ Request failed', false);
  } catch (e) { flash('✗ ' + e.message, false); }
}

// Delete everything s-hole stored (POST /api/purge). The server accepts it
// only from the s-hole host itself, so on another device the reply says
// where to run it.
async function purgeHistory() {
  if (!confirm('Delete the query history and everything else s-hole stored?\n\n' +
      'This deletes the stored queries, the query log file, the downloaded blocklists, ' +
      'the Top lists, the graph, and the DNS cache. You cannot undo it. The allowlist stays.')) return;
  try {
    const res = await fetch('/api/purge', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ confirm: true }),
    });
    if (res.status === 403) { flash('✗ ' + (await res.text()).trim(), false, 10000); return; }
    const rep = await res.json().catch(() => null);
    if (!res.ok || !rep) { flash('✗ Delete failed. See the s-hole log', false); return; }
    const failed = (rep.steps || []).filter(s => s.failed);
    flash(failed.length
      ? '✗ Some data was not deleted: ' + failed.map(s => s.what).join(', ')
      : '✓ History deleted', !failed.length);
    refresh();
  } catch (e) { flash('✗ ' + e.message, false); }
}

function flash(text, ok, ms = 3000) {
  const el = $('action-msg');
  el.textContent = text;
  el.className = 'action-msg ' + (ok ? 'ok' : 'err');
  setTimeout(() => { el.textContent = ''; el.className = 'action-msg'; }, ms);
}

// Diagnostic: ask the server why a domain is (or is not) blocked. Shows the
// decision, the block entry that matched, any allowlist entry that overrode
// it, and the full suffix walk that produced the decision. Changes no state.
async function checkDomain(e) {
  e.preventDefault();
  const domain = $('check-input').value.trim();
  const el = $('check-result');
  if (!domain) return;
  try {
    const res = await fetch('/api/check?domain=' + encodeURIComponent(domain));
    if (!res.ok) { el.innerHTML = '<span style="color:var(--red)">✗ invalid domain</span>'; return; }
    const r = await res.json();

    let summary = `<span class="dec-${esc(r.decision)}">${esc(r.domain)}: ${r.decision.toUpperCase()}</span>`;
    if (r.decision === 'blocked') {
      summary += ` <span class="muted">matched ${esc(r.matched_block)}</span>`;
    } else if (r.decision === 'allowlisted') {
      summary += ` <span class="muted">by ${esc(r.matched_allowlist)}`;
      summary += r.matched_block ? `, overrides block ${esc(r.matched_block)}</span>` : '</span>';
    }

    // Full walk: each label-suffix that was checked, most specific first,
    // with a badge on the level that matched the block set or allowlist.
    const walk = (r.walk || []).map(l => {
      let tags = '';
      if (l.blocked) tags += ' <span class="badge badge-block">BLOCK</span>';
      if (l.allowlisted) tags += ' <span class="badge badge-allow">ALLOW</span>';
      return `<div><span class="mono muted">${esc(l.suffix)}</span>${tags}</div>`;
    }).join('');

    el.innerHTML = summary + `<div class="check-walk">${walk}</div>`;
  } catch (e) { el.innerHTML = '<span style="color:var(--red)">✗ ' + esc(e.message) + '</span>'; }
}

// Top Blocked "Since start / Stored" toggle.
function selectDomainsMode(mode) {
  domainsMode = mode;
  for (const b of $('domains-mode').children) {
    b.classList.toggle('active', b.dataset.mode === domainsMode);
  }
}
$('domains-mode').addEventListener('click', e => {
  const btn = e.target.closest('button[data-mode]');
  if (!btn || btn.dataset.mode === domainsMode) return;
  selectDomainsMode(btn.dataset.mode);
  // Redraw immediately from the correct source instead of waiting for
  // the next 3 s tick.
  if (domainsMode === 'all') {
    refreshTopDomainsAllTime();
  } else {
    refresh();
  }
});

// Query-volume 24h / 7d window toggle.
function selectHistoryWindow(w) {
  historyWindow = w;
  for (const b of $('history-window').children) {
    b.classList.toggle('active', b.dataset.window === historyWindow);
  }
}
$('history-window').addEventListener('click', e => {
  const btn = e.target.closest('button[data-window]');
  if (!btn || btn.dataset.window === historyWindow) return;
  selectHistoryWindow(btn.dataset.window);
  refreshHistory();
});

// Recent Queries filter: domain input (debounced), status toggle, client
// picker, and clear. Each change saves the state and refetches at once.
let domainDebounce;
$('qf-domain').addEventListener('input', e => {
  queryFilter.domain = e.target.value.trim();
  saveQueryFilter();
  renderFilterBar();
  clearTimeout(domainDebounce);
  domainDebounce = setTimeout(refreshQueries, 300);
});

$('qf-status').addEventListener('click', e => {
  const btn = e.target.closest('button[data-status]');
  if (!btn || btn.dataset.status === queryFilter.status) return;
  queryFilter.status = btn.dataset.status;
  for (const b of $('qf-status').children) {
    b.classList.toggle('active', b.dataset.status === queryFilter.status);
  }
  saveQueryFilter();
  renderFilterBar();
  refreshQueries();
});

$('qf-client').addEventListener('change', e => {
  queryFilter.client = e.target.value;
  saveQueryFilter();
  renderFilterBar();
  refreshQueries();
});

$('qf-clear').addEventListener('click', () => {
  queryFilter = { domain: '', status: 'all', client: '' };
  try { sessionStorage.removeItem(QUERY_FILTER_KEY); } catch (e) {}
  syncFilterControls();
  renderFilterBar();
  refreshQueries();
});

// The page has no inline event handlers (the Content-Security-Policy allows
// no inline script), so the controls are wired here.
document.querySelectorAll('.collapse-btn[data-collapse]').forEach(b =>
  b.addEventListener('click', () => togglePanel(b.dataset.collapse)));
$('reload-btn').addEventListener('click', reloadBlocklists);
$('wl-form').addEventListener('submit', addAllowlist);
$('check-form').addEventListener('submit', checkDomain);
$('purge-btn').addEventListener('click', purgeHistory);

// Restore collapsed panels and the saved filter, wire the chart hover, and
// keep the canvas crisp on resize, before the first poll so the fetch guards
// and the filter URL see the right state.
['history-body', 'domains-table', 'queries-table'].forEach(applyCollapsed);
syncFilterControls();
renderFilterBar();
setupHistoryHover();
window.addEventListener('resize', drawHistory);

setInterval(refresh, 3000);
refresh();
