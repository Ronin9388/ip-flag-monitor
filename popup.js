'use strict';
/*
 * IP & Flag Monitor — popup
 * Shows: this computer's public/local IP + flag, the viewed site's IP, and runs
 * safe, passive network checks (HTTP round-trip "ping", DoH DNS, IPv4/IPv6,
 * WebRTC leak check, viewed-site ports 80/443 + security headers).
 * Browsers cannot send ICMP pings or raw port scans, so none are attempted.
 */

const api = typeof browser !== 'undefined' ? browser : chrome;

const REFRESH_SECONDS = 60;
const PROBES = 5;
const PROBE_TIMEOUT = 3000;

// Edit these to change what is "pinged" (HTTPS round-trip timing, not ICMP).
const LATENCY_TARGETS = [
  { name: 'Cloudflare (1.1.1.1)', url: 'https://1.1.1.1/cdn-cgi/trace', method: 'GET' },
  { name: 'Google', url: 'https://www.google.com/generate_204', method: 'GET' },
  { name: 'Microsoft', url: 'https://www.msftconnecttest.com/connecttest.txt', method: 'GET' },
];

const DOH = [
  { name: 'Cloudflare', url: (n, t) => `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(n)}&type=${t}` },
  { name: 'Google', url: (n, t) => `https://dns.google/resolve?name=${encodeURIComponent(n)}&type=${t}` },
];

/* ------------------------------- helpers ------------------------------- */

const $ = (id) => document.getElementById(id);

function h(tag, props = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === 'class') el.className = v;
    else if (k === 'text') el.textContent = v;
    else if (v !== false && v != null) el.setAttribute(k, v);
  }
  for (const k of kids.flat()) {
    if (k == null || k === false) continue;
    el.append(k instanceof Node ? k : document.createTextNode(String(k)));
  }
  return el;
}

const fmt = (ms) => `${Math.round(ms)} ms`;
const clock = (d = new Date()) => d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

async function fetchJson(url, { timeout = 6000, headers } = {}) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeout);
  try {
    const r = await fetch(url, { signal: ctrl.signal, headers, cache: 'no-store', credentials: 'omit' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return await r.json();
  } finally { clearTimeout(t); }
}

function flagNode(cc) {
  if (!cc) return null;
  const img = h('img', { class: 'inline-flag', alt: cc, src: `https://flagcdn.com/w40/${cc.toLowerCase()}.png` });
  img.addEventListener('error', () => img.replaceWith(h('span', { class: 'flag-fallback', text: cc })));
  return img;
}

function copyable(text) {
  const el = h('button', { class: 'copy', type: 'button', title: 'Click to copy' }, text);
  el.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(text);
      el.classList.add('copied');
      setTimeout(() => el.classList.remove('copied'), 1100);
    } catch { /* clipboard blocked */ }
  });
  return el;
}

const isIp = (s) => /^\d{1,3}(\.\d{1,3}){3}$/.test(s) || s.includes(':');
function isPrivate(host) {
  host = host.replace(/^\[|\]$/g, '').toLowerCase();
  if (host === 'localhost' || host.endsWith('.local') || host.endsWith('.localhost')) return true;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    const [a, b] = host.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
  }
  if (host.includes(':')) return host === '::1' || /^(fc|fd|fe80)/.test(host);
  return false;
}

/* --------------------------- row / group rendering --------------------------- */

const ORDER = { info: 0, ok: 1, warn: 2, bad: 3 };
const worst = (rows) => rows.reduce((w, r) => ((ORDER[r.status] ?? 0) > ORDER[w] ? r.status : w), 'info');

function rowEl({ label, value, status }) {
  const v = h('span', { class: 'v' });
  if (value instanceof Node) v.append(value); else v.textContent = value;
  return h('div', { class: 'row' }, h('i', { class: 'pip ' + (status || '') }), h('span', { class: 'k', text: label }), v);
}

function makeGroup(parent, title) {
  const dot = h('span', { class: 'dot run' });
  const body = h('div', { class: 'rows' });
  parent.append(h('section', { class: 'group' },
    h('div', { class: 'g-head' }, dot, h('span', { class: 'g-title', text: title })), body));
  return {
    running() { dot.className = 'dot run'; },
    set(rows, state) {
      body.replaceChildren(...rows.map(rowEl));
      dot.className = 'dot ' + (state || worst(rows));
    },
  };
}

/* ----------------------------- geo + DNS lookups ----------------------------- */

const geoCache = new Map();
function lookupIp(ip) {
  if (!geoCache.has(ip)) {
    geoCache.set(ip, (async () => {
      try {
        const d = await fetchJson(`https://ipwho.is/${encodeURIComponent(ip)}`);
        if (!d.success) return null;
        return {
          cc: d.country_code, country: d.country, city: d.city,
          org: d.connection && (d.connection.org || d.connection.isp),
          asn: d.connection && d.connection.asn,
        };
      } catch { return null; }
    })());
  }
  return geoCache.get(ip);
}

async function dohQuery(resolver, name, type) {
  const t0 = performance.now();
  try {
    const j = await fetchJson(resolver.url(name, type), { timeout: 4000, headers: { accept: 'application/dns-json' } });
    const want = type === 'A' ? 1 : 28;
    return { ms: performance.now() - t0, status: j.Status, answers: (j.Answer || []).filter((a) => a.type === want).map((a) => a.data) };
  } catch { return null; }
}

/* ------------------------------- WebRTC / ICE ------------------------------- */

function gatherIce(ms = 3500) {
  return new Promise((resolve) => {
    const found = { host: new Set(), srflx: new Set(), mdns: false };
    let pc;
    try {
      pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }, { urls: 'stun:stun.cloudflare.com:3478' }] });
    } catch { resolve(null); return; }
    let done = false;
    const finish = () => { if (done) return; done = true; try { pc.close(); } catch { /* ignore */ } resolve(found); };
    pc.createDataChannel('probe');
    pc.onicecandidate = (e) => {
      if (!e.candidate) { finish(); return; }
      const p = e.candidate.candidate.split(' ');
      const addr = p[4], typ = p[7];
      if (!addr) return;
      if (typ === 'host') { if (addr.endsWith('.local')) found.mdns = true; else found.host.add(addr); }
      else if (typ === 'srflx') found.srflx.add(addr);
    };
    pc.createOffer().then((o) => pc.setLocalDescription(o)).catch(finish);
    setTimeout(finish, ms);
  });
}

/* --------------------------------- "me" card --------------------------------- */

function renderMe(own, icePromise) {
  const box = $('me');
  if (!own) { box.replaceChildren(h('p', { class: 'muted', text: 'Detecting your connection…' })); return; }

  const flag = $('hdrFlag');
  if (own.cc) { flag.src = `https://flagcdn.com/w160/${own.cc.toLowerCase()}.png`; flag.style.visibility = 'visible'; }
  $('hdrCountry').textContent = own.country || (own.ok ? 'Unknown location' : 'No connection');
  $('hdrSub').textContent = own.ok
    ? [own.city, own.region].filter(Boolean).join(', ') || own.ip
    : 'Lookup failed' + (own.ip ? ' — showing last known' : '');

  const rows = [];
  if (own.ip) rows.push({ label: 'Public IP', value: copyable(own.ip), status: own.ok ? 'ok' : 'warn' });
  else rows.push({ label: 'Public IP', value: 'Unavailable — are you offline?', status: 'bad' });
  if (own.country) {
    rows.push({
      label: 'Connected from',
      value: h('span', {}, flagNode(own.cc), [own.city, own.region, own.country].filter(Boolean).join(', ')),
      status: 'info',
    });
  }
  if (own.isp) rows.push({ label: 'Network', value: own.asn ? `${own.isp} (AS${String(own.asn).replace(/^AS/i, '')})` : own.isp, status: 'info' });
  if (own.tz) rows.push({ label: 'Time zone', value: own.tz, status: 'info' });

  const local = h('span', { text: 'detecting…' });
  rows.push({ label: 'Local IP', value: local, status: 'info' });
  if (icePromise) {
    icePromise.then((r) => {
      if (!r) { local.textContent = 'WebRTC unavailable'; return; }
      const list = [...r.host];
      local.textContent = '';
      if (list.length) list.forEach((ip, i) => local.append(i ? ', ' : '', copyable(ip)));
      else local.textContent = r.mdns ? 'hidden by browser (mDNS privacy)' : 'not exposed';
    });
  }

  if (own.prevIp && own.changedAt) {
    rows.push({
      label: 'IP changed',
      value: `${own.prevIp}${own.prevCc ? ' (' + own.prevCc + ')' : ''} → ${own.ip} at ${clock(new Date(own.changedAt))}`,
      status: 'warn',
    });
  }
  if (!own.ok && own.error) rows.push({ label: 'Error', value: own.error, status: 'bad' });
  box.replaceChildren(...rows.map(rowEl));
}

/* --------------------------------- site card --------------------------------- */

async function renderSite(tab) {
  const box = $('site');
  let url = null;
  try { if (tab && tab.url && /^https?:\/\//i.test(tab.url)) url = new URL(tab.url); } catch { /* ignore */ }
  if (!url) {
    box.replaceChildren(h('p', { class: 'muted', text: 'Open a website in this tab to see its server IP.' }));
    return null;
  }

  const hostBare = url.hostname.replace(/^\[|\]$/g, '');
  const rec = await api.runtime.sendMessage({ type: 'getSite', tabId: tab.id }).catch(() => null);
  const ctx = {
    url, host: hostBare, origin: url.origin, priv: isPrivate(hostBare),
    ip: rec && rec.host === url.hostname && rec.ip ? rec.ip : null,
    ipSource: 'seen by the browser', a: [], aaaa: [], geo: null,
  };

  const draw = () => {
    const rows = [{ label: 'Site', value: `${url.protocol === 'https:' ? '🔒 ' : '⚠ '}${hostBare}`, status: url.protocol === 'https:' ? 'ok' : 'warn' }];
    if (ctx.ip) {
      rows.push({ label: 'Server IP', value: h('span', {}, copyable(ctx.ip), h('span', { class: 'muted', text: `  (${ctx.ipSource})` })), status: 'ok' });
    } else {
      rows.push({ label: 'Server IP', value: ctx.priv ? 'Local / private address' : 'resolving…', status: 'info' });
    }
    if (ctx.geo) {
      rows.push({ label: 'Server location', value: h('span', {}, flagNode(ctx.geo.cc), [ctx.geo.city, ctx.geo.country].filter(Boolean).join(', ')), status: 'info' });
      if (ctx.geo.org) rows.push({ label: 'Hosted by', value: ctx.geo.asn ? `${ctx.geo.org} (AS${String(ctx.geo.asn).replace(/^AS/i, '')})` : ctx.geo.org, status: 'info' });
    }
    const extra = [...ctx.a, ...ctx.aaaa].filter((x) => x !== ctx.ip);
    if (extra.length) rows.push({ label: 'Other DNS IPs', value: extra.slice(0, 6).join(', ') + (extra.length > 6 ? ' …' : ''), status: 'info' });
    box.replaceChildren(...rows.map(rowEl));
  };
  draw();

  if (!ctx.priv && !isIp(hostBare)) {
    const [a, aaaa] = await Promise.all([dohQuery(DOH[0], hostBare, 'A'), dohQuery(DOH[0], hostBare, 'AAAA')]);
    ctx.a = (a && a.answers) || [];
    ctx.aaaa = (aaaa && aaaa.answers) || [];
    if (!ctx.ip && (ctx.a[0] || ctx.aaaa[0])) { ctx.ip = ctx.a[0] || ctx.aaaa[0]; ctx.ipSource = 'via DNS lookup'; }
  } else if (isIp(hostBare) && !ctx.ip) {
    ctx.ip = hostBare; ctx.ipSource = 'address in URL';
  }
  if (ctx.ip && !isPrivate(ctx.ip)) ctx.geo = await lookupIp(ctx.ip);
  draw();
  return ctx;
}

/* ---------------------------------- scans ---------------------------------- */

let G = null;

async function timedFetch(url, method) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), PROBE_TIMEOUT);
  const t0 = performance.now();
  try {
    // no-cors: we only need timing, the response body/headers are never read.
    await fetch(url, { method, mode: 'no-cors', cache: 'no-store', credentials: 'omit', signal: ctrl.signal });
    return performance.now() - t0;
  } catch { return null; } finally { clearTimeout(t); }
}

async function probeTarget(t) {
  const samples = [];
  let attempts = 0, consecutiveFails = 0;
  for (let i = 0; i < PROBES; i++) {
    attempts++;
    const ms = await timedFetch(t.url, t.method || 'GET');
    if (ms == null) { if (++consecutiveFails >= 2) break; }
    else { consecutiveFails = 0; samples.push(ms); }
  }
  return { samples, attempts };
}

function summarize(samples, attempts) {
  if (!samples.length) return { text: `no reply (0/${attempts})`, status: 'bad' };
  const warm = samples.length > 2 ? samples.slice(1) : samples;
  const avg = warm.reduce((s, x) => s + x, 0) / warm.length;
  const jitter = warm.length > 1 ? warm.slice(1).reduce((s, x, i) => s + Math.abs(x - warm[i]), 0) / (warm.length - 1) : 0;
  const text = `${fmt(avg)} avg · ${fmt(Math.min(...warm))}–${fmt(Math.max(...warm))} · jitter ${Math.round(jitter)} ms · first ${fmt(samples[0])} · ${samples.length}/${attempts} replies`;
  let status = avg < 100 ? 'ok' : avg < 250 ? 'warn' : 'bad';
  if (samples.length < attempts && status === 'ok') status = 'warn';
  return { text, status };
}

async function scanLatency(ctx) {
  G.latency.running();
  const targets = [...LATENCY_TARGETS];
  if (ctx.site && !ctx.site.priv) {
    targets.push({ name: `This site (${ctx.site.host})`, url: ctx.site.origin + '/', method: 'HEAD' });
  }
  const results = await Promise.all(targets.map(probeTarget));
  const rows = targets.map((t, i) => {
    const s = summarize(results[i].samples, results[i].attempts);
    return { label: t.name, value: s.text, status: s.status };
  });
  const anyUp = results.some((r) => r.samples.length);
  rows.unshift({
    label: 'Internet',
    value: anyUp ? 'Reachable' : 'No reply from any target — offline, blocked, or captive portal',
    status: anyUp ? 'ok' : 'bad',
  });
  G.latency.set(rows);
}

async function scanDns(ctx) {
  G.dns.running();
  const name = ctx.site && !ctx.site.priv && !isIp(ctx.site.host) ? ctx.site.host : 'example.com';
  const res = await Promise.all(DOH.map(async (r) => {
    const [a, aaaa] = await Promise.all([dohQuery(r, name, 'A'), dohQuery(r, name, 'AAAA')]);
    return { r, a, aaaa };
  }));
  const rows = [{ label: 'Test name', value: name, status: 'info' }];
  for (const { r, a, aaaa } of res) {
    if (!a && !aaaa) { rows.push({ label: r.name, value: 'No answer (blocked or offline)', status: 'bad' }); continue; }
    const v4 = (a && a.answers) || [], v6 = (aaaa && aaaa.answers) || [];
    const ms = Math.min(...[a, aaaa].filter(Boolean).map((x) => x.ms));
    rows.push({
      label: r.name,
      value: `${fmt(ms)} · A: ${v4.slice(0, 3).join(', ') || '—'}${v4.length > 3 ? ' …' : ''}${v6.length ? ` · AAAA: ${v6.length}` : ''}`,
      status: v4.length || v6.length ? (ms < 300 ? 'ok' : 'warn') : 'warn',
    });
  }
  const sets = res.map((x) => (x.a ? new Set(x.a.answers) : null)).filter(Boolean);
  if (sets.length === 2) {
    const overlap = [...sets[0]].some((ip) => sets[1].has(ip));
    rows.push({
      label: 'Consistency',
      value: overlap ? 'Resolvers agree' : 'Answers differ (normal for CDNs, but can indicate DNS filtering or hijacking)',
      status: overlap ? 'ok' : 'warn',
    });
  }
  G.dns.set(rows);
}

async function scanStack() {
  G.stack.running();
  const probe = async (url) => {
    const t0 = performance.now();
    try { const d = await fetchJson(url, { timeout: 4000 }); return { ip: d.ip, ms: performance.now() - t0 }; }
    catch { return null; }
  };
  const [v4, v6] = await Promise.all([probe('https://api4.ipify.org?format=json'), probe('https://api6.ipify.org?format=json')]);
  G.stack.set([
    { label: 'IPv4', value: v4 ? `${v4.ip} · ${fmt(v4.ms)}` : 'No IPv4 connectivity', status: v4 ? 'ok' : 'bad' },
    { label: 'IPv6', value: v6 ? `${v6.ip} · ${fmt(v6.ms)}` : 'Not available (IPv4-only network)', status: v6 ? 'ok' : 'info' },
  ]);
}

async function scanWebRtc(ctx) {
  G.webrtc.running();
  const r = await ctx.icePromise;
  if (!r) { G.webrtc.set([{ label: 'WebRTC', value: 'Unavailable or disabled in this browser', status: 'info' }]); return; }
  const rows = [];
  const host = [...r.host], srflx = [...r.srflx];
  rows.push({ label: 'Local address', value: host.length ? host.join(', ') : (r.mdns ? 'Hidden by browser (mDNS privacy)' : 'None exposed'), status: 'info' });
  rows.push({ label: 'STUN sees', value: srflx.length ? srflx.join(', ') : 'No reply (STUN/UDP blocked)', status: 'info' });
  const own = ctx.own && ctx.own.ok ? ctx.own.ip : null;
  if (own && srflx.length) {
    const sameFamily = srflx.filter((ip) => ip.includes(':') === own.includes(':'));
    if (!sameFamily.length) rows.push({ label: 'Leak check', value: 'No same-family address to compare', status: 'info' });
    else if (sameFamily.every((ip) => ip === own)) rows.push({ label: 'Leak check', value: 'No leak — WebRTC reports the same IP as the web', status: 'ok' });
    else rows.push({ label: 'Leak check', value: 'WebRTC reports a different IP than the web — possible VPN/proxy leak', status: 'bad' });
  } else {
    rows.push({ label: 'Leak check', value: 'Could not compare (no public IP or no STUN reply)', status: 'info' });
  }
  G.webrtc.set(rows);
}

async function scanSite(ctx) {
  G.site.running();
  const site = ctx.site;
  if (!site) { G.site.set([{ label: 'Site', value: 'No website in the active tab', status: 'info' }]); return; }
  if (site.priv) { G.site.set([{ label: 'Site', value: 'Local/private address — skipped', status: 'info' }]); return; }

  const rows = [];
  const hostPart = site.url.host;
  const get = async (u, opts = {}) => {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 6000);
    try {
      const r = await fetch(u, { cache: 'no-store', credentials: 'omit', redirect: 'follow', signal: ctrl.signal, ...opts });
      if (r.body) r.body.cancel().catch(() => {});
      return r;
    } finally { clearTimeout(t); }
  };

  // Port 443 + headers
  try {
    const r = await get(`https://${hostPart}/`);
    rows.push({ label: 'Port 443', value: `HTTPS reachable · HTTP ${r.status}`, status: r.ok ? 'ok' : 'warn' });
    const hd = (n) => r.headers.get(n);
    const check = (label, present, valueOk) => rows.push({ label, value: present ? (valueOk || 'present') : 'missing', status: present ? 'ok' : 'warn' });
    check('HSTS', hd('strict-transport-security'), hd('strict-transport-security') && hd('strict-transport-security').slice(0, 60));
    check('CSP', hd('content-security-policy'), 'present');
    check('X-Content-Type', hd('x-content-type-options'), hd('x-content-type-options'));
    const csp = hd('content-security-policy') || '';
    check('Clickjacking', hd('x-frame-options') || /frame-ancestors/i.test(csp), hd('x-frame-options') || 'frame-ancestors (CSP)');
    check('Referrer-Policy', hd('referrer-policy'), hd('referrer-policy'));
    check('Permissions-Policy', hd('permissions-policy'), 'present');
    if (hd('server')) rows.push({ label: 'Server', value: hd('server'), status: 'info' });
    if (hd('x-powered-by')) rows.push({ label: 'X-Powered-By', value: `${hd('x-powered-by')} (reveals stack)`, status: 'warn' });
  } catch {
    rows.push({ label: 'Port 443', value: 'HTTPS not readable (closed, blocked, or site access not granted to the extension)', status: 'warn' });
  }

  // Port 80 behaviour
  try {
    const r = await get(`http://${hostPart}/`, { method: 'HEAD' });
    const upgraded = r.url.startsWith('https:');
    rows.push({
      label: 'Port 80',
      value: upgraded ? 'Open, redirects to HTTPS' : 'Open and serves plain HTTP',
      status: upgraded ? 'ok' : 'warn',
    });
  } catch {
    rows.push({ label: 'Port 80', value: 'Not reachable (HTTPS-only)', status: 'ok' });
  }
  if (site.url.protocol !== 'https:') rows.unshift({ label: 'Encryption', value: 'This page was loaded over plain HTTP', status: 'bad' });
  G.site.set(rows);
}

async function scanBrowser() {
  G.browser.running();
  const rows = [{ label: 'Online', value: navigator.onLine ? 'Browser reports online' : 'Browser reports offline', status: navigator.onLine ? 'ok' : 'bad' }];
  const c = navigator.connection;
  if (c) {
    if (c.effectiveType) rows.push({ label: 'Link quality', value: c.effectiveType, status: 'info' });
    if (c.downlink != null) rows.push({ label: 'Downlink', value: `${c.downlink} Mbit/s (estimate)`, status: 'info' });
    if (c.rtt != null) rows.push({ label: 'Est. RTT', value: `${c.rtt} ms`, status: 'info' });
    if (c.saveData) rows.push({ label: 'Data saver', value: 'On', status: 'warn' });
  } else {
    rows.push({ label: 'Link details', value: 'Not exposed by this browser', status: 'info' });
  }
  G.browser.set(rows);
}

async function runScans(ctx) {
  await scanLatency(ctx);               // timing-sensitive: run alone first
  await Promise.allSettled([scanDns(ctx), scanStack(), scanWebRtc(ctx), scanSite(ctx), scanBrowser()]);
}

/* ------------------------------ refresh + timer ------------------------------ */

let running = false;
let remaining = REFRESH_SECONDS;

function resetCountdown() {
  remaining = REFRESH_SECONDS;
  $('countdown').textContent = remaining + 's';
  const fill = $('barFill');
  fill.style.transition = 'none';
  fill.style.width = '0%';
  void fill.offsetWidth;
  fill.style.transition = 'width 1s linear';
}

async function refreshAll() {
  if (running) return;
  running = true;
  $('refreshBtn').classList.add('busy');
  resetCountdown();
  try {
    const icePromise = gatherIce();
    const [tab, own] = await Promise.all([
      api.tabs.query({ active: true, currentWindow: true }).then((t) => t[0]),
      api.runtime.sendMessage({ type: 'refresh' }),
    ]);
    renderMe(own, icePromise);
    const site = await renderSite(tab);
    await runScans({ own, site, icePromise });
  } catch (e) {
    console.error(e);
  } finally {
    running = false;
    $('refreshBtn').classList.remove('busy');
    $('updated').textContent = 'Last updated ' + clock();
  }
}

function tick() {
  remaining = Math.max(0, remaining - 1);
  $('countdown').textContent = remaining + 's';
  $('barFill').style.width = ((REFRESH_SECONDS - remaining) / REFRESH_SECONDS) * 100 + '%';
  if (remaining === 0) refreshAll();
}

async function init() {
  $('hdrFlag').addEventListener('error', () => { $('hdrFlag').style.visibility = 'hidden'; });
  G = {
    latency: makeGroup($('scans'), 'Latency — HTTP round-trip “ping”'),
    dns: makeGroup($('scans'), 'DNS resolution (DNS-over-HTTPS)'),
    stack: makeGroup($('scans'), 'IPv4 / IPv6 reachability'),
    webrtc: makeGroup($('scans'), 'WebRTC / VPN leak check'),
    site: makeGroup($('scans'), 'Viewed site — ports 80/443 & security headers'),
    browser: makeGroup($('scans'), 'Browser connection'),
  };
  $('refreshBtn').addEventListener('click', refreshAll);

  const cached = (await api.storage.local.get('own')).own;
  if (cached) renderMe(cached, null);

  setInterval(tick, 1000);
  refreshAll();
}

init();
