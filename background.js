'use strict';
/*
 * IP & Flag Monitor — background (Chrome service worker / Firefox event page)
 *  - every 60 s: look up the public IP + country, store it, paint the flag as the toolbar icon
 *  - records the server IP of every top-level page load, per tab (webRequest `ip` field)
 */

const api = typeof browser !== 'undefined' ? browser : chrome;
const ALARM = 'ip-refresh';
const sessionStore = api.storage.session || api.storage.local;

let inflight = null;
let appliedIconCC = null;

/* ------------------------------ helpers ------------------------------ */

async function getJSON(url, ms = 8000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try {
    const r = await fetch(url, { signal: ctrl.signal, cache: 'no-store', credentials: 'omit' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return await r.json();
  } finally {
    clearTimeout(t);
  }
}

function countryName(cc) {
  try { return new Intl.DisplayNames(['en'], { type: 'region' }).of(cc.toUpperCase()); }
  catch { return cc; }
}

/* ----------------------- public IP / country lookup ----------------------- */

const PROVIDERS = [
  async () => {
    const d = await getJSON('https://ipwho.is/');
    if (!d.success) throw new Error(d.message || 'ipwho.is failed');
    return {
      ip: d.ip, cc: d.country_code, country: d.country, region: d.region, city: d.city,
      isp: d.connection && (d.connection.isp || d.connection.org),
      asn: d.connection && d.connection.asn,
      tz: d.timezone && d.timezone.id,
    };
  },
  async () => {
    const d = await getJSON('https://ipapi.co/json/');
    if (d.error) throw new Error(d.reason || 'ipapi.co failed');
    return {
      ip: d.ip, cc: d.country_code, country: d.country_name, region: d.region, city: d.city,
      isp: d.org, asn: d.asn, tz: d.timezone,
    };
  },
  async () => {
    const d = await getJSON('https://api.country.is/');
    return { ip: d.ip, cc: d.country };
  },
];

async function lookupOwn() {
  let lastErr;
  for (const p of PROVIDERS) {
    try {
      const r = await p();
      if (r && r.ip && r.cc) {
        r.cc = r.cc.toUpperCase();
        r.country = r.country || countryName(r.cc);
        return r;
      }
    } catch (e) { lastErr = e; }
  }
  throw lastErr || new Error('All lookup providers failed');
}

/* --------------------------- toolbar flag icon --------------------------- */

const ICON_SIZES = [16, 32, 48, 128];

function drawFallback(size, label) {
  const c = new OffscreenCanvas(size, size);
  const x = c.getContext('2d');
  x.fillStyle = '#1a73e8';
  x.fillRect(0, 0, size, size);
  x.fillStyle = '#fff';
  x.font = `bold ${Math.floor(size * 0.5)}px sans-serif`;
  x.textAlign = 'center';
  x.textBaseline = 'middle';
  x.fillText(label, size / 2, size / 2 + 1);
  return x.getImageData(0, 0, size, size);
}

async function setFlagIcon(cc) {
  if (appliedIconCC === cc) return;
  const imageData = {};
  try {
    const res = await fetch(`https://flagcdn.com/w160/${cc.toLowerCase()}.png`, { credentials: 'omit' });
    if (!res.ok) throw new Error('flag HTTP ' + res.status);
    const bmp = await createImageBitmap(await res.blob());
    for (const s of ICON_SIZES) {
      const c = new OffscreenCanvas(s, s);
      const x = c.getContext('2d');
      const scale = Math.min(s / bmp.width, s / bmp.height);
      const w = Math.max(1, Math.round(bmp.width * scale));
      const h = Math.max(1, Math.round(bmp.height * scale));
      const dx = Math.floor((s - w) / 2);
      const dy = Math.floor((s - h) / 2);
      x.drawImage(bmp, dx, dy, w, h);
      x.strokeStyle = 'rgba(0,0,0,0.45)';
      x.lineWidth = Math.max(1, s / 32);
      x.strokeRect(dx + 0.5, dy + 0.5, w - 1, h - 1);
      imageData[s] = x.getImageData(0, 0, s, s);
    }
  } catch {
    for (const s of ICON_SIZES) imageData[s] = drawFallback(s, cc);
  }
  try {
    await api.action.setIcon({ imageData });
    appliedIconCC = cc;
  } catch (e) { console.warn('setIcon failed', e); }
}

/* ------------------------------ refresh cycle ------------------------------ */

function refreshOwn() {
  if (inflight) return inflight;
  inflight = (async () => {
    const prev = (await api.storage.local.get('own')).own;
    try {
      const own = await lookupOwn();
      own.ok = true;
      own.checkedAt = Date.now();
      if (prev && prev.ip && prev.ip !== own.ip) {
        own.prevIp = prev.ip;
        own.prevCc = prev.cc;
        own.changedAt = Date.now();
      } else if (prev && prev.prevIp) {
        own.prevIp = prev.prevIp;
        own.prevCc = prev.prevCc;
        own.changedAt = prev.changedAt;
      }
      await api.storage.local.set({ own });
      await setFlagIcon(own.cc);
      await api.action.setBadgeText({ text: '' });
      await api.action.setTitle({ title: `${own.ip} — ${own.country}${own.city ? ', ' + own.city : ''}` });
      return own;
    } catch (e) {
      const failed = { ...(prev || {}), ok: false, error: String((e && e.message) || e), checkedAt: Date.now() };
      await api.storage.local.set({ own: failed });
      await api.action.setBadgeBackgroundColor({ color: '#d93025' });
      await api.action.setBadgeText({ text: '!' });
      await api.action.setTitle({ title: 'IP & Flag Monitor — offline or lookup failed' });
      return failed;
    }
  })().finally(() => { inflight = null; });
  return inflight;
}

function ensureAlarm() {
  api.alarms.get(ALARM).then((a) => {
    if (!a) api.alarms.create(ALARM, { periodInMinutes: 1 });
  });
}

api.alarms.onAlarm.addListener((a) => { if (a.name === ALARM) refreshOwn(); });
api.runtime.onInstalled.addListener(() => {
  api.alarms.create(ALARM, { periodInMinutes: 1 });
  refreshOwn();
});
api.runtime.onStartup.addListener(() => { ensureAlarm(); refreshOwn(); });
ensureAlarm();
try { globalThis.addEventListener('online', () => refreshOwn()); } catch { /* not available */ }

/* ---------------------- server IP of each tab's page ---------------------- */

let sites = null;
let writeChain = Promise.resolve();

async function loadSites() {
  if (!sites) sites = (await sessionStore.get('sites')).sites || {};
  return sites;
}

function saveSite(tabId, rec) {
  writeChain = writeChain.then(async () => {
    await loadSites();
    sites[tabId] = rec;
    await sessionStore.set({ sites });
  }).catch(() => {});
}

api.webRequest.onCompleted.addListener(
  (d) => {
    if (d.tabId < 0 || !d.ip) return;
    let u;
    try { u = new URL(d.url); } catch { return; }
    saveSite(d.tabId, {
      url: d.url,
      host: u.hostname,
      ip: String(d.ip).replace(/^\[|\]$/g, ''),
      fromCache: !!d.fromCache,
      ts: Date.now(),
    });
  },
  { urls: ['<all_urls>'], types: ['main_frame'] }
);

api.tabs.onRemoved.addListener((tabId) => {
  writeChain = writeChain.then(async () => {
    await loadSites();
    if (sites[tabId]) { delete sites[tabId]; await sessionStore.set({ sites }); }
  }).catch(() => {});
});

/* ------------------------------ popup messages ------------------------------ */

api.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (!msg || !msg.type) return false;
  if (msg.type === 'refresh') {
    refreshOwn().then(sendResponse, (e) => sendResponse({ ok: false, error: String(e) }));
    return true;
  }
  if (msg.type === 'getSite') {
    writeChain.then(loadSites).then((s) => sendResponse(s[msg.tabId] || null), () => sendResponse(null));
    return true;
  }
  return false;
});
