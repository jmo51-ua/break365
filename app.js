/* Break365. Static, client-side only.
 * Security model:
 *  - No password is stored anywhere. keyring.json holds, per role, a PBKDF2 salt and the
 *    data key wrapped (AES-GCM) with a key derived from that role's password.
 *  - couples.enc.json is AES-256-GCM ciphertext. Without a correct password it is unreadable.
 *  - Password checking happens only in this browser via WebCrypto. No network call is made with it.
 */
(function () {
  'use strict';

  var ENC = new TextEncoder();
  var DEC = new TextDecoder();
  var AAD_DATA = ENC.encode('break365/data/v1');
  function aadKey(role) { return ENC.encode('break365/keyring/v1/' + role); }

  var BUCKETS = [
    { key: 'weeks', label: '+Weeks', hint: 'Ends before 3 months' },
    { key: 'months', label: '+Months', hint: 'Ends between 3 and 12 months' },
    { key: 'years', label: '+Years', hint: 'Lasts 1 year or more' }
  ];

  var state = {
    keyring: null,
    encFile: null,
    role: null,       // 'admin' | 'user'
    key: null,        // CryptoKey (data key), memory only
    data: null,       // decrypted data, memory only
    view: 'live',
    query: '',
    selection: null,  // { id, bucket }
    pending: [],      // admin changes not yet published: { t: 'upsert'|'delete'|'settings', ... }
    publishing: false,
    syncError: '',
    lastPublished: 0,
    adminKek: null,   // admin password key, memory only (unlocks the GitHub connection)
    gh: null,         // { owner, repo, branch, dir, token } memory only
    ghNotice: '',
    ghEditing: false,
    live: {},         // coupleId -> { ok, probs, bettors, volume, resolved, error, at }
    session: 0,       // bumps on logout so late network replies are ignored
    timer: null,
    lastRefresh: 0
  };

  var MANIFOLD_API = 'https://api.manifold.markets/v0/slug/';
  var REFRESH_MS = 60000;

  var $ = function (id) { return document.getElementById(id); };

  /* ---------- Manifold (live % and odds) ----------
   * Reads a public Manifold multiple-choice market. Answers are matched to buckets by name:
   * "Weeks"/"Semanas", "Months"/"Meses", "Years"/"Años". No login, no API key, nothing is sent
   * except the market slug. */
  function manifoldSlug(url) {
    if (!url) return '';
    try {
      var u = new URL(url);
      if (!/^(www\.)?manifold\.markets$/i.test(u.hostname)) return '';
      var seg = u.pathname.split('/').filter(Boolean);
      if (seg[0] === 'embed') seg.shift();
      if (seg.length !== 2 || !/^[A-Za-z0-9_-]+$/.test(seg[1])) return '';
      return seg[1];
    } catch (e) { return ''; }
  }
  function isManifoldHost(url) {
    try { return /^(www\.)?manifold\.markets$/i.test(new URL(url).hostname); } catch (e) { return false; }
  }
  function bucketOfAnswer(text) {
    var t = String(text || '').toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '');
    if (/\bweeks?\b|\bsemanas?\b/.test(t)) return 'weeks';
    if (/\bmonths?\b|\bmes(es)?\b/.test(t)) return 'months';
    if (/\byears?\b|\banos?\b/.test(t)) return 'years';
    return '';
  }

  async function fetchMarket(slug) {
    var ctrl = new AbortController();
    var to = setTimeout(function () { ctrl.abort(); }, 10000);
    var res;
    try {
      res = await fetch(MANIFOLD_API + encodeURIComponent(slug), {
        credentials: 'omit', cache: 'no-store', referrerPolicy: 'no-referrer', signal: ctrl.signal
      });
    } catch (e) {
      throw new Error('Could not reach Manifold.');
    } finally { clearTimeout(to); }
    if (res.status === 404) throw new Error('Manifold market not found. Check the link.');
    if (!res.ok) throw new Error('Manifold returned an error (' + res.status + ').');
    var m = await res.json();
    if (!Array.isArray(m.answers) || !m.answers.length) {
      throw new Error('That market is not multiple choice. Create one with the answers Weeks, Months and Years.');
    }
    var probs = {}, dupes = [];
    m.answers.forEach(function (a) {
      var b = bucketOfAnswer(a.text), p = Number(a.probability);
      if (!b || !isFinite(p)) return;
      if (b in probs) dupes.push(b);
      probs[b] = Math.min(Math.max(p, 0), 1);
    });
    if (dupes.length) throw new Error('More than one answer matches ' + labelOf(dupes[0]) + '. Keep one answer per option.');
    var missing = BUCKETS.filter(function (b) { return !(b.key in probs); }).map(function (b) { return b.label; });
    if (missing.length) throw new Error('No answer found for ' + missing.join(', ') + '. Name the answers Weeks, Months and Years.');
    return {
      ok: true, probs: probs,
      bettors: Number(m.uniqueBettorCount) || 0,
      volume: Number(m.volume) || 0,
      resolved: !!m.isResolved,
      at: Date.now()
    };
  }

  function oddsFromProb(p) {
    if (!(p > 0)) return 1000;
    var margin = state.data ? state.data.settings.margin : 0;
    var o = (1 - margin / 100) / p;
    return Math.round(Math.min(Math.max(o, 1.01), 1000) * 100) / 100;
  }
  function liveOf(c) { var l = state.live[c.id]; return l && l.ok ? l : null; }
  function oddsOf(c, bucket) { var l = liveOf(c); return l ? oddsFromProb(l.probs[bucket]) : c.odds[bucket]; }
  function labelOf(key) { return BUCKETS.filter(function (b) { return b.key === key; })[0].label; }
  function fmtPct(p) { var v = p * 100; return (v > 0 && v < 1 ? '<1' : Math.round(v)) + '%'; }

  async function refreshLive() {
    if (!state.data) return;
    var session = state.session;
    state.lastRefresh = Date.now();
    var jobs = state.data.couples.filter(function (c) { return c.status === 'active' && manifoldSlug(c.betUrl); });
    Object.keys(state.live).forEach(function (id) {
      if (!jobs.some(function (c) { return c.id === id; })) delete state.live[id];
    });
    await Promise.all(jobs.map(async function (c) {
      var result;
      try { result = await fetchMarket(manifoldSlug(c.betUrl)); }
      catch (e) {
        var prev = state.live[c.id];
        // keep the last good numbers if a refresh fails
        result = prev && prev.ok ? Object.assign({}, prev, { stale: true }) : { ok: false, error: e.message };
      }
      if (session !== state.session || !state.data) return;
      state.live[c.id] = result;
    }));
    if (session !== state.session || !state.data) return;
    if (state.view !== 'admin') renderBook();
    renderSlip();
  }
  function startLive() {
    stopLive();
    refreshLive();
    state.timer = setInterval(function () { if (!document.hidden) refreshLive(); }, REFRESH_MS);
  }
  function stopLive() {
    if (state.timer) clearInterval(state.timer);
    state.timer = null;
  }

  /* ---------- base64 ---------- */
  function b64enc(u8) {
    var s = '';
    for (var i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
    return btoa(s);
  }
  function b64dec(str) {
    var s = atob(str), u = new Uint8Array(s.length);
    for (var i = 0; i < s.length; i++) u[i] = s.charCodeAt(i);
    return u;
  }

  /* ---------- crypto ---------- */
  function normPw(pw) { return String(pw).normalize('NFC').trim(); }

  // Returns { raw: data key bytes, kek: password-derived key } or null if the password is wrong for this role.
  async function tryRole(password, role, entry, iterations) {
    try {
      var base = await crypto.subtle.importKey('raw', ENC.encode(normPw(password)), 'PBKDF2', false, ['deriveKey']);
      var kek = await crypto.subtle.deriveKey(
        { name: 'PBKDF2', hash: 'SHA-256', salt: b64dec(entry.salt), iterations: iterations },
        base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
      var raw = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: b64dec(entry.iv), additionalData: aadKey(role) }, kek, b64dec(entry.wrapped));
      return { raw: new Uint8Array(raw), kek: kek };
    } catch (e) {
      return null;
    }
  }

  // Admin-only secrets (the GitHub connection) are locked with the admin password's key,
  // so the player password can never open them.
  var AAD_SECRETS = ENC.encode('break365/admin-secrets/v1');
  async function encryptSecrets(kek, obj) {
    var iv = crypto.getRandomValues(new Uint8Array(12));
    var ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv, additionalData: AAD_SECRETS }, kek, ENC.encode(JSON.stringify(obj)));
    return { iv: b64enc(iv), ct: b64enc(new Uint8Array(ct)) };
  }
  async function decryptSecrets(kek, s) {
    var pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64dec(s.iv), additionalData: AAD_SECRETS }, kek, b64dec(s.ct));
    return JSON.parse(DEC.decode(pt));
  }

  async function decryptData(key, file) {
    var pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b64dec(file.iv), additionalData: AAD_DATA }, key, b64dec(file.ct));
    return JSON.parse(DEC.decode(pt));
  }

  async function encryptData(key, obj) {
    var iv = crypto.getRandomValues(new Uint8Array(12));
    var ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv, additionalData: AAD_DATA }, key, ENC.encode(JSON.stringify(obj)));
    return JSON.stringify({ v: 1, iv: b64enc(iv), ct: b64enc(new Uint8Array(ct)) }) + '\n';
  }

  /* ---------- data validation ---------- */
  function safeUrl(s) {
    if (typeof s !== 'string' || !s.trim()) return '';
    try {
      var u = new URL(s.trim());
      return u.protocol === 'https:' ? u.href : '';
    } catch (e) { return ''; }
  }
  function isISODate(s) {
    if (typeof s !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
    var d = parseDate(s);
    return d.getFullYear() === +s.slice(0, 4) && d.getMonth() === +s.slice(5, 7) - 1 && d.getDate() === +s.slice(8, 10);
  }
  function validOdds(n) { n = Number(n); return isFinite(n) && n >= 1.01 && n <= 1000 ? Math.round(n * 100) / 100 : null; }
  function validMargin(n) { n = Number(n); return isFinite(n) && n >= 0 && n <= 25 ? Math.round(n * 10) / 10 : null; }
  function cleanText(s, max) { return typeof s === 'string' ? s.replace(/\s+/g, ' ').trim().slice(0, max) : ''; }

  function normCouple(c) {
    if (!c || typeof c !== 'object') return null;
    var a = cleanText(c.a, 60), b = cleanText(c.b, 60);
    if (!a || !b || !isISODate(c.since)) return null;
    var odds = {};
    for (var i = 0; i < BUCKETS.length; i++) {
      var k = BUCKETS[i].key, v = validOdds(c.odds && c.odds[k]);
      if (v === null) return null;
      odds[k] = v;
    }
    var ended = c.status === 'ended' && isISODate(c.endedOn) && c.endedOn >= c.since;
    return {
      id: typeof c.id === 'string' && c.id ? c.id.slice(0, 64) : newId(),
      a: a, b: b, since: c.since, odds: odds,
      betUrl: safeUrl(c.betUrl),
      note: cleanText(c.note, 140),
      status: ended ? 'ended' : 'active',
      endedOn: ended ? c.endedOn : ''
    };
  }
  function normalizeData(d) {
    var out = { v: 1, settings: { defaultBetUrl: '', margin: 0 }, couples: [] };
    if (d && typeof d === 'object') {
      if (d.settings) {
        out.settings.defaultBetUrl = safeUrl(d.settings.defaultBetUrl);
        out.settings.margin = validMargin(d.settings.margin) || 0;
      }
      if (Array.isArray(d.couples)) out.couples = d.couples.map(normCouple).filter(Boolean);
    }
    return out;
  }
  function newId() {
    if (crypto.randomUUID) return crypto.randomUUID();
    var r = crypto.getRandomValues(new Uint8Array(16)), s = '';
    for (var i = 0; i < r.length; i++) s += ('0' + r[i].toString(16)).slice(-2);
    return s;
  }

  /* ---------- dates ---------- */
  function parseDate(s) { return new Date(+s.slice(0, 4), +s.slice(5, 7) - 1, +s.slice(8, 10)); }
  function today() { var n = new Date(); return new Date(n.getFullYear(), n.getMonth(), n.getDate()); }
  function toISO(d) {
    return d.getFullYear() + '-' + ('0' + (d.getMonth() + 1)).slice(-2) + '-' + ('0' + d.getDate()).slice(-2);
  }
  function addMonths(d, n) {
    var y = d.getFullYear(), m = d.getMonth() + n, day = d.getDate();
    var last = new Date(y, m + 1, 0).getDate();
    return new Date(y, m, Math.min(day, last));
  }
  function daysBetween(a, b) { return Math.round((b - a) / 86400000); }
  function fmtDate(s) {
    return parseDate(s).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' });
  }
  function fmtDuration(from, to) {
    var days = daysBetween(from, to);
    if (days < 0) return 'not started';
    var months = 0;
    while (addMonths(from, months + 1) <= to) months++;
    var y = Math.floor(months / 12), m = months % 12;
    var rest = daysBetween(addMonths(from, months), to);
    var parts = [];
    if (y) parts.push(y + (y === 1 ? ' year' : ' years'));
    if (m) parts.push(m + (m === 1 ? ' month' : ' months'));
    if (!y && !m) parts.push(rest + (rest === 1 ? ' day' : ' days'));
    else if (!y && rest) parts.push(rest + (rest === 1 ? ' day' : ' days'));
    return parts.join(' ');
  }
  // Which bucket a finished relationship falls into.
  function outcome(c) {
    var since = parseDate(c.since), end = parseDate(c.endedOn);
    if (end < addMonths(since, 3)) return 'weeks';
    if (end < addMonths(since, 12)) return 'months';
    return 'years';
  }
  // Whether a bucket can still win for a live couple.
  function isOpen(c, bucket) {
    var since = parseDate(c.since), t = today();
    if (bucket === 'weeks') return t < addMonths(since, 3);
    if (bucket === 'months') return t < addMonths(since, 12);
    return true;
  }

  /* ---------- DOM helpers ---------- */
  function el(tag, attrs, children) {
    var n = document.createElement(tag);
    if (attrs) Object.keys(attrs).forEach(function (k) {
      var v = attrs[k];
      if (v === null || v === undefined || v === false) return;
      if (k === 'class') n.className = v;
      else if (k === 'text') n.textContent = v;
      else if (k.slice(0, 2) === 'on') n.addEventListener(k.slice(2), v);
      else n.setAttribute(k, v === true ? '' : v);
    });
    (children || []).forEach(function (c) { if (c) n.appendChild(typeof c === 'string' ? document.createTextNode(c) : c); });
    return n;
  }
  function setMsg(id, text, kind) {
    var m = $(id);
    m.textContent = text || '';
    m.className = 'msg' + (kind ? ' ' + kind : '');
  }
  function fmtOdds(n) { return Number(n).toFixed(2); }
  function coupleName(c) { return c.a + ' & ' + c.b; }
  function findCouple(id) {
    for (var i = 0; i < state.data.couples.length; i++) if (state.data.couples[i].id === id) return state.data.couples[i];
    return null;
  }
  function betUrlFor(c) { return c.betUrl || state.data.settings.defaultBetUrl || ''; }

  /* ---------- loading ---------- */
  async function fetchJson(path) {
    var res = await fetch(path + '?t=' + Date.now(), { cache: 'no-store', credentials: 'omit' });
    if (!res.ok) throw new Error(path + ' returned ' + res.status);
    return res.json();
  }

  async function boot() {
    if (!window.crypto || !crypto.subtle) {
      setMsg('login-msg', 'This browser cannot run the secure login. Open the site over https in an up-to-date browser.', 'error');
      return;
    }
    try {
      var r = await Promise.all([fetchJson('keyring.json'), fetchJson('couples.enc.json')]);
      state.keyring = r[0];
      state.encFile = r[1];
      if (!state.keyring.roles || !state.keyring.kdf) throw new Error('keyring.json is not valid');
    } catch (e) {
      var fileHint = location.protocol === 'file:' ? ' Open it from GitHub Pages or a local web server, not as a file.' : '';
      setMsg('login-msg', 'Could not load the site data.' + fileHint, 'error');
      $('login-btn').textContent = 'Unavailable';
      return;
    }
    $('pw').disabled = false;
    $('login-btn').disabled = false;
    $('login-btn').textContent = 'Log in';
    $('pw').focus();
  }

  async function login(ev) {
    ev.preventDefault();
    var pw = $('pw').value;
    if (!normPw(pw)) { setMsg('login-msg', 'Enter the password.', 'error'); return; }
    $('login-btn').disabled = true;
    $('login-btn').textContent = 'Checking…';
    setMsg('login-msg', '');
    var kr = state.keyring, it = kr.kdf.iterations;
    var results = await Promise.all([
      kr.roles.admin ? tryRole(pw, 'admin', kr.roles.admin, it) : null,
      kr.roles.user ? tryRole(pw, 'user', kr.roles.user, it) : null
    ]);
    var role = results[0] ? 'admin' : (results[1] ? 'user' : null);
    var raw = results[0] ? results[0].raw : (results[1] ? results[1].raw : null);
    if (results[0] && results[1]) results[1].raw.fill(0);
    if (!role) {
      await new Promise(function (r) { setTimeout(r, 400); });
      $('login-btn').disabled = false;
      $('login-btn').textContent = 'Log in';
      setMsg('login-msg', 'Wrong password.', 'error');
      $('pw').select();
      return;
    }
    try {
      state.key = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
      raw.fill(0);
      state.data = normalizeData(await decryptData(state.key, state.encFile));
    } catch (e) {
      $('login-btn').disabled = false;
      $('login-btn').textContent = 'Log in';
      setMsg('login-msg', 'Password accepted but the couples file could not be read. The admin should re-publish it.', 'error');
      state.key = null;
      return;
    }
    state.role = role;
    state.gh = null;
    state.ghNotice = '';
    if (role === 'admin') {
      state.adminKek = results[0].kek;
      var sec = kr.roles.admin.secrets;
      if (sec) {
        try { state.gh = validGh(await decryptSecrets(state.adminKek, sec)); }
        catch (e) { state.gh = null; }
        if (!state.gh) state.ghNotice = 'The saved GitHub connection could not be read. Connect it again below.';
      }
    }
    $('pw').value = '';
    $('login-btn').textContent = 'Log in';
    $('login-btn').disabled = false;
    enterApp();
    if (state.gh) pullLatest();
  }

  function logout() {
    if (state.pending.length && !confirm('Some changes are not published yet. Log out and lose them?')) return;
    state.key = null; state.data = null; state.role = null; state.selection = null;
    state.pending = []; state.publishing = false; state.syncError = ''; state.lastPublished = 0;
    state.adminKek = null; state.gh = null; state.ghNotice = ''; state.ghEditing = false; state.query = '';
    state.live = {}; state.session++; stopLive();
    $('gh-token').value = '';
    $('search').value = '';
    document.body.classList.remove('has-slip', 'view-admin');
    $('main').hidden = true;
    $('login').hidden = false;
    setMsg('login-msg', 'Logged out.', 'ok');
    $('pw').focus();
  }

  function enterApp() {
    $('login').hidden = true;
    $('main').hidden = false;
    var isAdmin = state.role === 'admin';
    $('role-badge').textContent = isAdmin ? 'Admin' : 'Player';
    $('role-badge').className = 'badge' + (isAdmin ? ' admin' : '');
    document.querySelector('.tab-admin').hidden = !isAdmin;
    if (isAdmin) { prefillGitHub(); resetForm(); }
    setView('live');
    startLive();
  }

  /* ---------- views ---------- */
  function setView(v) {
    if (v === 'admin' && state.role !== 'admin') v = 'live';
    state.view = v;
    Array.prototype.forEach.call(document.querySelectorAll('.tab'), function (t) {
      t.classList.toggle('is-active', t.getAttribute('data-view') === v);
    });
    var admin = v === 'admin';
    $('book').hidden = admin;
    $('admin').hidden = !admin;
    $('slip').hidden = admin;
    document.body.classList.toggle('view-admin', admin);
    if (admin) renderAdmin(); else renderBook();
    renderSlip();
  }

  function renderBook() {
    var titles = { live: 'Live couples', settled: 'Settled', all: 'All couples' };
    $('book-title').textContent = titles[state.view];
    var q = state.query.toLowerCase();
    var list = state.data.couples.filter(function (c) {
      if (state.view === 'live' && c.status !== 'active') return false;
      if (state.view === 'settled' && c.status !== 'ended') return false;
      return !q || coupleName(c).toLowerCase().indexOf(q) !== -1;
    }).sort(function (x, y) {
      if (x.status !== y.status) return x.status === 'active' ? -1 : 1;
      var kx = x.status === 'ended' ? x.endedOn : x.since, ky = y.status === 'ended' ? y.endedOn : y.since;
      return kx < ky ? 1 : kx > ky ? -1 : 0;
    });
    var box = $('couple-list');
    box.textContent = '';
    if (!list.length) {
      var msg = q ? 'No couples match your search.'
        : state.view === 'settled' ? 'Nobody has broken up yet.'
        : state.role === 'admin' ? 'No couples yet. Add one in the Admin tab.' : 'No couples on the board yet.';
      box.appendChild(el('div', { class: 'empty', text: msg }));
      return;
    }
    list.forEach(function (c) { box.appendChild(renderCard(c)); });
  }

  function renderCard(c) {
    var live = c.status === 'active';
    var since = parseDate(c.since);
    var metaText = live
      ? 'Together since ' + fmtDate(c.since) + ' · ' + fmtDuration(since, today())
      : 'Lasted ' + fmtDuration(since, parseDate(c.endedOn)) + ' · ' + fmtDate(c.since) + ' to ' + fmtDate(c.endedOn);
    var head = el('div', { class: 'card-head' }, [
      el('div', null, [
        el('div', { class: 'names' }, [c.a, el('span', { class: 'amp', text: '♥' }), c.b]),
        el('div', { class: 'meta', text: metaText }),
        c.note ? el('div', { class: 'note', text: c.note }) : null,
        live ? sourceLine(c) : null
      ]),
      el('span', { class: 'status ' + (live ? 'live' : 'settled'), text: live ? 'Live' : 'Settled' })
    ]);
    var win = live ? null : outcome(c);
    var lv = live ? liveOf(c) : null;
    var markets = el('div', { class: 'markets' }, BUCKETS.map(function (b) {
      var open = live && isOpen(c, b.key);
      var selected = !!(state.selection && state.selection.id === c.id && state.selection.bucket === b.key);
      var cls = 'odds-btn', valueText = fmtOdds(oddsOf(c, b.key));
      var pct = lv && open ? fmtPct(lv.probs[b.key]) : '';
      if (!live) { cls += b.key === win ? ' won' : ' lost'; valueText = b.key === win ? 'Winner' : fmtOdds(c.odds[b.key]); }
      else if (!open) { cls += ' closed'; valueText = 'Closed'; }
      return el('button', {
        type: 'button', class: cls, title: b.hint, disabled: !open,
        'aria-pressed': open ? String(selected) : null,
        'aria-label': coupleName(c) + ', ' + b.label + ', ' + (open ? 'odds ' + valueText + (pct ? ', ' + pct + ' chance on Manifold' : '') : valueText),
        onclick: open ? function () { select(c.id, b.key); } : null
      }, [
        el('span', { class: 'm-label', text: b.label }),
        el('span', { class: 'm-odds', text: valueText }),
        pct ? el('span', { class: 'm-pct', text: pct }) : null
      ]);
    }));
    return el('article', { class: 'card' }, [head, markets]);
  }

  function sourceLine(c) {
    if (!manifoldSlug(c.betUrl)) return el('div', { class: 'source', text: 'House odds' });
    var l = state.live[c.id];
    if (!l) return el('div', { class: 'source', text: 'Loading live odds from Manifold…' });
    if (!l.ok) return el('div', { class: 'source warn', text: 'Live odds unavailable, showing house odds' });
    var parts = ['Live from Manifold', l.bettors + (l.bettors === 1 ? ' bettor' : ' bettors'), 'M$' + Math.round(l.volume) + ' volume'];
    if (l.resolved) parts.push('market resolved');
    if (l.stale) parts.push('last update failed');
    return el('div', { class: 'source live' }, [el('span', { class: 'pulse' }), parts.join(' · ')]);
  }

  /* ---------- bet slip ---------- */
  function select(id, bucket) {
    var s = state.selection;
    state.selection = s && s.id === id && s.bucket === bucket ? null : { id: id, bucket: bucket };
    renderBook();
    renderSlip();
  }

  function renderSlip() {
    var sel = state.selection, c = sel && findCouple(sel.id);
    if (sel && (!c || c.status !== 'active' || !isOpen(c, sel.bucket))) { state.selection = sel = c = null; }
    document.body.classList.toggle('has-slip', !!sel && state.view !== 'admin');
    $('slip-empty').hidden = !!sel;
    $('slip-body').hidden = !sel;
    if (!sel) return;
    var b = BUCKETS.filter(function (x) { return x.key === sel.bucket; })[0];
    $('slip-couple').textContent = coupleName(c);
    $('slip-bucket').textContent = b.label + ' (' + b.hint.toLowerCase() + ')';
    $('slip-odds').textContent = fmtOdds(oddsOf(c, sel.bucket));
    var lv = liveOf(c);
    $('slip-source').textContent = lv
      ? 'Live odds from Manifold: ' + fmtPct(lv.probs[sel.bucket]) + ' of the market expects this. Your real payout on Manifold depends on the price when you bet.'
      : 'Break365 house odds, for fun. Your bet is placed and tracked on the linked site.';
    updateReturn();
    var url = betUrlFor(c), go = $('slip-go');
    if (url) {
      var host = new URL(url).hostname.replace(/^www\./, '');
      go.href = url;
      go.textContent = 'Place bet on ' + host;
      go.removeAttribute('aria-disabled');
      go.hidden = false;
      $('slip-nolink').hidden = true;
    } else {
      go.removeAttribute('href');
      go.hidden = true;
      $('slip-nolink').hidden = false;
    }
  }

  function updateReturn() {
    var sel = state.selection, c = sel && findCouple(sel.id);
    if (!c) return;
    var stake = Number($('slip-stake').value);
    if (!isFinite(stake) || stake < 0) stake = 0;
    $('slip-return').textContent = (stake * oddsOf(c, sel.bucket)).toFixed(2);
  }

  /* ---------- admin: changes and sync ---------- */
  function applyOps(data, ops) {
    var d = JSON.parse(JSON.stringify(data));
    ops.forEach(function (op) {
      if (op.t === 'upsert') {
        var i = -1;
        d.couples.forEach(function (c, j) { if (c.id === op.c.id) i = j; });
        if (i >= 0) d.couples[i] = op.c; else d.couples.push(op.c);
      } else if (op.t === 'delete') {
        d.couples = d.couples.filter(function (c) { return c.id !== op.id; });
      } else if (op.t === 'settings') {
        d.settings = Object.assign({}, op.s);
      }
    });
    return normalizeData(d);
  }

  // Every admin change goes through here: applied locally at once, then published automatically.
  function commit(op) {
    state.pending.push(op);
    state.data = applyOps(state.data, [op]);
    state.syncError = '';
    queuePublish();
    renderSyncState();
  }

  function renderSyncState() {
    var n = state.pending.length;
    $('dirty-dot').hidden = !n;
    var bar = $('sync-bar'), text, kind;
    if (state.publishing) { text = 'Publishing…'; kind = 'busy'; }
    else if (state.syncError) { text = 'Not published: ' + state.syncError; kind = 'error'; }
    else if (n && !state.gh) { text = n + (n === 1 ? ' change is' : ' changes are') + ' only in this tab. Connect GitHub once (bottom of this page) to publish automatically.'; kind = 'error'; }
    else if (!state.gh) { text = 'GitHub is not connected yet, so changes cannot be published. See the bottom of this page.'; kind = 'warn'; }
    else if (state.lastPublished) { text = 'All changes published. Players see them within about 1 to 2 minutes.'; kind = 'ok'; }
    else { text = 'Connected. Every change you make is published automatically.'; kind = 'ok'; }
    $('sync-text').textContent = text;
    bar.className = 'sync-bar ' + kind;
    $('sync-retry').hidden = !(state.syncError && state.gh && n);
    // connection panel
    $('gh-connected').hidden = !state.gh || state.ghEditing;
    $('gh-form').hidden = !!state.gh && !state.ghEditing;
    $('gh-cancel').hidden = !state.ghEditing;
    if (state.gh) $('gh-where').textContent = state.gh.owner + '/' + state.gh.repo + ' (branch ' + state.gh.branch + (state.gh.dir ? ', folder ' + state.gh.dir : '') + ')';
    if (state.ghNotice && !state.gh) setMsg('gh-msg', state.ghNotice, 'error');
  }

  function renderAdmin() {
    var box = $('admin-list');
    box.textContent = '';
    if (!state.data.couples.length) box.appendChild(el('p', { class: 'muted', text: 'No couples yet.' }));
    state.data.couples.slice().sort(function (x, y) { return x.since < y.since ? 1 : x.since > y.since ? -1 : 0; })
      .forEach(function (c) {
        var info = c.status === 'active' ? 'Live since ' + fmtDate(c.since) : 'Settled: ' + labelOf(outcome(c));
        if (manifoldSlug(c.betUrl)) info += ' · Manifold market';
        box.appendChild(el('div', { class: 'admin-item' }, [
          el('div', null, [el('div', { class: 'names', text: coupleName(c) }), el('div', { class: 'meta', text: info })]),
          el('div', { class: 'actions' }, [
            el('button', { type: 'button', class: 'btn btn-ghost btn-small', text: 'Edit', onclick: function () { editCouple(c.id); } }),
            el('button', { type: 'button', class: 'btn btn-danger', text: 'Delete', onclick: function () { deleteCouple(c.id); } })
          ])
        ]));
      });
    $('s-url').value = state.data.settings.defaultBetUrl;
    $('s-margin').value = String(state.data.settings.margin);
    renderSyncState();
  }

  function resetForm() {
    $('couple-form').reset();
    $('f-id').value = '';
    $('f-since').max = toISO(today());
    $('f-ended').max = toISO(today());
    $('f-o-weeks').value = '3.00';
    $('f-o-months').value = '2.00';
    $('f-o-years').value = '4.00';
    $('f-ended-wrap').hidden = true;
    $('form-title').textContent = 'Add couple';
    $('f-save').textContent = 'Add couple';
    $('f-cancel').hidden = true;
    setMsg('form-msg', '');
  }

  function editCouple(id) {
    var c = findCouple(id);
    if (!c) return;
    $('f-id').value = c.id;
    $('f-a').value = c.a;
    $('f-b').value = c.b;
    $('f-since').value = c.since;
    $('f-status').value = c.status;
    $('f-ended').value = c.endedOn;
    $('f-ended-wrap').hidden = c.status !== 'ended';
    $('f-o-weeks').value = fmtOdds(c.odds.weeks);
    $('f-o-months').value = fmtOdds(c.odds.months);
    $('f-o-years').value = fmtOdds(c.odds.years);
    $('f-url').value = c.betUrl;
    $('f-note').value = c.note;
    $('form-title').textContent = 'Edit couple';
    $('f-save').textContent = 'Save changes';
    $('f-cancel').hidden = false;
    setMsg('form-msg', '');
    $('couple-form').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function deleteCouple(id) {
    var c = findCouple(id);
    if (!c || !confirm('Delete ' + coupleName(c) + '?')) return;
    if (state.selection && state.selection.id === id) state.selection = null;
    if ($('f-id').value === id) resetForm();
    commit({ t: 'delete', id: id });
    renderAdmin();
  }

  function saveCouple(ev) {
    ev.preventDefault();
    var todayISO = toISO(today());
    var a = cleanText($('f-a').value, 60), b = cleanText($('f-b').value, 60);
    var since = $('f-since').value, status = $('f-status').value, ended = $('f-ended').value;
    var rawUrl = $('f-url').value.trim(), url = safeUrl(rawUrl);
    var odds = { weeks: validOdds($('f-o-weeks').value), months: validOdds($('f-o-months').value), years: validOdds($('f-o-years').value) };
    var err = !a || !b ? 'Enter both names.'
      : !isISODate(since) ? 'Enter the date they got together.'
      : since > todayISO ? 'The start date cannot be in the future.'
      : odds.weeks === null || odds.months === null || odds.years === null ? 'Odds must be numbers between 1.01 and 1000.'
      : rawUrl && !url ? 'The betting link must be a valid https:// address.'
      : url && isManifoldHost(url) && !manifoldSlug(url) ? 'Paste the full Manifold market link, like https://manifold.markets/username/market-name'
      : status === 'ended' && !isISODate(ended) ? 'Enter the break-up date.'
      : status === 'ended' && ended < since ? 'The break-up date cannot be before the start date.'
      : status === 'ended' && ended > todayISO ? 'The break-up date cannot be in the future.'
      : '';
    if (err) { setMsg('form-msg', err, 'error'); return; }
    var id = $('f-id').value;
    var couple = normCouple({ id: id || newId(), a: a, b: b, since: since, odds: odds, betUrl: url,
      note: $('f-note').value, status: status, endedOn: status === 'ended' ? ended : '' });
    if (id) delete state.live[id];
    commit({ t: 'upsert', c: couple });
    var done = (id ? 'Saved ' : 'Added ') + coupleName(couple) + '.';
    resetForm();
    setMsg('form-msg', done, 'ok');
    renderAdmin();
    refreshLive();
  }

  async function checkMarket() {
    var raw = $('f-url').value.trim(), url = safeUrl(raw), slug = manifoldSlug(url);
    if (!slug) {
      setMsg('form-msg', 'Paste a Manifold market link first, like https://manifold.markets/username/market-name', 'error');
      return;
    }
    $('f-check').disabled = true;
    setMsg('form-msg', 'Checking the market…');
    try {
      var r = await fetchMarket(slug);
      setMsg('form-msg', 'Market OK. ' + BUCKETS.map(function (b) {
        return b.label + ' ' + fmtPct(r.probs[b.key]) + ' (' + fmtOdds(oddsFromProb(r.probs[b.key])) + ')';
      }).join(', ') + '. ' + r.bettors + (r.bettors === 1 ? ' bettor.' : ' bettors.'), 'ok');
    } catch (e) {
      setMsg('form-msg', e.message, 'error');
    } finally {
      $('f-check').disabled = false;
    }
  }

  function saveSettings(ev) {
    ev.preventDefault();
    var raw = $('s-url').value.trim(), url = safeUrl(raw);
    var margin = validMargin($('s-margin').value === '' ? 0 : $('s-margin').value);
    if (raw && !url) { setMsg('settings-msg', 'The link must be a valid https:// address.', 'error'); return; }
    if (margin === null) { setMsg('settings-msg', 'House margin must be between 0 and 25.', 'error'); return; }
    commit({ t: 'settings', s: { defaultBetUrl: url, margin: margin } });
    setMsg('settings-msg', 'Settings saved.', 'ok');
  }

  /* ---------- GitHub (admin only) ---------- */
  function validGh(g) {
    if (!g || typeof g !== 'object') return null;
    var owner = String(g.owner || ''), repo = String(g.repo || ''), branch = String(g.branch || '');
    var dir = String(g.dir || '').replace(/^\/+|\/+$/g, ''), token = String(g.token || '');
    if (!/^[A-Za-z0-9-]{1,39}$/.test(owner) || !/^[A-Za-z0-9._-]{1,100}$/.test(repo)) return null;
    if (!/^[A-Za-z0-9._\/-]{1,200}$/.test(branch) || !/^[A-Za-z0-9._\/-]{0,200}$/.test(dir) || /\.\./.test(dir)) return null;
    if (!/^[A-Za-z0-9_]{20,255}$/.test(token)) return null;
    return { owner: owner, repo: repo, branch: branch, dir: dir, token: token };
  }
  function ghPath(g, file) { return (g.dir ? g.dir + '/' : '') + file; }
  function ghUrl(g, file) {
    return 'https://api.github.com/repos/' + encodeURIComponent(g.owner) + '/' + encodeURIComponent(g.repo) +
      '/contents/' + ghPath(g, file).split('/').map(encodeURIComponent).join('/');
  }
  function ghHeaders(g) {
    return { 'Accept': 'application/vnd.github+json', 'Authorization': 'Bearer ' + g.token, 'X-GitHub-Api-Version': '2022-11-28' };
  }
  function ghError(status) {
    if (status === 401) return 'the GitHub connection has expired or was revoked. The site owner needs to connect GitHub again (bottom of the Admin page).';
    if (status === 403) return 'GitHub denied access. The token needs Contents: Read and write on this repository.';
    if (status === 404) return 'GitHub could not find the repository, branch or file. Check the connection details.';
    if (status === 422) return 'GitHub refused the update. Check the branch and folder.';
    return 'GitHub returned an error (' + status + '). Try again in a moment.';
  }
  async function ghFetch(url, opts) {
    try { return await fetch(url, Object.assign({ cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer' }, opts)); }
    catch (e) { throw new Error('could not reach GitHub. Check your internet connection.'); }
  }
  // -> { sha, text } ; { sha: null, text: null } when the file does not exist
  async function ghGet(g, file) {
    var r = await ghFetch(ghUrl(g, file) + '?ref=' + encodeURIComponent(g.branch), { headers: ghHeaders(g) });
    if (r.status === 404) return { sha: null, text: null };
    if (!r.ok) throw new Error(ghError(r.status));
    var j = await r.json();
    if (j.encoding !== 'base64' || typeof j.content !== 'string') throw new Error('the file on GitHub could not be read.');
    return { sha: j.sha, text: DEC.decode(b64dec(j.content.replace(/\s/g, ''))) };
  }
  // -> true, or 'conflict' when someone else changed the file in the meantime
  async function ghPut(g, file, text, sha, message) {
    var body = { message: message, content: b64enc(ENC.encode(text)), branch: g.branch };
    if (sha) body.sha = sha;
    var r = await ghFetch(ghUrl(g, file), {
      method: 'PUT', headers: Object.assign({ 'Content-Type': 'application/json' }, ghHeaders(g)), body: JSON.stringify(body)
    });
    if (r.status === 409 || (r.status === 422 && sha)) return 'conflict';
    if (!r.ok) throw new Error(ghError(r.status));
    return true;
  }

  async function readRemoteData(g) {
    var cur = await ghGet(g, 'couples.enc.json');
    var data = normalizeData(null);
    if (cur.text) {
      try { data = normalizeData(await decryptData(state.key, JSON.parse(cur.text))); }
      catch (e) { throw new Error('the couples file on GitHub uses different passwords. Reload the page and log in again.'); }
    }
    return { sha: cur.sha, data: data };
  }

  // Admin login: start from the newest published data (GitHub Pages can lag a minute or two).
  async function pullLatest() {
    var session = state.session;
    try {
      var r = await readRemoteData(state.gh);
      if (session !== state.session) return;
      state.data = applyOps(r.data, state.pending);
      if (state.view === 'admin') renderAdmin(); else renderBook();
      renderSlip();
      refreshLive();
    } catch (e) {
      if (session !== state.session) return;
      state.syncError = e.message;
      renderSyncState();
    }
  }

  function queuePublish() {
    if (!state.gh || state.publishing) return;
    publishNow();
  }

  async function publishNow() {
    var session = state.session;
    state.publishing = true;
    state.syncError = '';
    renderSyncState();
    try {
      while (state.pending.length) {
        var ops = state.pending.slice(), merged = null;
        for (var attempt = 0; attempt < 4 && !merged; attempt++) {
          // Re-read the latest file and re-apply our changes, so two admins never overwrite each other.
          var r = await readRemoteData(state.gh);
          var next = applyOps(r.data, ops);
          var ok = await ghPut(state.gh, 'couples.enc.json', await encryptData(state.key, next), r.sha, 'Update data');
          if (session !== state.session) return;
          if (ok === true) merged = next;
        }
        if (!merged) throw new Error('GitHub kept reporting that the file changed. Try again in a moment.');
        state.pending = state.pending.slice(ops.length);
        state.data = applyOps(merged, state.pending);
        state.lastPublished = Date.now();
      }
    } catch (e) {
      if (session !== state.session) return;
      state.syncError = e.message;
    } finally {
      if (session === state.session) {
        state.publishing = false;
        if (state.view === 'admin') renderAdmin(); else { renderBook(); renderSlip(); }
        renderSyncState();
      }
    }
  }

  function prefillGitHub() {
    var host = location.hostname, m = host.match(/^([a-z0-9-]+)\.github\.io$/i);
    var seg = location.pathname.split('/').filter(Boolean);
    if (seg.length && /\.html?$/i.test(seg[seg.length - 1])) seg.pop();
    var g = state.gh;
    $('gh-owner').value = g ? g.owner : (m ? m[1] : '');
    $('gh-repo').value = g ? g.repo : (m ? (seg[0] || host) : '');
    $('gh-branch').value = g ? g.branch : 'main';
    $('gh-dir').value = g ? g.dir : (m ? seg.slice(1).join('/') : '');
    $('gh-token').value = '';
  }

  // One-time setup: store the GitHub connection inside keyring.json, encrypted with the admin password's key.
  async function connectGitHub(ev) {
    ev.preventDefault();
    var g = validGh({
      owner: $('gh-owner').value.trim(), repo: $('gh-repo').value.trim(),
      branch: $('gh-branch').value.trim() || 'main', dir: $('gh-dir').value.trim(), token: $('gh-token').value.trim()
    });
    if (!g) { setMsg('gh-msg', 'Check the owner, repository, branch, folder and token.', 'error'); return; }
    await saveConnection(g, 'Connected. From now on every change is published automatically.');
  }

  async function disconnectGitHub() {
    if (!state.gh || !confirm('Disconnect GitHub? Admins will not be able to publish until someone connects it again.')) return;
    await saveConnection(null, 'Disconnected.');
  }

  async function saveConnection(g, okText) {
    var session = state.session, via = g || state.gh;
    $('gh-btn').disabled = true;
    setMsg('gh-msg', 'Saving the connection…');
    try {
      var cur = await ghGet(via, 'keyring.json');
      if (!cur.text) throw new Error('keyring.json was not found there. Check the repository, branch and folder.');
      var kr = JSON.parse(cur.text), mine = state.keyring.roles.admin;
      if (!kr.roles || !kr.roles.admin || kr.roles.admin.salt !== mine.salt || kr.roles.admin.wrapped !== mine.wrapped) {
        throw new Error('the passwords in that repository are different from this page. Reload the page and try again.');
      }
      if (g) kr.roles.admin.secrets = await encryptSecrets(state.adminKek, g);
      else delete kr.roles.admin.secrets;
      var ok = await ghPut(via, 'keyring.json', JSON.stringify(kr, null, 2) + '\n', cur.sha, 'Update keyring');
      if (ok !== true) throw new Error('keyring.json changed while saving. Try again.');
      if (session !== state.session) return;
      state.keyring = kr;
      state.gh = g;
      state.ghNotice = '';
      state.ghEditing = false;
      state.syncError = '';
      $('gh-token').value = '';
      setMsg('gh-msg', okText, 'ok');
      renderSyncState();
      if (g && state.pending.length) queuePublish();
    } catch (e) {
      if (session !== state.session) return;
      var msg = e.message || 'unknown error.';
      setMsg('gh-msg', 'Could not save: ' + msg, 'error');
    } finally {
      $('gh-btn').disabled = false;
    }
  }

  function download() {
    return encryptData(state.key, state.data).then(function (content) {
      var blob = new Blob([content], { type: 'application/json' });
      var a = el('a', { href: URL.createObjectURL(blob), download: 'couples.enc.json' });
      document.body.appendChild(a);
      a.click();
      setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
      if (!state.gh) { state.pending = []; renderSyncState(); }
    });
  }

  /* ---------- wiring ---------- */
  $('login-form').addEventListener('submit', login);
  $('logout-btn').addEventListener('click', logout);
  Array.prototype.forEach.call(document.querySelectorAll('.tab'), function (t) {
    t.addEventListener('click', function () { setView(t.getAttribute('data-view')); });
  });
  $('search').addEventListener('input', function () { state.query = this.value.trim(); renderBook(); });
  $('slip-close').addEventListener('click', function () { state.selection = null; renderBook(); renderSlip(); });
  $('slip-stake').addEventListener('input', updateReturn);
  $('couple-form').addEventListener('submit', saveCouple);
  $('f-cancel').addEventListener('click', resetForm);
  $('f-status').addEventListener('change', function () {
    $('f-ended-wrap').hidden = this.value !== 'ended';
    if (this.value === 'ended' && !$('f-ended').value) $('f-ended').value = toISO(today());
  });
  $('settings-form').addEventListener('submit', saveSettings);
  $('f-check').addEventListener('click', checkMarket);
  document.addEventListener('visibilitychange', function () {
    if (!document.hidden && state.timer && Date.now() - state.lastRefresh > REFRESH_MS) refreshLive();
  });
  $('gh-form').addEventListener('submit', connectGitHub);
  $('gh-change').addEventListener('click', function () { state.ghEditing = true; prefillGitHub(); setMsg('gh-msg', ''); renderSyncState(); });
  $('gh-cancel').addEventListener('click', function () { state.ghEditing = false; setMsg('gh-msg', ''); renderSyncState(); });
  $('gh-disconnect').addEventListener('click', disconnectGitHub);
  $('sync-retry').addEventListener('click', function () { state.syncError = ''; queuePublish(); renderSyncState(); });
  $('dl-btn').addEventListener('click', function () {
    download().catch(function () { alert('Could not create the file.'); });
  });
  window.addEventListener('beforeunload', function (e) {
    if (state.pending.length) { e.preventDefault(); e.returnValue = ''; }
  });

  boot();
})();
