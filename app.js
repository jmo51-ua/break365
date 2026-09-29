/* Break365. Static, client-side only.
 * Security model:
 *  - No password is stored anywhere. keyring.json holds, per role, a PBKDF2 salt and the data key wrapped
 *    (AES-GCM) with a key derived from that role's password. Passwords are checked only in this browser.
 *  - couples.enc.json (site repository) is AES-256-GCM ciphertext made with the data key.
 *  - The admin's GitHub connection (site repository) is encrypted with the admin password's key only.
 *  - Bets live in bets.enc.json in a separate PRIVATE repository, encrypted with a random bets key that is
 *    itself stored inside the encrypted couples data.
 * Betting model (pool based, like Twitch predictions):
 *  - A "line" is a duration (N weeks, months or years from the day they got together) or the marriage question.
 *  - Each line has two sides: + (still together after the date) and - (break up on or before it), or Yes / No.
 *  - Odds of a side = all points on the line / points on that side. Winners split the whole line pool.
 *  - Lines resolve on their own from the dates the admin enters. Bets placed on or after the day that
 *    decides a line are refunded.
 */
(function () {
  'use strict';

  var ENC = new TextEncoder();
  var DEC = new TextDecoder();
  var AAD_DATA = ENC.encode('break365/data/v1');
  var AAD_SECRETS = ENC.encode('break365/admin-secrets/v1');
  var AAD_BETS = ENC.encode('break365/bets/v1');
  function aadKey(role) { return ENC.encode('break365/keyring/v1/' + role); }

  var UNITS = {
    w: { one: 'week', many: 'weeks', max: 520 },
    m: { one: 'month', many: 'months', max: 240 },
    y: { one: 'year', many: 'years', max: 50 }
  };
  var BETS_FILE = 'bets.enc.json';
  var POLL_MS = 10000, ERROR_MS = 20000, BACKOFF_MS = 60000, COUPLES_MS = 60000;
  var PIN_ITER = 100000;
  var PROFILE_KEY = 'break365.profile.v1';
  var DEFAULT_START = 1000;
  var MAX_OPEN_LINES = 5;
  var MINUS = '−';

  var state = {
    keyring: null, encFile: null, role: null, key: null, data: null,
    view: 'live', query: '', selection: null,
    pending: [], publishing: false, syncError: '', lastPublished: 0,
    adminKek: null, gh: null, ghNotice: '', ghEditing: false, betsEditing: false,
    session: 0,
    bets: null, stats: null, betsStatus: 'idle', betsError: '', betsFor: null, betsEtag: null,
    betsLoop: 0, betsTimer: null, betsWaiting: false, couplesTimer: null,
    profile: null, placing: false, openBets: Object.create(null), openSettled: Object.create(null)
  };

  var $ = function (id) { return document.getElementById(id); };

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
  function randomB64(n) { return b64enc(crypto.getRandomValues(new Uint8Array(n))); }
  function newId() {
    if (crypto.randomUUID) return crypto.randomUUID();
    var r = crypto.getRandomValues(new Uint8Array(16)), s = '';
    for (var i = 0; i < r.length; i++) s += ('0' + r[i].toString(16)).slice(-2);
    return s;
  }
  function userErr(msg) { var e = new Error(msg); e.user = true; return e; }
  function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

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
  async function encryptSecrets(kek, obj) {
    var iv = crypto.getRandomValues(new Uint8Array(12));
    var ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv, additionalData: AAD_SECRETS }, kek, ENC.encode(JSON.stringify(obj)));
    return { iv: b64enc(iv), ct: b64enc(new Uint8Array(ct)) };
  }
  async function decryptSecrets(kek, s) {
    var pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64dec(s.iv), additionalData: AAD_SECRETS }, kek, b64dec(s.ct));
    return JSON.parse(DEC.decode(pt));
  }
  async function encryptWith(key, aad, obj) {
    var iv = crypto.getRandomValues(new Uint8Array(12));
    var ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv, additionalData: aad }, key, ENC.encode(JSON.stringify(obj)));
    return JSON.stringify({ v: 1, iv: b64enc(iv), ct: b64enc(new Uint8Array(ct)) }) + '\n';
  }
  async function decryptWith(key, aad, file) {
    if (!file || typeof file.iv !== 'string' || typeof file.ct !== 'string') throw new Error('not an encrypted file');
    var pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64dec(file.iv), additionalData: aad }, key, b64dec(file.ct));
    return JSON.parse(DEC.decode(pt));
  }
  function importAes(rawB64) {
    return crypto.subtle.importKey('raw', b64dec(rawB64), 'AES-GCM', false, ['encrypt', 'decrypt']);
  }
  async function pinHash(pin, saltB64) {
    var base = await crypto.subtle.importKey('raw', ENC.encode(pin), 'PBKDF2', false, ['deriveBits']);
    var bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: b64dec(saltB64), iterations: PIN_ITER }, base, 256);
    return b64enc(new Uint8Array(bits));
  }

  /* ---------- validation ---------- */
  function cleanText(s, max) { return typeof s === 'string' ? s.replace(/\s+/g, ' ').trim().slice(0, max) : ''; }
  function isoParts(s) { return [+s.slice(0, 4), +s.slice(5, 7), +s.slice(8, 10)]; }
  function isISODate(s) {
    if (typeof s !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
    var p = isoParts(s), d = new Date(Date.UTC(p[0], p[1] - 1, p[2]));
    return p[0] >= 1900 && d.getUTCFullYear() === p[0] && d.getUTCMonth() === p[1] - 1 && d.getUTCDate() === p[2];
  }
  function isoAddDays(s, n) {
    var p = isoParts(s);
    return new Date(Date.UTC(p[0], p[1] - 1, p[2] + n)).toISOString().slice(0, 10);
  }
  function isoAddMonths(s, n) {
    var p = isoParts(s), m = p[1] - 1 + n;
    var last = new Date(Date.UTC(p[0], m + 1, 0)).getUTCDate();
    return new Date(Date.UTC(p[0], m, Math.min(p[2], last))).toISOString().slice(0, 10);
  }
  function utcDay(t) { return new Date(t).toISOString().slice(0, 10); }
  function validStart(n) { n = Number(n); return Number.isInteger(n) && n >= 10 && n <= 1000000 ? n : null; }
  function playerKey(name) { return cleanText(name, 24).normalize('NFKC').toLowerCase(); }

  function validGh(g) {
    if (!g || typeof g !== 'object') return null;
    var owner = String(g.owner || ''), repo = String(g.repo || ''), branch = String(g.branch || '');
    var dir = String(g.dir || '').replace(/^\/+|\/+$/g, ''), token = String(g.token || '');
    if (!/^[A-Za-z0-9-]{1,39}$/.test(owner) || !/^[A-Za-z0-9._-]{1,100}$/.test(repo)) return null;
    if (!/^[A-Za-z0-9._\/-]{1,200}$/.test(branch) || !/^[A-Za-z0-9._\/-]{0,200}$/.test(dir) || /\.\./.test(dir)) return null;
    if (!/^[A-Za-z0-9_]{20,255}$/.test(token)) return null;
    return { owner: owner, repo: repo, branch: branch, dir: dir, token: token };
  }
  function validBetsConn(g) {
    if (!g || typeof g !== 'object') return null;
    var v = validGh({ owner: g.owner, repo: g.repo, branch: g.branch, dir: '', token: g.token });
    if (!v) return null;
    try { if (typeof g.key !== 'string' || b64dec(g.key).length !== 32) return null; } catch (e) { return null; }
    return { owner: v.owner, repo: v.repo, branch: v.branch, dir: '', token: v.token, key: g.key };
  }

  function normCouple(c) {
    if (!c || typeof c !== 'object') return null;
    var a = cleanText(c.a, 60), b = cleanText(c.b, 60);
    if (!a || !b || !isISODate(c.since)) return null;
    var ended = c.status === 'ended' && isISODate(c.endedOn) && c.endedOn >= c.since;
    var married = isISODate(c.marriedOn) && c.marriedOn >= c.since && (!ended || c.marriedOn <= c.endedOn);
    return {
      id: typeof c.id === 'string' && c.id ? c.id.slice(0, 64) : newId(),
      a: a, b: b, since: c.since,
      note: cleanText(c.note, 140),
      status: ended ? 'ended' : 'active',
      endedOn: ended ? c.endedOn : '',
      marriedOn: married ? c.marriedOn : ''
    };
  }
  function normalizeData(d) {
    var out = { v: 2, settings: { startPoints: DEFAULT_START, bets: null }, couples: [] };
    if (d && typeof d === 'object') {
      if (d.settings && typeof d.settings === 'object') {
        out.settings.startPoints = validStart(d.settings.startPoints) || DEFAULT_START;
        out.settings.bets = validBetsConn(d.settings.bets);
      }
      if (Array.isArray(d.couples)) {
        var seen = Object.create(null);
        out.couples = d.couples.map(normCouple).filter(function (c) {
          if (!c || seen[c.id]) return false;
          seen[c.id] = 1;
          return true;
        });
      }
    }
    return out;
  }

  /* ---------- lines (markets) ---------- */
  function parseMk(mk) {
    if (mk === 'marry') return { type: 'marry' };
    var m = /^([1-9]\d{0,2})([wmy])$/.exec(typeof mk === 'string' ? mk : '');
    if (!m) return null;
    var n = +m[1];
    return n <= UNITS[m[2]].max ? { type: 'dur', n: n, u: m[2] } : null;
  }
  function sidesOf(mk) { return mk === 'marry' ? ['yes', 'no'] : ['over', 'under']; }
  function validSide(mk, s) { return sidesOf(mk).indexOf(s) !== -1; }
  function mkLabel(mk) {
    var p = parseMk(mk);
    if (!p) return '';
    if (p.type === 'marry') return 'Marriage';
    return p.n + ' ' + (p.n === 1 ? UNITS[p.u].one : UNITS[p.u].many);
  }
  function betLabel(mk, s) {
    if (mk === 'marry') return s === 'yes' ? 'Marry: Yes' : 'Marry: No';
    return (s === 'over' ? '+' : MINUS) + mkLabel(mk);
  }
  function sideShort(mk, s) {
    if (mk === 'marry') return s === 'yes' ? 'Yes' : 'No';
    return s === 'over' ? '+ More' : MINUS + ' Less';
  }
  // The date that decides a duration line (UTC dates, same result in every browser).
  function threshold(c, mk) {
    var p = parseMk(mk);
    if (p.u === 'w') return isoAddDays(c.since, 7 * p.n);
    if (p.u === 'm') return isoAddMonths(c.since, p.n);
    return isoAddMonths(c.since, 12 * p.n);
  }
  // Winning side, or '' while the line is still open.
  function marketResult(c, mk, day) {
    if (mk === 'marry') {
      if (c.marriedOn) return 'yes';
      if (c.status === 'ended') return 'no';
      return '';
    }
    var th = threshold(c, mk);
    if (c.status === 'ended') return c.endedOn > th ? 'over' : 'under';
    if (day > th) return 'over';
    return '';
  }
  // A bet counts only if it was placed before the day that decided its line.
  function betValid(c, mk, t) {
    var d = utcDay(t);
    if (c.status === 'ended' && d >= c.endedOn) return false;
    if (mk === 'marry') return !(c.marriedOn && d >= c.marriedOn);
    return d < threshold(c, mk);
  }
  function canBetNow(c, mk) {
    var now = Date.now();
    return c.status === 'active' && betValid(c, mk, now) && !marketResult(c, mk, utcDay(now));
  }

  /* ---------- local dates (display only) ---------- */
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
  function fmtWhen(t) {
    return new Date(t).toLocaleString('en-GB', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });
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

  /* ---------- bets data ---------- */
  function emptyBets() { return { v: 2, players: Object.create(null), bets: [] }; }
  function normalizeBets(d) {
    var out = emptyBets();
    if (!d || typeof d !== 'object') return out;
    if (d.players && typeof d.players === 'object') {
      Object.keys(d.players).forEach(function (k) {
        var p = d.players[k];
        if (!p || typeof p !== 'object') return;
        var name = cleanText(p.name, 24);
        if (!name || playerKey(name) !== k) return;
        out.players[k] = { name: name, salt: typeof p.salt === 'string' ? p.salt : '', hash: typeof p.hash === 'string' ? p.hash : '' };
      });
    }
    if (Array.isArray(d.bets)) {
      var seen = Object.create(null);
      d.bets.forEach(function (b) {
        if (!b || typeof b !== 'object' || typeof b.id !== 'string' || !b.id || seen[b.id]) return;
        if (typeof b.c !== 'string' || !parseMk(b.m) || !validSide(b.m, b.s) || !out.players[b.k]) return;
        var p = Number(b.p), t = Number(b.t);
        if (!Number.isInteger(p) || p < 1 || p > 1e9 || !isFinite(t) || t <= 0 || t > 8.64e15) return;
        seen[b.id] = 1;
        out.bets.push({ id: b.id.slice(0, 64), c: b.c, m: b.m, s: b.s, p: p, k: b.k, t: t });
      });
    }
    out.bets.sort(function (x, y) { return x.t - y.t; });
    return out;
  }

  function newMarket(c, mk, day) {
    var m = { mk: mk, pools: {}, bettors: {}, total: 0, list: [], winner: marketResult(c, mk, day), ratio: 0, refundedAll: false };
    sidesOf(mk).forEach(function (s) { m.pools[s] = 0; m.bettors[s] = 0; });
    return m;
  }

  // Pure: same data and bets give the same balances in every browser.
  function computeStats(data, bets) {
    var start = data.settings.startPoints, day = utcDay(Date.now());
    var S = { players: Object.create(null), couples: Object.create(null), bets: Object.create(null) };
    Object.keys(bets.players).forEach(function (k) {
      S.players[k] = { key: k, name: bets.players[k].name, balance: start, locked: 0, net: 0, won: 0, lost: 0, count: 0 };
    });
    var cmap = Object.create(null);
    data.couples.forEach(function (c) {
      cmap[c.id] = c;
      S.couples[c.id] = { markets: Object.create(null), total: 0, people: 0, list: [], seen: Object.create(null) };
    });
    var seenSide = Object.create(null);
    bets.bets.forEach(function (b) {
      var c = cmap[b.c], pl = S.players[b.k];
      if (!c || !pl) return; // bets on deleted couples do not count (points come back)
      var cs = S.couples[b.c];
      var m = cs.markets[b.m] || (cs.markets[b.m] = newMarket(c, b.m, day));
      var r = { bet: b, status: 'open', net: 0, payout: 0 };
      S.bets[b.id] = r;
      cs.list.push(r);
      m.list.push(r);
      pl.count++;
      if (!betValid(c, b.m, b.t)) { r.status = 'refunded'; return; }
      m.pools[b.s] += b.p;
      m.total += b.p;
      cs.total += b.p;
      var sk = b.c + '|' + b.m + '|' + b.s + '|' + b.k;
      if (!seenSide[sk]) { seenSide[sk] = 1; m.bettors[b.s]++; }
      if (!cs.seen[b.k]) { cs.seen[b.k] = 1; cs.people++; }
    });
    Object.keys(S.couples).forEach(function (id) {
      var cs = S.couples[id];
      Object.keys(cs.markets).forEach(function (mk) {
        var m = cs.markets[mk];
        var valid = m.list.filter(function (r) { return r.status !== 'refunded'; });
        if (!m.winner) {
          valid.forEach(function (r) { S.players[r.bet.k].locked += r.bet.p; });
          return;
        }
        var w = m.winner, pw = m.pools[w];
        if (!pw) {
          m.refundedAll = valid.length > 0;
          valid.forEach(function (r) { r.status = 'refunded'; });
          return;
        }
        m.ratio = m.total / pw;
        valid.forEach(function (r) {
          var pl = S.players[r.bet.k];
          if (r.bet.s === w) {
            r.payout = Math.floor(r.bet.p * m.total / pw);
            r.net = r.payout - r.bet.p;
            r.status = 'won';
            pl.won++;
          } else {
            r.net = -r.bet.p;
            r.status = 'lost';
            pl.lost++;
          }
          pl.net += r.net;
        });
      });
    });
    Object.keys(S.players).forEach(function (k) {
      var p = S.players[k];
      p.balance = start + p.net - p.locked;
    });
    return S;
  }
  function marketView(cs, c, mk) {
    return (cs && cs.markets[mk]) || newMarket(c, mk, utcDay(Date.now()));
  }
  // Which side of this line the player already backed (valid bets only), or ''.
  function sideOfPlayer(cs, mk, key) {
    if (!cs || !cs.markets[mk]) return '';
    var r = cs.markets[mk].list.filter(function (x) { return x.bet.k === key && x.status !== 'refunded'; })[0];
    return r ? r.bet.s : '';
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
  function fmtPts(n) { return Math.round(n).toLocaleString('en-US') + ' pts'; }
  function fmtPct(p) {
    var v = p * 100;
    if (v > 0 && v < 1) return '<1%';
    if (v > 99 && v < 100) return '>99%';
    return Math.round(v) + '%';
  }
  function coupleName(c) { return c.a + ' & ' + c.b; }
  function findCouple(id) {
    for (var i = 0; i < state.data.couples.length; i++) if (state.data.couples[i].id === id) return state.data.couples[i];
    return null;
  }
  function isBookView() { return state.view === 'live' || state.view === 'settled' || state.view === 'all'; }

  /* ---------- player profile (this device) ---------- */
  function loadProfile() {
    try {
      var p = JSON.parse(localStorage.getItem(PROFILE_KEY));
      if (p && typeof p.key === 'string' && typeof p.name === 'string' && typeof p.hash === 'string') return p;
    } catch (e) { /* storage unavailable */ }
    return null;
  }
  function saveProfile(p) { try { localStorage.setItem(PROFILE_KEY, JSON.stringify(p)); } catch (e) { /* ignore */ } }
  function forgetProfile() {
    state.profile = null;
    try { localStorage.removeItem(PROFILE_KEY); } catch (e) { /* ignore */ }
  }
  function checkProfile() {
    var p = state.profile;
    if (!p || !state.bets) return;
    var pl = state.bets.players[p.key];
    if (!pl || !pl.hash || pl.hash !== p.hash) forgetProfile();
  }

  /* ---------- loading and login ---------- */
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
      await sleep(400);
      $('login-btn').disabled = false;
      $('login-btn').textContent = 'Log in';
      setMsg('login-msg', 'Wrong password.', 'error');
      $('pw').select();
      return;
    }
    try {
      state.key = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
      raw.fill(0);
      state.data = normalizeData(await decryptWith(state.key, AAD_DATA, state.encFile));
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
    state.session++;
    stopBets();
    clearInterval(state.couplesTimer);
    state.couplesTimer = null;
    state.key = null; state.data = null; state.role = null; state.selection = null;
    state.pending = []; state.publishing = false; state.syncError = ''; state.lastPublished = 0;
    state.adminKek = null; state.gh = null; state.ghNotice = ''; state.ghEditing = false; state.betsEditing = false;
    state.bets = null; state.stats = null; state.betsStatus = 'idle'; state.betsError = ''; state.betsFor = null; state.betsEtag = null;
    state.profile = null; state.placing = false; state.query = '';
    state.openBets = Object.create(null); state.openSettled = Object.create(null);
    betsKeyCache = { raw: '', key: null };
    ['gh-token', 'b-token', 'search', 'slip-pin'].forEach(function (id) { $(id).value = ''; });
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
    state.profile = loadProfile();
    if (isAdmin) { prefillGitHub(); prefillBets(); resetForm(); }
    setView('live');
    startBets();
    startCouplesRefresh();
  }

  /* ---------- views ---------- */
  function setView(v) {
    if (v === 'admin' && state.role !== 'admin') v = 'live';
    state.view = v;
    Array.prototype.forEach.call(document.querySelectorAll('.tab'), function (t) {
      t.classList.toggle('is-active', t.getAttribute('data-view') === v);
    });
    $('book').hidden = !isBookView();
    $('ranking').hidden = v !== 'ranking';
    $('admin').hidden = v !== 'admin';
    $('slip').hidden = !isBookView();
    document.body.classList.toggle('view-admin', v === 'admin' || v === 'ranking');
    renderView();
  }
  function renderView() {
    if (!state.data) return;
    if (isBookView()) renderBook();
    else if (state.view === 'ranking') renderRanking();
    else if (state.view === 'admin') renderAdmin();
    renderSlip();
    renderMe();
    renderBetsStatus();
    if (state.role === 'admin') renderSyncState();
  }

  function renderBetsStatus() {
    var t, k = '';
    if (state.betsStatus === 'off') { t = state.role === 'admin' ? 'Betting is not set up yet. Connect bets storage in Admin.' : 'Betting is not set up yet. Ask the admin.'; k = 'warn'; }
    else if (state.betsStatus === 'ok') { t = 'Live pools. Odds move with every bet.'; k = 'ok'; }
    else if (state.betsStatus === 'error') { t = 'Bets unavailable: ' + state.betsError; k = 'error'; }
    else t = 'Loading bets…';
    $('bets-status').textContent = t;
    $('bets-status').className = 'bets-status ' + k;
  }

  function renderMe() {
    var p = state.profile, s = p && state.stats && state.stats.players[p.key];
    $('me-chip').hidden = !s;
    if (s) $('me-chip').textContent = s.name + ' · ' + fmtPts(s.balance);
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
    var cs = state.stats ? state.stats.couples[c.id] : null;
    var metaText = live
      ? 'Together since ' + fmtDate(c.since) + ' · ' + fmtDuration(since, today())
      : 'Lasted ' + fmtDuration(since, parseDate(c.endedOn)) + ' · ' + fmtDate(c.since) + ' to ' + fmtDate(c.endedOn);
    var badges = el('div', { class: 'badges' }, [
      c.marriedOn ? el('span', { class: 'status married', text: 'Married' }) : null,
      el('span', { class: 'status ' + (live ? 'live' : 'settled'), text: live ? 'Live' : 'Settled' })
    ]);
    var poolText = cs && cs.total ? fmtPts(cs.total) + ' bet · ' + cs.people + (cs.people === 1 ? ' person' : ' people') : 'No bets yet';
    var head = el('div', { class: 'card-head' }, [
      el('div', null, [
        el('div', { class: 'names' }, [c.a, el('span', { class: 'amp', text: '♥' }), c.b]),
        el('div', { class: 'meta', text: metaText }),
        c.note ? el('div', { class: 'note', text: c.note }) : null,
        el('div', { class: 'pool', text: poolText })
      ]),
      badges
    ]);

    var lines = [], mks = cs ? Object.keys(cs.markets).filter(function (mk) { return mk !== 'marry'; }) : [];
    var open = [], done = [];
    mks.forEach(function (mk) { (cs.markets[mk].winner ? done : open).push(mk); });
    open.sort(function (x, y) {
      var d = cs.markets[y].total - cs.markets[x].total;
      return d || (threshold(c, x) < threshold(c, y) ? -1 : 1);
    });
    done.sort(function (x, y) { return threshold(c, x) < threshold(c, y) ? -1 : 1; });
    var shownOpen = open.slice(0, MAX_OPEN_LINES);
    // Keep a selected line visible even when it is not in the top list.
    var sel = state.selection;
    if (sel && sel.id === c.id) {
      var smk = slipMk(sel);
      if (smk && smk !== 'marry' && open.indexOf(smk) >= MAX_OPEN_LINES) shownOpen.push(smk);
    }
    shownOpen.forEach(function (mk) { lines.push(renderLine(c, cs, mk, live)); });
    if (open.length > shownOpen.length) {
      lines.push(el('p', { class: 'muted small more', text: (open.length - shownOpen.length) + ' more lines. Use Make your own bet to pick any time.' }));
    }
    if (!open.length && live) lines.push(el('p', { class: 'muted small more', text: 'No time bets yet. Make the first one.' }));
    lines.push(renderLine(c, cs, 'marry', live));
    if (done.length) {
      var det = el('details', { class: 'settled-lines', open: state.openSettled[c.id] ? true : null }, [
        el('summary', { text: 'Decided lines (' + done.length + ')' }),
        el('div', null, done.map(function (mk) { return renderLine(c, cs, mk, live); }))
      ]);
      det.addEventListener('toggle', function () { if (det.open) state.openSettled[c.id] = 1; else delete state.openSettled[c.id]; });
      if (!live) lines = done.map(function (mk) { return renderLine(c, cs, mk, live); });
      else lines.push(det);
    }
    if (!live) {
      // settled couples: only show lines people actually bet on
      if (!done.length) lines = [];
      var mm = cs && cs.markets.marry;
      if (mm && mm.list.length) lines.push(renderLine(c, cs, 'marry', live));
      if (!lines.length) lines.push(el('p', { class: 'muted small more', text: 'Nobody bet on this couple.' }));
    }
    var foot = live ? el('button', {
      type: 'button', class: 'btn btn-secondary btn-block make-bet',
      text: '+ Make your own bet',
      onclick: function () { select({ id: c.id, type: 'dur', side: 'over', n: '', u: 'm' }, true); }
    }) : null;
    var body = el('div', { class: 'lines' }, lines.concat([foot]));
    return el('article', { class: 'card' }, [head, body, renderBetsList(c, cs)]);
  }

  function renderLine(c, cs, mk, live) {
    var m = marketView(cs, c, mk);
    var open = live && canBetNow(c, mk);
    var title = mk === 'marry' ? 'Will they get married?' : mkLabel(mk);
    var sub;
    if (mk === 'marry') sub = c.marriedOn ? 'Married on ' + fmtDate(c.marriedOn) : (m.total ? fmtPts(m.total) + ' on this line' : '');
    else sub = 'Line: ' + fmtDate(threshold(c, mk)) + (m.total ? ' · ' + fmtPts(m.total) : '');
    return el('div', { class: 'line' }, [
      el('div', { class: 'line-head' }, [el('span', { class: 'line-title', text: title }), el('span', { class: 'line-sub', text: sub })]),
      el('div', { class: 'line-sides' }, sidesOf(mk).map(function (s) { return sideBtn(c, m, mk, s, open); }))
    ]);
  }

  function sideBtn(c, m, mk, s, open) {
    var pool = m.pools[s], total = m.total, pct = total ? pool / total : 0;
    var cls = 'odds-btn', value;
    var sub = total ? fmtPct(pct) + ' · ' + fmtPts(pool) : '0 pts';
    if (m.winner) {
      if (m.refundedAll) { cls += ' closed'; value = 'Refunded'; }
      else if (s === m.winner) { cls += ' won'; value = m.pools[s] ? 'Won ×' + fmtOdds(m.ratio) : 'Won'; }
      else { cls += ' lost'; value = 'Lost'; }
    } else if (!open) { cls += ' closed'; value = 'Closed'; }
    else value = pool ? fmtOdds(total / pool) : 'New';
    var sel = state.selection;
    var selected = !!(sel && sel.id === c.id && slipMk(sel) === mk && sel.side === s);
    var meter = el('span', { class: 'meter' });
    meter.style.width = (pct * 100).toFixed(1) + '%';
    var p = parseMk(mk);
    return el('button', {
      type: 'button', class: cls, disabled: !open,
      'aria-pressed': open ? String(selected) : null,
      'aria-label': coupleName(c) + ', ' + betLabel(mk, s) + ', ' + (open ? (pool ? 'odds ' + value : 'no bets yet') : value) + ', ' + sub,
      onclick: open ? function () {
        select(p.type === 'marry' ? { id: c.id, type: 'marry', side: s } : { id: c.id, type: 'dur', side: s, n: String(p.n), u: p.u }, true);
      } : null
    }, [
      el('span', { class: 'm-label', text: sideShort(mk, s) }),
      el('span', { class: 'm-odds', text: value }),
      el('span', { class: 'm-pct', text: sub }),
      meter
    ]);
  }

  function renderBetsList(c, cs) {
    if (!cs || !cs.list.length) return null;
    var rows = cs.list.slice().reverse();
    var shown = rows.slice(0, 40);
    var isAdmin = state.role === 'admin';
    var me = state.profile && state.profile.key;
    var items = shown.map(function (r) {
      var b = r.bet, pl = state.stats.players[b.k];
      var res = r.status === 'won' ? '+' + fmtPts(r.net) : r.status === 'lost' ? MINUS + fmtPts(-r.net) : r.status === 'refunded' ? 'refunded' : 'open';
      return el('li', { class: 'bet-row' + (b.k === me ? ' mine' : '') }, [
        el('span', { class: 'bet-who', text: pl ? pl.name : '?' }),
        el('span', { class: 'bet-what', text: betLabel(b.m, b.s) + ' · ' + fmtPts(b.p) }),
        el('span', { class: 'bet-res ' + r.status, text: res }),
        el('span', { class: 'bet-when', text: fmtWhen(b.t) }),
        isAdmin ? el('button', { type: 'button', class: 'icon-btn small', title: 'Delete this bet', 'aria-label': 'Delete bet of ' + (pl ? pl.name : ''), text: '×', onclick: function () { voidBet(b.id); } }) : null
      ]);
    });
    if (rows.length > shown.length) items.push(el('li', { class: 'muted small', text: 'and ' + (rows.length - shown.length) + ' older bets' }));
    var det = el('details', { class: 'bets', open: state.openBets[c.id] ? true : null }, [
      el('summary', { text: cs.list.length + (cs.list.length === 1 ? ' bet' : ' bets') }),
      el('ul', null, items)
    ]);
    det.addEventListener('toggle', function () { if (det.open) state.openBets[c.id] = 1; else delete state.openBets[c.id]; });
    return det;
  }

  function renderRanking() {
    var box = $('rank-list');
    box.textContent = '';
    $('rank-note').textContent = 'Everyone starts with ' + fmtPts(state.data.settings.startPoints) +
      '. On each line, the winners split all the points bet on it, in proportion to what they bet.';
    if (state.betsStatus !== 'ok' || !state.stats) {
      box.appendChild(el('div', { class: 'empty', text: $('bets-status').textContent || 'Loading bets…' }));
      return;
    }
    var list = Object.keys(state.stats.players).map(function (k) { return state.stats.players[k]; })
      .sort(function (x, y) { return y.balance - x.balance || (x.name < y.name ? -1 : 1); });
    if (!list.length) { box.appendChild(el('div', { class: 'empty', text: 'Nobody has bet yet.' })); return; }
    var me = state.profile && state.profile.key, isAdmin = state.role === 'admin';
    list.forEach(function (p, i) {
      box.appendChild(el('div', { class: 'rank-row' + (p.key === me ? ' me' : '') }, [
        el('span', { class: 'rank-pos', text: String(i + 1) }),
        el('div', { class: 'rank-main' }, [
          el('div', { class: 'names', text: p.name + (p.key === me ? ' (you)' : '') }),
          el('div', { class: 'meta', text: 'In play ' + fmtPts(p.locked) + ' · ' + p.won + ' won · ' + p.lost + ' lost' })
        ]),
        el('span', { class: 'rank-bal', text: fmtPts(p.balance) }),
        isAdmin ? el('button', { type: 'button', class: 'btn btn-ghost btn-small', text: 'Reset PIN', onclick: function () { resetPin(p.key); } }) : null
      ]));
    });
  }

  /* ---------- bet slip ---------- */
  function slipMk(sel) {
    if (!sel) return '';
    if (sel.type === 'marry') return 'marry';
    var n = Number(sel.n);
    if (!Number.isInteger(n) || n < 1 || !UNITS[sel.u] || n > UNITS[sel.u].max) return '';
    return n + sel.u;
  }

  function select(sel, fromCard) {
    var s = state.selection;
    if (fromCard && s && sel.type !== undefined && s.id === sel.id && slipMk(s) === slipMk(sel) && s.side === sel.side && slipMk(sel)) {
      state.selection = null; // tapping the selected button again clears it
    } else {
      state.selection = sel;
    }
    setMsg('slip-msg', '');
    syncSlipInputs();
    if (isBookView()) renderBook();
    renderSlip();
    if (state.selection && !state.selection.n && state.selection.type === 'dur') {
      setTimeout(function () { try { $('slip-n').focus(); } catch (e) { /* ignore */ } }, 0);
    }
  }
  function syncSlipInputs() {
    var s = state.selection;
    if (!s) return;
    if (s.type === 'dur') { $('slip-n').value = s.n || ''; $('slip-u').value = s.u || 'm'; }
  }
  function readSlipInputs() {
    var s = state.selection;
    if (!s || s.type !== 'dur') return;
    s.n = $('slip-n').value.trim();
    s.u = $('slip-u').value;
  }
  function setSeg(id, value) {
    Array.prototype.forEach.call($(id).querySelectorAll('button'), function (b) {
      b.setAttribute('aria-pressed', String(b.getAttribute('data-v') === value));
    });
  }

  function renderSlip() {
    var sel = state.selection, c = sel && state.data && findCouple(sel.id);
    if (sel && (!c || c.status !== 'active')) { state.selection = sel = c = null; }
    document.body.classList.toggle('has-slip', !!sel && isBookView());
    $('slip-empty').hidden = !!sel;
    $('slip-body').hidden = !sel;
    if (!sel) return;

    $('slip-couple').textContent = coupleName(c);
    setSeg('slip-type', sel.type);
    $('slip-dur').hidden = sel.type !== 'dur';
    $('slip-marry').hidden = sel.type !== 'marry';
    setSeg(sel.type === 'dur' ? 'slip-side' : 'slip-yn', sel.side);

    var mk = slipMk(sel), problem = '';
    var cs = state.stats && state.stats.couples[c.id];
    if (!mk) {
      var u = UNITS[sel.u] || UNITS.m;
      problem = sel.n === '' ? 'Enter how many ' + u.many + '.' : 'Enter a whole number from 1 to ' + u.max + '.';
      $('slip-explain').textContent = '';
    } else {
      if (mk === 'marry') {
        $('slip-explain').textContent = sel.side === 'yes' ? 'Wins if they get married.' : 'Wins if they break up without getting married.';
        if (c.marriedOn) problem = 'They are already married.';
      } else {
        var th = threshold(c, mk);
        $('slip-explain').textContent = sel.side === 'over'
          ? 'Wins if they are still together after ' + fmtDate(th) + '.'
          : 'Wins if they break up on or before ' + fmtDate(th) + '.';
        if (!canBetNow(c, mk)) problem = 'They have already been together that long. Pick a longer time.';
      }
    }
    var m = mk ? marketView(cs, c, mk) : null;
    $('slip-bucket').textContent = mk ? betLabel(mk, sel.side) : 'Your bet';
    var pool = m ? m.pools[sel.side] : 0, total = m ? m.total : 0;
    $('slip-odds').textContent = !mk ? '' : pool ? fmtOdds(total / pool) : 'New';
    $('slip-pool').textContent = !mk ? '' : total
      ? fmtPts(pool) + ' of ' + fmtPts(total) + ' on this side (' + fmtPct(pool / total) + ').'
      : 'Nobody has bet on this line yet. If nobody takes the other side, you just get your points back.';

    var ready = state.betsStatus === 'ok' && !!state.stats;
    var stateMsg = state.betsStatus === 'off' ? 'Betting is not set up yet.'
      : state.betsStatus === 'error' ? 'Bets unavailable: ' + state.betsError
      : !ready ? 'Loading bets…' : '';
    $('slip-state').textContent = stateMsg;
    $('slip-state').hidden = !stateMsg;
    $('slip-form').hidden = !ready;
    if (!ready) return;

    var me = state.profile && state.stats.players[state.profile.key];
    $('slip-profile').hidden = !!me;
    $('slip-me').hidden = !me;
    var mine = 0;
    if (me) {
      $('slip-me-name').textContent = me.name;
      $('slip-me-bal').textContent = fmtPts(me.balance) + ' available';
      var other = mk ? sideOfPlayer(cs, mk, me.key) : '';
      if (!problem && other && other !== sel.side) problem = 'You already backed ' + betLabel(mk, other) + '. You can only add points to that side.';
      if (!problem && me.balance < 1) problem = 'You have no points left.';
      if (m) m.list.forEach(function (r) { if (r.bet.k === me.key && r.bet.s === sel.side && r.status !== 'refunded') mine += r.bet.p; });
    }
    $('slip-mine').textContent = mine ? 'You have ' + fmtPts(mine) + ' on this side.' : '';
    $('slip-mine').hidden = !mine;
    $('slip-rule').textContent = problem;
    $('slip-rule').hidden = !problem;
    $('slip-go').disabled = state.placing || !!problem;
    $('slip-go').textContent = state.placing ? 'Placing…' : 'Place bet';
    updateReturn();
  }

  function updateReturn() {
    var sel = state.selection, c = sel && findCouple(sel.id), mk = slipMk(sel);
    var stake = Number($('slip-stake').value);
    if (!c || !mk || !Number.isInteger(stake) || stake < 1) {
      $('slip-return').textContent = '0 pts';
      $('slip-after').textContent = '';
      return;
    }
    var m = marketView(state.stats && state.stats.couples[c.id], c, mk);
    var pool = m.pools[sel.side], total = m.total;
    $('slip-return').textContent = fmtPts(Math.floor(stake * (total + stake) / (pool + stake)));
    $('slip-after').textContent = 'Odds after your bet: ' + fmtOdds((total + stake) / (pool + stake)) + '. They keep moving as others bet.';
  }

  async function placeBet(ev) {
    if (ev) ev.preventDefault();
    if (state.placing) return;
    var sel = state.selection, c0 = sel && findCouple(sel.id), mk = slipMk(sel);
    if (!c0 || !mk) return;
    var side = sel.side, stake = Number($('slip-stake').value), prof = state.profile;
    var nameIn = '', pinIn = '';
    if (!prof) {
      nameIn = cleanText($('slip-name').value, 24);
      pinIn = $('slip-pin').value.trim();
      if (!nameIn) { setMsg('slip-msg', 'Enter your name.', 'error'); return; }
      if (!/^\d{4,8}$/.test(pinIn)) { setMsg('slip-msg', 'Your PIN must be 4 to 8 digits.', 'error'); return; }
    }
    if (!Number.isInteger(stake) || stake < 1) { setMsg('slip-msg', 'Enter a whole number of points.', 'error'); return; }
    state.placing = true;
    setMsg('slip-msg', '');
    renderSlip();
    var session = state.session, newProfile = null;
    try {
      await betsTxn(async function (latest) {
        var c = findCouple(c0.id);
        if (!c || !canBetNow(c, mk)) throw userErr('Betting on this line is closed.');
        var key, player;
        if (prof) {
          key = prof.key;
          player = latest.players[key];
          if (!player || !player.hash || player.hash !== prof.hash) throw userErr('Your player PIN was reset. Enter your name and a PIN again.');
        } else {
          key = playerKey(nameIn);
          player = latest.players[key];
          if (player && player.hash) {
            if ((await pinHash(pinIn, player.salt)) !== player.hash) throw userErr('Wrong PIN for ' + player.name + '. If this is not you, pick another name.');
            newProfile = { key: key, name: player.name, hash: player.hash };
          } else {
            var salt = randomB64(16), hash = await pinHash(pinIn, salt);
            latest.players[key] = { name: player ? player.name : nameIn, salt: salt, hash: hash };
            newProfile = { key: key, name: latest.players[key].name, hash: hash };
          }
        }
        var S = computeStats(state.data, latest);
        var me = S.players[key];
        if (stake > me.balance) throw userErr('You only have ' + fmtPts(Math.max(0, me.balance)) + ' available.');
        var other = sideOfPlayer(S.couples[c.id], mk, key);
        if (other && other !== side) throw userErr('You already backed ' + betLabel(mk, other) + '. You can only add points to that side.');
        latest.bets.push({ id: newId(), c: c.id, m: mk, s: side, p: stake, k: key, t: Date.now() });
        return latest;
      });
      if (session !== state.session) return;
      if (newProfile) { state.profile = newProfile; saveProfile(newProfile); $('slip-pin').value = ''; }
      setMsg('slip-msg', 'Bet placed: ' + fmtPts(stake) + ' on ' + betLabel(mk, side) + '.', 'ok');
    } catch (e) {
      if (session !== state.session) return;
      if (/PIN was reset/.test(e.message)) forgetProfile();
      setMsg('slip-msg', e.user ? e.message : 'Could not place the bet: ' + e.message, 'error');
    } finally {
      if (session === state.session) {
        state.placing = false;
        renderView();
      }
    }
  }

  /* ---------- bets engine (private bets repository) ---------- */
  var betsKeyCache = { raw: '', key: null };
  async function betsKey(g) {
    if (betsKeyCache.raw !== g.key) betsKeyCache = { raw: g.key, key: await importAes(g.key) };
    return betsKeyCache.key;
  }
  function connId(g) { return g ? g.owner + '/' + g.repo + '@' + g.branch + '#' + g.key + '|' + g.token : ''; }

  function startBets() {
    state.betsLoop++;
    clearTimeout(state.betsTimer);
    state.betsWaiting = false;
    tickBets(state.betsLoop);
  }
  function stopBets() {
    state.betsLoop++;
    clearTimeout(state.betsTimer);
    state.betsTimer = null;
    state.betsWaiting = false;
  }
  async function tickBets(loop) {
    var delay = await pollBets();
    if (loop !== state.betsLoop) return;
    state.betsTimer = setTimeout(function () {
      if (loop !== state.betsLoop) return;
      if (document.hidden) { state.betsWaiting = true; return; }
      tickBets(loop);
    }, delay);
  }

  async function contentText(g, file, j) {
    if (j.encoding === 'base64' && typeof j.content === 'string') return DEC.decode(b64dec(j.content.replace(/\s/g, '')));
    // files over 1 MB come without content: fetch the raw file
    var r = await ghFetch(ghUrl(g, file) + '?ref=' + encodeURIComponent(g.branch),
      { headers: Object.assign(ghHeaders(g), { 'Accept': 'application/vnd.github.raw' }) });
    if (!r.ok) throw new Error(ghError(r.status, 'bets', r));
    return r.text();
  }
  async function decryptBetsText(g, text) {
    try { return normalizeBets(await decryptWith(await betsKey(g), AAD_BETS, JSON.parse(text))); }
    catch (e) { throw new Error('the bets file could not be decrypted. It was made with a different bets key.'); }
  }

  // Returns the delay before the next poll.
  async function pollBets() {
    var g = state.data && state.data.settings.bets, session = state.session;
    if (!state.data) return POLL_MS;
    if (!g) {
      state.betsFor = '';
      state.bets = null; state.stats = null; state.betsStatus = 'off';
      renderView();
      return POLL_MS;
    }
    var id = connId(g);
    if (state.betsFor !== id) {
      state.betsFor = id; state.betsEtag = null; state.bets = null; state.stats = null; state.betsStatus = 'loading';
      renderView();
    }
    try {
      var h = ghHeaders(g);
      if (state.betsEtag) h['If-None-Match'] = state.betsEtag;
      var r = await ghFetch(ghUrl(g, BETS_FILE) + '?ref=' + encodeURIComponent(g.branch), { headers: h });
      if (session !== state.session || state.betsFor !== id) return POLL_MS;
      if (r.status === 304) {
        if (state.betsStatus !== 'ok') { state.betsStatus = 'ok'; state.betsError = ''; renderView(); }
      } else if (r.status === 404) {
        var repo = await ghFetch(repoUrl(g), { headers: ghHeaders(g) });
        if (!repo.ok) throw new Error(ghError(repo.status, 'bets', repo));
        if (session !== state.session || state.betsFor !== id) return POLL_MS;
        applyBets(emptyBets(), null);
      } else if (!r.ok) {
        throw new Error(ghError(r.status, 'bets', r));
      } else {
        var j = await r.json();
        var d = await decryptBetsText(g, await contentText(g, BETS_FILE, j));
        if (session !== state.session || state.betsFor !== id) return POLL_MS;
        applyBets(d, r.headers.get('ETag'));
      }
      return POLL_MS;
    } catch (e) {
      if (session !== state.session || state.betsFor !== id) return POLL_MS;
      state.betsStatus = 'error';
      state.betsError = e.message || 'unknown error.';
      renderView();
      return /limiting/.test(state.betsError) ? BACKOFF_MS : ERROR_MS;
    }
  }

  function applyBets(d, etag) {
    state.bets = d;
    state.betsEtag = etag || null;
    state.betsStatus = 'ok';
    state.betsError = '';
    state.stats = computeStats(state.data, d);
    checkProfile();
    renderView();
  }

  // Read the newest bets file, change it, write it back. Retries when someone else wrote in between.
  async function betsTxn(mutate) {
    var g = state.data.settings.bets;
    if (!g) throw userErr('Betting is not set up yet.');
    var session = state.session, id = connId(g);
    for (var i = 0; i < 6; i++) {
      var cur = await ghGet(g, BETS_FILE, 'bets');
      var latest = cur.text ? await decryptBetsText(g, cur.text) : emptyBets();
      var next = await mutate(latest);
      var text = await encryptWith(await betsKey(g), AAD_BETS, next);
      var r = await ghPut(g, BETS_FILE, text, cur.sha, 'Update bets', 'bets');
      if (session !== state.session) throw userErr('You logged out.');
      if (r !== 'conflict') {
        if (state.betsFor === id) applyBets(normalizeBets(JSON.parse(JSON.stringify(next))), null);
        return;
      }
      await sleep(200 + Math.random() * 800);
    }
    throw userErr('Lots of bets at the same moment. Try again.');
  }

  async function voidBet(id) {
    var r = state.stats && state.stats.bets[id];
    if (!r) return;
    var pl = state.stats.players[r.bet.k];
    if (!confirm('Delete the bet of ' + (pl ? pl.name : '?') + ' (' + betLabel(r.bet.m, r.bet.s) + ', ' + fmtPts(r.bet.p) + ')? The points go back.')) return;
    try {
      await betsTxn(function (latest) {
        latest.bets = latest.bets.filter(function (b) { return b.id !== id; });
        return latest;
      });
    } catch (e) { alert(e.user ? e.message : 'Could not delete the bet: ' + e.message); }
  }

  async function resetPin(key) {
    var pl = state.stats && state.stats.players[key];
    if (!pl || !confirm('Reset the PIN of ' + pl.name + '? Next time they bet they choose a new PIN. Their points and bets stay.')) return;
    try {
      await betsTxn(function (latest) {
        if (latest.players[key]) { latest.players[key].hash = ''; latest.players[key].salt = ''; }
        return latest;
      });
    } catch (e) { alert(e.user ? e.message : 'Could not reset the PIN: ' + e.message); }
  }

  /* ---------- couples refresh for players ---------- */
  function startCouplesRefresh() {
    clearInterval(state.couplesTimer);
    state.couplesTimer = null;
    if (state.role === 'admin') return; // admins work on their own copy and publish it
    state.couplesTimer = setInterval(refreshCouples, COUPLES_MS);
  }
  async function refreshCouples() {
    if (document.hidden || !state.key) return;
    var session = state.session;
    try {
      var f = await fetchJson('couples.enc.json');
      if (session !== state.session || !f || f.ct === state.encFile.ct) return;
      var d = normalizeData(await decryptWith(state.key, AAD_DATA, f));
      if (session !== state.session) return;
      state.encFile = f;
      state.data = d;
      onDataChanged();
    } catch (e) { /* keep what we have; try again next minute */ }
  }

  function onDataChanged() {
    if (state.bets) state.stats = computeStats(state.data, state.bets);
    var id = connId(state.data.settings.bets);
    if (id !== state.betsFor) startBets();
    renderView();
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
        d.settings = Object.assign({}, d.settings, op.s);
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
    onDataChanged();
  }

  function renderSyncState() {
    var n = state.pending.length;
    $('dirty-dot').hidden = !n;
    var text, kind;
    if (state.publishing) { text = 'Publishing…'; kind = 'busy'; }
    else if (state.syncError) { text = 'Not published: ' + state.syncError; kind = 'error'; }
    else if (n && !state.gh) { text = n + (n === 1 ? ' change is' : ' changes are') + ' only in this tab. Connect GitHub once (bottom of this page) to publish automatically.'; kind = 'error'; }
    else if (!state.gh) { text = 'GitHub is not connected yet, so changes cannot be published. See the bottom of this page.'; kind = 'warn'; }
    else if (state.lastPublished) { text = 'All changes published. Players see them within about 1 to 2 minutes.'; kind = 'ok'; }
    else { text = 'Connected. Every change you make is published automatically.'; kind = 'ok'; }
    $('sync-text').textContent = text;
    $('sync-bar').className = 'sync-bar ' + kind;
    $('sync-retry').hidden = !(state.syncError && state.gh && n);
    $('gh-connected').hidden = !state.gh || state.ghEditing;
    $('gh-form').hidden = !!state.gh && !state.ghEditing;
    $('gh-cancel').hidden = !state.ghEditing;
    if (state.gh) $('gh-where').textContent = state.gh.owner + '/' + state.gh.repo + ' (branch ' + state.gh.branch + (state.gh.dir ? ', folder ' + state.gh.dir : '') + ')';
    if (state.ghNotice && !state.gh) setMsg('gh-msg', state.ghNotice, 'error');
  }

  function renderBetsConn() {
    var b = state.data.settings.bets;
    $('b-connected').hidden = !b || state.betsEditing;
    $('b-form').hidden = !!b && !state.betsEditing;
    $('b-cancel').hidden = !state.betsEditing;
    if (b) $('b-where').textContent = b.owner + '/' + b.repo + ' (branch ' + b.branch + ')';
  }

  function renderAdmin() {
    var box = $('admin-list');
    box.textContent = '';
    if (!state.data.couples.length) box.appendChild(el('p', { class: 'muted', text: 'No couples yet.' }));
    state.data.couples.slice().sort(function (x, y) { return x.since < y.since ? 1 : x.since > y.since ? -1 : 0; })
      .forEach(function (c) {
        var cs = state.stats && state.stats.couples[c.id];
        var info = c.status === 'active' ? 'Live since ' + fmtDate(c.since) : 'Broke up on ' + fmtDate(c.endedOn);
        if (c.marriedOn) info += ' · married';
        if (cs && cs.list.length) info += ' · ' + cs.list.length + (cs.list.length === 1 ? ' bet' : ' bets');
        box.appendChild(el('div', { class: 'admin-item' }, [
          el('div', null, [el('div', { class: 'names', text: coupleName(c) }), el('div', { class: 'meta', text: info })]),
          el('div', { class: 'actions' }, [
            el('button', { type: 'button', class: 'btn btn-ghost btn-small', text: 'Edit', onclick: function () { editCouple(c.id); } }),
            el('button', { type: 'button', class: 'btn btn-danger', text: 'Delete', onclick: function () { deleteCouple(c.id); } })
          ])
        ]));
      });
    if (document.activeElement !== $('s-start')) $('s-start').value = String(state.data.settings.startPoints);
    renderBetsConn();
    renderSyncState();
  }

  function resetForm() {
    $('couple-form').reset();
    $('f-id').value = '';
    $('f-since').max = toISO(today());
    $('f-ended').max = toISO(today());
    $('f-married-on').max = toISO(today());
    $('f-ended-wrap').hidden = true;
    $('f-married-wrap').hidden = true;
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
    $('f-married').checked = !!c.marriedOn;
    $('f-married-on').value = c.marriedOn;
    $('f-married-wrap').hidden = !c.marriedOn;
    $('f-note').value = c.note;
    $('form-title').textContent = 'Edit couple';
    $('f-save').textContent = 'Save changes';
    $('f-cancel').hidden = false;
    setMsg('form-msg', '');
    $('couple-form').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function deleteCouple(id) {
    var c = findCouple(id);
    if (!c) return;
    var cs = state.stats && state.stats.couples[id], n = cs ? cs.list.length : 0;
    if (!confirm('Delete ' + coupleName(c) + '?' + (n ? ' Their ' + n + (n === 1 ? ' bet is' : ' bets are') + ' cancelled and the points go back.' : ''))) return;
    if (state.selection && state.selection.id === id) state.selection = null;
    if ($('f-id').value === id) resetForm();
    commit({ t: 'delete', id: id });
  }

  function saveCouple(ev) {
    ev.preventDefault();
    var todayISO = toISO(today());
    var a = cleanText($('f-a').value, 60), b = cleanText($('f-b').value, 60);
    var since = $('f-since').value, status = $('f-status').value, ended = $('f-ended').value;
    var married = $('f-married').checked, marriedOn = $('f-married-on').value;
    var err = !a || !b ? 'Enter both names.'
      : !isISODate(since) ? 'Enter the date they got together.'
      : since > todayISO ? 'The start date cannot be in the future.'
      : status === 'ended' && !isISODate(ended) ? 'Enter the break-up date.'
      : status === 'ended' && ended < since ? 'The break-up date cannot be before the start date.'
      : status === 'ended' && ended > todayISO ? 'The break-up date cannot be in the future.'
      : married && !isISODate(marriedOn) ? 'Enter the wedding date.'
      : married && marriedOn < since ? 'The wedding date cannot be before the start date.'
      : married && marriedOn > todayISO ? 'The wedding date cannot be in the future.'
      : married && status === 'ended' && marriedOn > ended ? 'The wedding date cannot be after the break-up date.'
      : '';
    if (err) { setMsg('form-msg', err, 'error'); return; }
    var id = $('f-id').value;
    var couple = normCouple({ id: id || newId(), a: a, b: b, since: since, note: $('f-note').value,
      status: status, endedOn: status === 'ended' ? ended : '', marriedOn: married ? marriedOn : '' });
    var done = (id ? 'Saved ' : 'Added ') + coupleName(couple) + '.';
    resetForm();
    commit({ t: 'upsert', c: couple });
    setMsg('form-msg', done, 'ok');
  }

  function saveSettings(ev) {
    ev.preventDefault();
    var n = validStart($('s-start').value);
    if (n === null) { setMsg('settings-msg', 'Starting points must be a whole number from 10 to 1,000,000.', 'error'); return; }
    commit({ t: 'settings', s: { startPoints: n } });
    setMsg('settings-msg', 'Saved. Every player now starts with ' + fmtPts(n) + '.', 'ok');
  }

  function siteRepoGuess() {
    if (state.gh) return { owner: state.gh.owner, repo: state.gh.repo };
    var m = location.hostname.match(/^([a-z0-9-]+)\.github\.io$/i);
    if (!m) return null;
    var seg = location.pathname.split('/').filter(Boolean);
    if (seg.length && /\.html?$/i.test(seg[seg.length - 1])) seg.pop();
    return { owner: m[1], repo: seg[0] || location.hostname };
  }

  function prefillBets() {
    var b = state.data.settings.bets, site = siteRepoGuess();
    $('b-owner').value = b ? b.owner : (site ? site.owner : '');
    $('b-repo').value = b ? b.repo : (site ? site.repo + '-bets' : 'break365-bets');
    $('b-branch').value = b ? b.branch : 'main';
    $('b-token').value = '';
  }

  async function saveBetsConn(ev) {
    ev.preventDefault();
    var g = validGh({ owner: $('b-owner').value.trim(), repo: $('b-repo').value.trim(), branch: $('b-branch').value.trim() || 'main', dir: '', token: $('b-token').value.trim() });
    if (!g) { setMsg('b-msg', 'Check the username, repository, branch and token.', 'error'); return; }
    var site = siteRepoGuess();
    if (site && site.owner.toLowerCase() === g.owner.toLowerCase() && site.repo.toLowerCase() === g.repo.toLowerCase()) {
      setMsg('b-msg', 'Use a separate private repository for bets, not the site repository. Players\' browsers use this token.', 'error');
      return;
    }
    if (state.gh && state.gh.token === g.token) {
      setMsg('b-msg', 'Use a different token from the admin one: players\' browsers use this token, so it must only reach the bets repository.', 'error');
      return;
    }
    var session = state.session;
    $('b-btn').disabled = true;
    setMsg('b-msg', 'Checking the repository…');
    try {
      var r = await ghFetch(repoUrl(g), { headers: ghHeaders(g) });
      if (!r.ok) throw new Error(ghError(r.status, 'bets', r));
      var info = await r.json();
      if (info.private !== true) throw userErr('That repository is public. Make it private first (repository Settings > General > Danger Zone > Change visibility).');
      var old = state.data.settings.bets;
      g.key = old && old.key ? old.key : randomB64(32);
      var cur = await ghGet(g, BETS_FILE, 'bets');
      if (cur.text) {
        try { await decryptWith(await importAes(g.key), AAD_BETS, JSON.parse(cur.text)); }
        catch (e) { throw userErr('That repository already has a bets file made with a different key. Pick an empty private repository.'); }
      }
      if (session !== state.session) return;
      state.betsEditing = false;
      $('b-token').value = '';
      commit({ t: 'settings', s: { bets: g } });
      setMsg('b-msg', 'Bets storage connected. Players can bet now (after the change is published).', 'ok');
    } catch (e) {
      if (session !== state.session) return;
      setMsg('b-msg', e.user ? e.message : 'Could not connect: ' + e.message, 'error');
    } finally {
      $('b-btn').disabled = false;
    }
  }

  /* ---------- GitHub ---------- */
  function ghPath(g, file) { return (g.dir ? g.dir + '/' : '') + file; }
  function repoUrl(g) { return 'https://api.github.com/repos/' + encodeURIComponent(g.owner) + '/' + encodeURIComponent(g.repo); }
  function ghUrl(g, file) { return repoUrl(g) + '/contents/' + ghPath(g, file).split('/').map(encodeURIComponent).join('/'); }
  function ghHeaders(g) {
    return { 'Accept': 'application/vnd.github+json', 'Authorization': 'Bearer ' + g.token, 'X-GitHub-Api-Version': '2022-11-28' };
  }
  function ghError(status, ctx, res) {
    var bets = ctx === 'bets';
    var limited = res && res.headers && res.headers.get('x-ratelimit-remaining') === '0';
    if (status === 429 || (status === 403 && limited)) return 'GitHub is limiting requests right now. Trying again in a minute.';
    if (status === 401) return bets
      ? 'the bets storage token has expired or was revoked. The admin needs to update it in Admin > Bets storage.'
      : 'the GitHub connection has expired or was revoked. The site owner needs to connect GitHub again (bottom of the Admin page).';
    if (status === 403) return bets
      ? 'GitHub denied access. The bets token needs Contents: Read and write on the bets repository.'
      : 'GitHub denied access. The token needs Contents: Read and write on this repository.';
    if (status === 404) return bets
      ? 'the bets repository was not found, or the token cannot access it.'
      : 'GitHub could not find the repository, branch or file. Check the connection details.';
    if (status === 422) return 'GitHub refused the update. Check the branch.';
    return 'GitHub returned an error (' + status + '). Try again in a moment.';
  }
  async function ghFetch(url, opts) {
    try { return await fetch(url, Object.assign({ cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer' }, opts)); }
    catch (e) { throw new Error('could not reach GitHub. Check your internet connection.'); }
  }
  // -> { sha, text } ; { sha: null, text: null } when the file does not exist
  async function ghGet(g, file, ctx) {
    var r = await ghFetch(ghUrl(g, file) + '?ref=' + encodeURIComponent(g.branch), { headers: ghHeaders(g) });
    if (r.status === 404) return { sha: null, text: null };
    if (!r.ok) throw new Error(ghError(r.status, ctx, r));
    var j = await r.json();
    return { sha: j.sha, text: await contentText(g, file, j) };
  }
  // -> { sha } of the new file, or 'conflict' when someone else changed it in the meantime
  async function ghPut(g, file, text, sha, message, ctx) {
    var body = { message: message, content: b64enc(ENC.encode(text)), branch: g.branch };
    if (sha) body.sha = sha;
    var r = await ghFetch(ghUrl(g, file), {
      method: 'PUT', headers: Object.assign({ 'Content-Type': 'application/json' }, ghHeaders(g)), body: JSON.stringify(body)
    });
    if (r.status === 409 || r.status === 422) return 'conflict';
    if (!r.ok) throw new Error(ghError(r.status, ctx, r));
    var j = null;
    try { j = await r.json(); } catch (e) { /* no body */ }
    return { sha: j && j.content ? j.content.sha : null };
  }

  async function readRemoteData(g) {
    var cur = await ghGet(g, 'couples.enc.json', 'site');
    var data = normalizeData(null);
    if (cur.text) {
      try { data = normalizeData(await decryptWith(state.key, AAD_DATA, JSON.parse(cur.text))); }
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
      onDataChanged();
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
          var ok = await ghPut(state.gh, 'couples.enc.json', await encryptWith(state.key, AAD_DATA, next), r.sha, 'Update data', 'site');
          if (session !== state.session) return;
          if (ok !== 'conflict') merged = next;
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
        onDataChanged();
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
    var b = state.data.settings.bets;
    if (b && b.token === g.token) { setMsg('gh-msg', 'Use a different token from the bets one.', 'error'); return; }
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
      var cur = await ghGet(via, 'keyring.json', 'site');
      if (!cur.text) throw new Error('keyring.json was not found there. Check the repository, branch and folder.');
      var kr = JSON.parse(cur.text), mine = state.keyring.roles.admin;
      if (!kr.roles || !kr.roles.admin || kr.roles.admin.salt !== mine.salt || kr.roles.admin.wrapped !== mine.wrapped) {
        throw new Error('the passwords in that repository are different from this page. Reload the page and try again.');
      }
      if (g) kr.roles.admin.secrets = await encryptSecrets(state.adminKek, g);
      else delete kr.roles.admin.secrets;
      var ok = await ghPut(via, 'keyring.json', JSON.stringify(kr, null, 2) + '\n', cur.sha, 'Update keyring', 'site');
      if (ok === 'conflict') throw new Error('keyring.json changed while saving. Try again.');
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
      setMsg('gh-msg', 'Could not save: ' + (e.message || 'unknown error.'), 'error');
    } finally {
      $('gh-btn').disabled = false;
    }
  }

  function download() {
    return encryptWith(state.key, AAD_DATA, state.data).then(function (content) {
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
  $('me-chip').addEventListener('click', function () { setView('ranking'); });
  Array.prototype.forEach.call(document.querySelectorAll('.tab'), function (t) {
    t.addEventListener('click', function () { setView(t.getAttribute('data-view')); });
  });
  $('search').addEventListener('input', function () { state.query = this.value.trim(); renderBook(); });

  $('slip-close').addEventListener('click', function () { state.selection = null; renderBook(); renderSlip(); });
  $('slip-type').addEventListener('click', function (e) {
    var b = e.target.closest('button');
    if (!b || !state.selection) return;
    var t = b.getAttribute('data-v');
    if (t === state.selection.type) return;
    state.selection = t === 'marry'
      ? { id: state.selection.id, type: 'marry', side: 'yes' }
      : { id: state.selection.id, type: 'dur', side: 'over', n: '', u: 'm' };
    syncSlipInputs();
    setMsg('slip-msg', '');
    renderBook();
    renderSlip();
  });
  ['slip-side', 'slip-yn'].forEach(function (id) {
    $(id).addEventListener('click', function (e) {
      var b = e.target.closest('button');
      if (!b || !state.selection) return;
      state.selection.side = b.getAttribute('data-v');
      setMsg('slip-msg', '');
      renderBook();
      renderSlip();
    });
  });
  ['slip-n', 'slip-u'].forEach(function (id) {
    $(id).addEventListener('input', function () { readSlipInputs(); setMsg('slip-msg', ''); renderBook(); renderSlip(); });
  });
  $('slip-stake').addEventListener('input', updateReturn);
  $('slip-chips').addEventListener('click', function (e) {
    var b = e.target.closest('button');
    if (!b) return;
    var v = b.getAttribute('data-v');
    if (v === 'all') {
      var me = state.profile && state.stats && state.stats.players[state.profile.key];
      if (!me) return;
      v = String(Math.max(0, me.balance));
    }
    $('slip-stake').value = v;
    updateReturn();
  });
  $('slip-form').addEventListener('submit', placeBet);
  $('slip-switch').addEventListener('click', function () { forgetProfile(); setMsg('slip-msg', ''); renderView(); });

  $('couple-form').addEventListener('submit', saveCouple);
  $('f-cancel').addEventListener('click', resetForm);
  $('f-status').addEventListener('change', function () {
    $('f-ended-wrap').hidden = this.value !== 'ended';
    if (this.value === 'ended' && !$('f-ended').value) $('f-ended').value = toISO(today());
  });
  $('f-married').addEventListener('change', function () {
    $('f-married-wrap').hidden = !this.checked;
    if (this.checked && !$('f-married-on').value) $('f-married-on').value = toISO(today());
  });
  $('settings-form').addEventListener('submit', saveSettings);
  $('b-form').addEventListener('submit', saveBetsConn);
  $('b-change').addEventListener('click', function () { state.betsEditing = true; prefillBets(); setMsg('b-msg', ''); renderBetsConn(); });
  $('b-cancel').addEventListener('click', function () { state.betsEditing = false; setMsg('b-msg', ''); renderBetsConn(); });

  $('gh-form').addEventListener('submit', connectGitHub);
  $('gh-change').addEventListener('click', function () { state.ghEditing = true; prefillGitHub(); setMsg('gh-msg', ''); renderSyncState(); });
  $('gh-cancel').addEventListener('click', function () { state.ghEditing = false; setMsg('gh-msg', ''); renderSyncState(); });
  $('gh-disconnect').addEventListener('click', disconnectGitHub);
  $('sync-retry').addEventListener('click', function () { state.syncError = ''; queuePublish(); renderSyncState(); });
  $('dl-btn').addEventListener('click', function () {
    download().catch(function () { alert('Could not create the file.'); });
  });
  document.addEventListener('visibilitychange', function () {
    if (!document.hidden && state.betsWaiting) { state.betsWaiting = false; tickBets(state.betsLoop); }
  });
  window.addEventListener('beforeunload', function (e) {
    if (state.pending.length) { e.preventDefault(); e.returnValue = ''; }
  });

  boot();
})();
