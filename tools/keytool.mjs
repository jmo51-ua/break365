#!/usr/bin/env node
// Break365 key tool. Creates or rotates keyring.json and couples.enc.json.
// Passwords are never written to disk: only PBKDF2 salts and AES-GCM wrapped keys are.
//
// Usage (run from the site folder, Node 18+):
//   node tools/keytool.mjs init     create a new keyring and an empty couples list
//   node tools/keytool.mjs rotate   new passwords AND new data key; re-encrypts the current couples
//
// Passwords are asked interactively (hidden). For automation you can set
// B365_ADMIN_PW, B365_USER_PW and, for rotate, B365_CURRENT_PW.

import { readFile, writeFile, access } from 'node:fs/promises';
import { webcrypto as crypto } from 'node:crypto';
import readline from 'node:readline';

const ITERATIONS = 600000;
const ENC = new TextEncoder();
const DEC = new TextDecoder();
const AAD_DATA = ENC.encode('break365/data/v1');
const aadKey = (role) => ENC.encode('break365/keyring/v1/' + role);
const AAD_SECRETS = ENC.encode('break365/admin-secrets/v1');
const b64e = (u8) => Buffer.from(u8).toString('base64');
const b64d = (s) => new Uint8Array(Buffer.from(s, 'base64'));
const norm = (pw) => String(pw).normalize('NFC').trim();
const rand = (n) => crypto.getRandomValues(new Uint8Array(n));

async function deriveKek(password, salt, iterations) {
  const base = await crypto.subtle.importKey('raw', ENC.encode(norm(password)), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

async function wrap(role, password, dkRaw) {
  const salt = rand(16), iv = rand(12);
  const kek = await deriveKek(password, salt, ITERATIONS);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aadKey(role) }, kek, dkRaw);
  return { entry: { salt: b64e(salt), iv: b64e(iv), wrapped: b64e(new Uint8Array(ct)) }, kek };
}

async function decryptSecrets(kek, s) {
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64d(s.iv), additionalData: AAD_SECRETS }, kek, b64d(s.ct));
  return new Uint8Array(pt);
}

async function encryptSecrets(kek, pt) {
  const iv = rand(12);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: AAD_SECRETS }, kek, pt);
  return { iv: b64e(iv), ct: b64e(new Uint8Array(ct)) };
}

async function unwrapAny(keyring, password) {
  for (const [role, e] of Object.entries(keyring.roles)) {
    try {
      const kek = await deriveKek(password, b64d(e.salt), keyring.kdf.iterations);
      const raw = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64d(e.iv), additionalData: aadKey(role) }, kek, b64d(e.wrapped));
      return { role, dk: new Uint8Array(raw), kek };
    } catch { /* try next role */ }
  }
  throw new Error('Current password does not match any role.');
}

async function encryptData(dkRaw, obj) {
  const key = await crypto.subtle.importKey('raw', dkRaw, 'AES-GCM', false, ['encrypt']);
  const iv = rand(12);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: AAD_DATA }, key, ENC.encode(JSON.stringify(obj)));
  return { v: 1, iv: b64e(iv), ct: b64e(new Uint8Array(ct)) };
}

async function decryptData(dkRaw, file) {
  const key = await crypto.subtle.importKey('raw', dkRaw, 'AES-GCM', false, ['decrypt']);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64d(file.iv), additionalData: AAD_DATA }, key, b64d(file.ct));
  return JSON.parse(DEC.decode(pt));
}

function ask(question) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    rl._writeToOutput = (s) => { if (s.includes(question)) rl.output.write(s); };
    rl.question(question, (a) => { rl.output.write('\n'); rl.close(); resolve(a); });
  });
}

async function getPw(envName, label, confirm) {
  if (process.env[envName]) return process.env[envName];
  const a = await ask(label + ': ');
  if (confirm && (await ask('Repeat ' + label.toLowerCase() + ': ')) !== a) throw new Error('Passwords do not match.');
  return a;
}

function check(pw, label) {
  if (norm(pw).length < 12) throw new Error(label + ' must be at least 12 characters.');
}

async function exists(p) { try { await access(p); return true; } catch { return false; } }

async function main() {
  const mode = process.argv[2];
  if (!['init', 'rotate'].includes(mode)) {
    console.log('Usage: node tools/keytool.mjs init | rotate');
    process.exit(1);
  }

  let data = { v: 2, settings: { startPoints: 1000, bets: null }, couples: [] };
  let secrets = null; // GitHub connection, kept across a rotate when the admin password is given
  if (mode === 'init') {
    if ((await exists('keyring.json')) && !process.argv.includes('--force')) {
      throw new Error('keyring.json already exists. Use "rotate", or "init --force" to start over with an EMPTY couples list.');
    }
  } else {
    const keyring = JSON.parse(await readFile('keyring.json', 'utf8'));
    const current = await getPw('B365_CURRENT_PW', 'Current admin password (or user password)', false);
    const old = await unwrapAny(keyring, current);
    data = await decryptData(old.dk, JSON.parse(await readFile('couples.enc.json', 'utf8')));
    const sec = keyring.roles.admin && keyring.roles.admin.secrets;
    if (sec && old.role === 'admin') secrets = await decryptSecrets(old.kek, sec);
    else if (sec) console.log('Note: the GitHub connection can only be kept with the admin password. Connect it again in Admin after uploading.');
  }

  const adminPw = await getPw('B365_ADMIN_PW', 'New admin password', true);
  const userPw = await getPw('B365_USER_PW', 'New user password', true);
  check(adminPw, 'Admin password');
  check(userPw, 'User password');
  if (norm(adminPw) === norm(userPw)) throw new Error('Admin and user passwords must be different.');

  const dk = rand(32); // fresh data key: old copies of the data in git history stay locked to the old passwords
  const admin = await wrap('admin', adminPw, dk);
  const user = await wrap('user', userPw, dk);
  if (secrets) admin.entry.secrets = await encryptSecrets(admin.kek, secrets);
  const keyring = {
    v: 1,
    kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations: ITERATIONS },
    roles: { admin: admin.entry, user: user.entry },
  };
  await writeFile('keyring.json', JSON.stringify(keyring, null, 2) + '\n');
  await writeFile('couples.enc.json', JSON.stringify(await encryptData(dk, data)) + '\n');
  dk.fill(0);
  console.log('Wrote keyring.json and couples.enc.json (' + data.couples.length + ' couples' +
    (secrets ? ', GitHub connection kept' : '') + '). Commit both files.');
}

main().catch((e) => { console.error('Error: ' + e.message); process.exit(1); });
