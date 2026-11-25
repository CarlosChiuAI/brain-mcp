// Single-user OAuth 2.1 authorization server for the Brain MCP server.
// - One password (scrypt hash from the environment) unlocks the login page.
// - Clients: Client ID Metadata Documents from allowlisted hosts (e.g. Claude's published identity),
//   or Dynamic Client Registration as a fallback.
// - PKCE is enforced by the SDK's token handler. Access tokens live in memory (1 h);
//   refresh tokens and registered clients persist (hashed) in STATE_DIR so a restart doesn't force re-login.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import express from 'express';
import { rateLimit } from 'express-rate-limit';
import { InvalidGrantError, InvalidTokenError, InvalidClientMetadataError } from '@modelcontextprotocol/sdk/server/auth/errors.js';

const ACCESS_TTL_S = 3600;
const REFRESH_TTL_S = 30 * 86400;
const CODE_TTL_MS = 5 * 60_000;
const PENDING_TTL_MS = 10 * 60_000;
const MAX_CLIENTS = 50;
const SCOPE = 'vault:read';

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
const token = () => crypto.randomBytes(32).toString('base64url');

/** Verify a password against "scrypt$N$r$p$saltB64$hashB64". Constant-time compare. */
export function verifyPassword(password, encoded) {
  if (typeof password !== 'string' || typeof encoded !== 'string') return false;
  const parts = encoded.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const [N, r, p] = parts.slice(1, 4).map(Number);
  const salt = Buffer.from(parts[4], 'base64');
  const want = Buffer.from(parts[5], 'base64');
  if (!N || !r || !p || salt.length < 16 || want.length < 32) return false;
  let got;
  try {
    got = crypto.scryptSync(password, salt, want.length, { N, r, p, maxmem: 256 * N * r });
  } catch {
    return false;
  }
  return crypto.timingSafeEqual(got, want);
}

export function hashPassword(password, { N = 32768, r = 8, p = 1 } = {}) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, 32, { N, r, p, maxmem: 256 * N * r });
  return ['scrypt', N, r, p, salt.toString('base64'), hash.toString('base64')].join('$');
}

class StateFile {
  constructor(dir) {
    this.file = dir ? path.join(dir, 'state.json') : null;
    this.data = { clients: {}, refresh: {} };
    if (this.file && fs.existsSync(this.file)) {
      try {
        this.data = { clients: {}, refresh: {}, ...JSON.parse(fs.readFileSync(this.file, 'utf8')) };
      } catch {
        /* corrupt state: start clean, user just logs in again */
      }
    }
  }
  save() {
    if (!this.file) return;
    const now = Date.now() / 1000;
    for (const [k, v] of Object.entries(this.data.refresh)) if (v.exp < now) delete this.data.refresh[k];
    const tmp = this.file + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(this.data), { mode: 0o600 });
    fs.renameSync(tmp, this.file);
  }
}

export class BrainAuthProvider {
  /**
   * @param {object} o
   * @param {string} o.passwordHash   scrypt hash
   * @param {URL}    o.resourceUrl    e.g. https://brain.example.com/mcp
   * @param {string} [o.stateDir]     writable dir for clients + refresh tokens
   * @param {string[]} [o.cimdHosts]  hosts allowed to serve client metadata documents
   * @param {(url: string) => Promise<any>} [o.fetchJson] injectable for tests
   */
  constructor({ passwordHash, resourceUrl, stateDir, cimdHosts = [], fetchJson }) {
    if (!passwordHash) throw new Error('BRAIN_PASSWORD_HASH is not set');
    this.passwordHash = passwordHash;
    this.resourceUrl = resourceUrl;
    this.state = new StateFile(stateDir);
    this.cimdHosts = cimdHosts.map((h) => h.toLowerCase());
    this.fetchJson = fetchJson || defaultFetchJson;
    this.cimdCache = new Map(); // url -> { client, exp }
    this.pending = new Map(); // reqId -> { client, params, exp }
    this.codes = new Map(); // code -> { clientId, params, exp }
    this.completed = new Map(); // reqId -> { location, exp } (repeat clicks)
    this.access = new Map(); // sha256(token) -> { clientId, scopes, resource, exp }
    const self = this;

    this.clientsStore = {
      async getClient(clientId) {
        if (/^https:\/\//i.test(clientId)) return self.#getMetadataClient(clientId);
        return self.state.data.clients[clientId];
      },
      registerClient(meta) {
        const ids = Object.keys(self.state.data.clients);
        if (ids.length >= MAX_CLIENTS) {
          const oldest = ids.sort((a, b) => self.state.data.clients[a].client_id_issued_at - self.state.data.clients[b].client_id_issued_at)[0];
          delete self.state.data.clients[oldest];
        }
        for (const u of meta.redirect_uris || []) {
          const url = new URL(u);
          if (url.protocol !== 'https:' && !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)) {
            throw new InvalidClientMetadataError('redirect_uris must be https (or localhost)');
          }
        }
        const client = { ...meta, client_id: crypto.randomUUID(), client_id_issued_at: Math.floor(Date.now() / 1000) };
        self.state.data.clients[client.client_id] = client;
        self.state.save();
        return client;
      },
    };
  }

  async #getMetadataClient(url) {
    let u;
    try {
      u = new URL(url);
    } catch {
      return undefined;
    }
    const host = u.hostname.toLowerCase();
    if (!this.cimdHosts.some((h) => host === h || host.endsWith('.' + h))) return undefined;
    const hit = this.cimdCache.get(url);
    if (hit && hit.exp > Date.now()) return hit.client;
    let doc;
    try {
      doc = await this.fetchJson(url);
    } catch {
      return undefined;
    }
    if (!doc || doc.client_id !== url || !Array.isArray(doc.redirect_uris) || doc.redirect_uris.length === 0) return undefined;
    const client = {
      client_id: url,
      client_name: typeof doc.client_name === 'string' ? doc.client_name.slice(0, 100) : host,
      redirect_uris: doc.redirect_uris.filter((r) => typeof r === 'string'),
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
    };
    this.cimdCache.set(url, { client, exp: Date.now() + 3600_000 });
    return client;
  }

  // Called by the SDK's /authorize handler after it has validated client_id and redirect_uri.
  async authorize(client, params, res) {
    this.#sweep();
    const reqId = token();
    this.pending.set(reqId, { client, params, exp: Date.now() + PENDING_TTL_MS });
    sendLoginPage(res, { reqId, clientName: client.client_name || client.client_id, redirectUri: params.redirectUri });
  }

  /** Express router for POST /login (the password form). */
  loginRouter() {
    const r = express.Router();
    const limiter = rateLimit({ windowMs: 15 * 60_000, limit: 10, standardHeaders: 'draft-7', legacyHeaders: false });
    r.post('/login', limiter, express.urlencoded({ extended: false, limit: '4kb' }), (req, res) => {
      res.setHeader('Cache-Control', 'no-store');
      const reqId = String(req.body?.req || '');
      // A second click after a successful sign-in returns the same redirect instead of an error.
      const done = this.completed.get(reqId);
      if (done && done.exp > Date.now()) {
        res.redirect(302, done.location);
        return;
      }
      const p = this.pending.get(reqId);
      if (!p || p.exp < Date.now()) {
        this.pending.delete(reqId);
        res.status(400).type('text/plain').send('This sign-in request expired. Go back to Claude and connect again.');
        return;
      }
      if (!verifyPassword(String(req.body?.password || ''), this.passwordHash)) {
        sendLoginPage(res.status(401), { reqId, clientName: p.client.client_name || p.client.client_id, redirectUri: p.params.redirectUri, error: true });
        return;
      }
      this.pending.delete(reqId);
      const code = token();
      this.codes.set(code, { clientId: p.client.client_id, params: p.params, exp: Date.now() + CODE_TTL_MS });
      const target = new URL(p.params.redirectUri);
      target.searchParams.set('code', code);
      if (p.params.state !== undefined) target.searchParams.set('state', p.params.state);
      this.completed.set(reqId, { location: target.href, exp: Date.now() + CODE_TTL_MS });
      res.redirect(302, target.href);
    });
    return r;
  }

  async challengeForAuthorizationCode(client, code) {
    const c = this.codes.get(code);
    if (!c || c.clientId !== client.client_id || c.exp < Date.now()) throw new InvalidGrantError('Invalid authorization code');
    return c.params.codeChallenge;
  }

  async exchangeAuthorizationCode(client, code, _verifier, redirectUri, resource) {
    const c = this.codes.get(code);
    this.codes.delete(code); // single use, even on failure
    if (!c || c.clientId !== client.client_id || c.exp < Date.now()) throw new InvalidGrantError('Invalid authorization code');
    if (redirectUri && redirectUri !== c.params.redirectUri) throw new InvalidGrantError('redirect_uri mismatch');
    const res = resource?.href || c.params.resource?.href || this.resourceUrl.href;
    if (res !== this.resourceUrl.href) throw new InvalidGrantError('Unknown resource');
    return this.#issue(client.client_id, [SCOPE], res);
  }

  async exchangeRefreshToken(client, refreshToken, _scopes, resource) {
    const key = sha256(refreshToken);
    const rt = this.state.data.refresh[key];
    if (!rt || rt.clientId !== client.client_id || rt.exp < Date.now() / 1000) throw new InvalidGrantError('Invalid refresh token');
    if (resource && resource.href !== rt.resource) throw new InvalidGrantError('Unknown resource');
    delete this.state.data.refresh[key]; // rotate
    return this.#issue(client.client_id, rt.scopes, rt.resource);
  }

  async verifyAccessToken(tok) {
    const a = this.access.get(sha256(tok));
    if (!a || a.exp < Date.now() / 1000) throw new InvalidTokenError('Invalid or expired token');
    return { token: tok, clientId: a.clientId, scopes: a.scopes, expiresAt: a.exp, resource: new URL(a.resource) };
  }

  async revokeToken(client, { token: tok }) {
    const k = sha256(tok);
    if (this.state.data.refresh[k]?.clientId === client.client_id) {
      delete this.state.data.refresh[k];
      this.state.save();
    }
    if (this.access.get(k)?.clientId === client.client_id) this.access.delete(k);
  }

  #issue(clientId, scopes, resource) {
    const now = Math.floor(Date.now() / 1000);
    const at = token();
    const rt = token();
    this.access.set(sha256(at), { clientId, scopes, resource, exp: now + ACCESS_TTL_S });
    this.state.data.refresh[sha256(rt)] = { clientId, scopes, resource, exp: now + REFRESH_TTL_S };
    this.state.save();
    this.#sweep();
    return { access_token: at, token_type: 'bearer', expires_in: ACCESS_TTL_S, refresh_token: rt, scope: scopes.join(' ') };
  }

  #sweep() {
    const now = Date.now();
    for (const [k, v] of this.pending) if (v.exp < now) this.pending.delete(k);
    for (const [k, v] of this.codes) if (v.exp < now) this.codes.delete(k);
    for (const [k, v] of this.completed) if (v.exp < now) this.completed.delete(k);
    for (const [k, v] of this.access) if (v.exp * 1000 < now) this.access.delete(k);
  }
}

async function defaultFetchJson(url) {
  const ctl = AbortSignal.timeout(5000);
  const r = await fetch(url, { signal: ctl, redirect: 'error', headers: { accept: 'application/json' } });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  const text = await r.text();
  if (text.length > 20_000) throw new Error('metadata too large');
  return JSON.parse(text);
}

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

function sendLoginPage(res, { reqId, clientName, redirectUri, error = false }) {
  // form-action also governs where the form's response may redirect (Chrome enforces this),
  // so the client's registered redirect origin must be listed or the hand-back to Claude is blocked.
  let redirectOrigin = '';
  try {
    redirectOrigin = new URL(redirectUri).origin;
  } catch {
    /* no redirect origin */
  }
  const formAction = ["'self'", redirectOrigin].filter(Boolean).join(' ');
  res.setHeader('Content-Security-Policy', `default-src 'none'; style-src 'unsafe-inline'; form-action ${formAction}; frame-ancestors 'none'; base-uri 'none'`);
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cache-Control', 'no-store');
  res.type('html').send(`<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Brain · Sign in</title>
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0D0D0D;color:#DCDAD2;font:16px/1.5 system-ui,sans-serif}
main{width:min(360px,90vw);border:1px solid #2C2933;border-radius:18px;padding:32px}
h1{margin:0 0 4px;font-size:22px}p{margin:0 0 20px;color:#9aa6b8;font-size:14px}
label{font-size:13px;letter-spacing:.06em;text-transform:uppercase}
input{width:100%;box-sizing:border-box;margin:8px 0 16px;padding:12px;border-radius:6px;border:1px solid #2C2933;background:#15131A;color:#DCDAD2;font-size:16px}
button{width:100%;padding:12px;border:0;border-radius:999px;background:#8FA8C8;color:#0D0D0D;font-weight:700;font-size:16px;cursor:pointer}
.err{color:#E6C07B}</style></head><body><main>
<h1>Brain</h1><p><b>${esc(clientName)}</b> wants read-only access to the shared notes.</p>
${error ? '<p class="err">Wrong password.</p>' : ''}
<form method="post" action="login"><input type="hidden" name="req" value="${esc(reqId)}">
<label for="pw">Password</label><input id="pw" name="password" type="password" autocomplete="current-password" required autofocus>
<button type="submit">Allow read-only access</button></form></main></body></html>`);
}

export const BRAIN_SCOPE = SCOPE;
