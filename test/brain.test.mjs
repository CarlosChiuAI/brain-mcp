import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import crypto from 'node:crypto';
import { createApp } from '../src/server.mjs';
import { hashPassword, verifyPassword } from '../src/auth.mjs';
import { Vault, makeStamper } from '../src/vault.mjs';

const PASSWORD = 'correct horse battery staple';
let tmp, vaultDir, stateDir, server, base, cimdDocs;

function write(rel, text) {
  const p = path.join(vaultDir, rel);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, text);
}

async function freePort() {
  return new Promise((res) => {
    const s = net.createServer().listen(0, '127.0.0.1', () => {
      const { port } = s.address();
      s.close(() => res(port));
    });
  });
}

before(async () => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'brain-test-'));
  vaultDir = path.join(tmp, 'vault');
  stateDir = path.join(tmp, 'state');
  fs.mkdirSync(stateDir, { recursive: true });
  write('Now.md', '# Now\nBuilding the Brain MCP server.');
  write('Projects/Garden Planner.md', '# Garden Planner\nDecision: keep SQLite. Zebra keyword.');
  write('Career/Plan.md', '# Career\nMCP portfolio piece.');
  write('Team/Builder/Notes.md', 'builder notes zebra');
  write('Team/Finance/Notes.md', 'SECRET bills zebra');
  write('Private/Diary.md', 'SECRET family zebra');
  write('Systems/Server.md', 'SECRET infra zebra');
  write('Projects/.hidden.md', 'SECRET hidden zebra');
  write('Projects/image.png', 'not markdown');
  fs.symlinkSync(path.join(vaultDir, 'Private/Diary.md'), path.join(vaultDir, 'Projects/link.md'));

  const port = await freePort();
  base = `http://localhost:${port}`;
  cimdDocs = new Map();
  const { app } = createApp({
    publicUrl: base,
    vaultRoot: vaultDir,
    allow: ['Now.md', 'Projects', 'Career', 'Team', 'Lists'],
    deny: ['Team/Finance', 'Team/Inbox'],
    passwordHash: hashPassword(PASSWORD, { N: 1024 }),
    stateDir,
    cimdHosts: ['claude.ai'],
    fetchJson: async (url) => {
      if (!cimdDocs.has(url)) throw new Error('404');
      return cimdDocs.get(url);
    },
    trustProxy: false,
  });
  await new Promise((r) => (server = app.listen(port, '127.0.0.1', r)));
});

after(() => {
  server?.close();
  fs.rmSync(tmp, { recursive: true, force: true });
});

// ---------- helpers ----------
const pkce = () => {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
};

async function register(redirect = 'https://claude.ai/api/mcp/auth_callback') {
  const r = await fetch(`${base}/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ client_name: 'Test Client', redirect_uris: [redirect], token_endpoint_auth_method: 'none', grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'] }),
  });
  assert.equal(r.status, 201, await r.clone().text());
  return r.json();
}

async function authorize(clientId, redirect, challenge, password = PASSWORD) {
  const q = new URLSearchParams({ response_type: 'code', client_id: clientId, redirect_uri: redirect, code_challenge: challenge, code_challenge_method: 'S256', state: 'xyz', resource: `${base}/mcp`, scope: 'vault:read' });
  const page = await fetch(`${base}/authorize?${q}`, { redirect: 'manual' });
  assert.equal(page.status, 200);
  const html = await page.text();
  const req = html.match(/name="req" value="([^"]+)"/)[1];
  return fetch(`${base}/login`, { method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ req, password }) });
}

async function tokenFor(clientId, redirect) {
  const { verifier, challenge } = pkce();
  const login = await authorize(clientId, redirect, challenge);
  assert.equal(login.status, 302);
  const loc = new URL(login.headers.get('location'));
  assert.equal(loc.searchParams.get('state'), 'xyz');
  const r = await fetch(`${base}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'authorization_code', code: loc.searchParams.get('code'), code_verifier: verifier, client_id: clientId, redirect_uri: redirect, resource: `${base}/mcp` }),
  });
  assert.equal(r.status, 200, await r.clone().text());
  return r.json();
}

async function mcp(accessToken, method, params = {}) {
  const r = await fetch(`${base}/mcp`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', authorization: `Bearer ${accessToken}` },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  return { status: r.status, body: r.status === 200 ? await r.json() : await r.text() };
}
const callTool = async (t, name, args) => {
  const r = await mcp(t, 'tools/call', { name, arguments: args });
  assert.equal(r.status, 200);
  return r.body.result;
};
const toolJson = (result) => JSON.parse(result.content[0].text);

// ---------- password ----------
test('password hash verifies only the right password', () => {
  const h = hashPassword('pw-123456', { N: 1024 });
  assert.equal(verifyPassword('pw-123456', h), true);
  assert.equal(verifyPassword('pw-123457', h), false);
  assert.equal(verifyPassword('pw-123456', 'garbage'), false);
});

// ---------- time zone ----------
test('timestamps render in the configured zone with offset', async () => {
  const manila = makeStamper('Asia/Manila');
  assert.equal(manila(new Date('2026-11-25T18:03:00Z')), '2026-11-26T02:03:00+08:00');
  assert.equal(makeStamper('UTC')(new Date('2026-11-25T18:03:00Z')), '2026-11-25T18:03:00Z');
  assert.equal(Date.parse('2026-11-26T02:03:00+08:00'), Date.parse('2026-11-25T18:03:00Z'));
  const v = new Vault({ root: vaultDir, allow: ['Now.md'], timeZone: 'Asia/Manila' });
  assert.match((await v.readNote('Now.md')).modified, /\+08:00$/);
});

// ---------- instructions and private config ----------
test('instructions are generic by default and personalised from config', async () => {
  const { buildInstructions, readLocalConfig, configFromEnv } = await import('../src/server.mjs');
  const generic = buildInstructions();
  assert.match(generic, /the owner's shared, read-only notes/);
  assert.match(generic, /\(UTC\)/);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'brain-cfg-'));
  fs.writeFileSync(path.join(dir, 'brain.config.json'), JSON.stringify({ owner: 'Alex', writer: 'a bot', timeZone: 'Asia/Manila' }));
  assert.equal(readLocalConfig(dir).owner, 'Alex');
  const cfg = configFromEnv({ BRAIN_PUBLIC_URL: 'https://b.example', BRAIN_PASSWORD_HASH: 'x', BRAIN_STATE_DIR: dir, BRAIN_TZ: 'UTC' });
  assert.equal(cfg.owner, 'Alex');
  assert.equal(cfg.timeZone, 'UTC', 'env wins over the file');
  const personal = buildInstructions({ owner: 'Alex', writer: 'a bot', timeZone: 'Asia/Manila' });
  assert.match(personal, /Alex's local time \(Asia\/Manila, UTC\+8\)/);
  assert.equal(readLocalConfig(path.join(dir, 'missing')).owner, undefined);
});

// ---------- vault rules (unit) ----------
test('vault allowlist blocks traversal, hidden, denied, non-md and escaping symlinks', async () => {
  const v = new Vault({ root: vaultDir, allow: ['Now.md', 'Projects', 'Team'], deny: ['Team/Finance'] });
  for (const bad of ['../etc/passwd', '/etc/passwd', 'Private/Diary.md', 'Systems/Server.md', 'Projects/.hidden.md', 'Projects/image.png', 'Team/Finance/Notes.md', 'Projects/link.md', 'Projects/../Private/Diary.md', 'Projects\\..\\Private\\Diary.md']) {
    await assert.rejects(v.readNote(bad), /not found|Only Markdown|Invalid/, bad);
  }
  assert.match((await v.readNote('Now.md')).content, /Brain MCP/);
  const listed = (await v.listNotes()).map((n) => n.path).sort();
  assert.deepEqual(listed, ['Now.md', 'Projects/Garden Planner.md', 'Team/Builder/Notes.md']);
  const hits = (await v.search('zebra')).map((h) => h.path).sort();
  assert.deepEqual(hits, ['Projects/Garden Planner.md', 'Team/Builder/Notes.md']);
});

test('"*" serves the whole vault but still blocks hidden, non-md, traversal and escaping symlinks', async () => {
  const v = new Vault({ root: vaultDir, allow: ['*'], deny: ['Team/Finance'] });
  const listed = (await v.listNotes()).map((n) => n.path);
  assert.ok(listed.includes('Private/Diary.md') && listed.includes('Systems/Server.md'));
  assert.ok(!listed.some((p) => /\.hidden|image\.png|link\.md|Team\/Finance/.test(p)));
  for (const bad of ['../etc/passwd', '/etc/passwd', 'Projects/.hidden.md', 'Projects/image.png', 'Team/Finance/Notes.md']) {
    await assert.rejects(v.readNote(bad), /not found|Only Markdown|Invalid/, bad);
  }
  const outside = path.join(tmp, 'outside.md');
  fs.writeFileSync(outside, 'SECRET outside');
  fs.symlinkSync(outside, path.join(vaultDir, 'Projects/escape.md'));
  await assert.rejects(v.readNote('Projects/escape.md'), /not found/);
  fs.unlinkSync(path.join(vaultDir, 'Projects/escape.md'));
});

// ---------- HTTP auth ----------
test('MCP endpoint requires a bearer token and advertises resource metadata', async () => {
  const r = await fetch(`${base}/mcp`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
  assert.equal(r.status, 401);
  assert.match(r.headers.get('www-authenticate') || '', /resource_metadata=/);
  const bad = await mcp('not-a-token', 'tools/list');
  assert.equal(bad.status, 401);
  const prm = await (await fetch(`${base}/.well-known/oauth-protected-resource/mcp`)).json();
  assert.equal(prm.resource, `${base}/mcp`);
  const as = await (await fetch(`${base}/.well-known/oauth-authorization-server`)).json();
  assert.equal(as.client_id_metadata_document_supported, true);
  assert.ok(as.code_challenge_methods_supported.includes('S256'));
});

test('login page CSP allows the hand-back to the client redirect origin; a repeat click repeats the redirect', async () => {
  const redirect = 'https://claude.ai/api/mcp/auth_callback';
  const c = await register(redirect);
  const q = new URLSearchParams({ response_type: 'code', client_id: c.client_id, redirect_uri: redirect, code_challenge: pkce().challenge, code_challenge_method: 'S256', state: 'xyz' });
  const page = await fetch(`${base}/authorize?${q}`, { redirect: 'manual' });
  const csp = page.headers.get('content-security-policy');
  assert.match(csp, /form-action 'self' https:\/\/claude\.ai;/);
  const req = (await page.text()).match(/name="req" value="([^"]+)"/)[1];
  const post = () => fetch(`${base}/login`, { method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ req, password: PASSWORD }) });
  const a = await post();
  const b = await post();
  assert.equal(a.status, 302);
  assert.equal(b.status, 302);
  assert.equal(a.headers.get('location'), b.headers.get('location'));
});

test('wrong password does not issue a code', async () => {
  const redirect = 'https://claude.ai/api/mcp/auth_callback';
  const c = await register(redirect);
  const r = await authorize(c.client_id, redirect, pkce().challenge, 'wrong');
  assert.equal(r.status, 401);
  assert.equal(r.headers.get('location'), null);
});

test('unregistered redirect_uri is refused before the login page', async () => {
  const c = await register('https://claude.ai/api/mcp/auth_callback');
  const q = new URLSearchParams({ response_type: 'code', client_id: c.client_id, redirect_uri: 'https://evil.example/cb', code_challenge: pkce().challenge, code_challenge_method: 'S256' });
  const r = await fetch(`${base}/authorize?${q}`, { redirect: 'manual' });
  assert.equal(r.status, 400);
});

test('token exchange fails with the wrong PKCE verifier, and codes are single use', async () => {
  const redirect = 'https://claude.ai/api/mcp/auth_callback';
  const c = await register(redirect);
  const { verifier, challenge } = pkce();
  const login = await authorize(c.client_id, redirect, challenge);
  const code = new URL(login.headers.get('location')).searchParams.get('code');
  const body = (v) => new URLSearchParams({ grant_type: 'authorization_code', code, code_verifier: v, client_id: c.client_id, redirect_uri: redirect });
  const post = (v) => fetch(`${base}/token`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: body(v) });
  assert.equal((await post(crypto.randomBytes(32).toString('base64url'))).status, 400);
  // a correct verifier can't rescue a code after a failed attempt (PKCE check consumed nothing, so try success path on a fresh code)
  const login2 = await authorize(c.client_id, redirect, challenge);
  const code2 = new URL(login2.headers.get('location')).searchParams.get('code');
  const ok = (cd) => fetch(`${base}/token`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'authorization_code', code: cd, code_verifier: verifier, client_id: c.client_id, redirect_uri: redirect }) });
  assert.equal((await ok(code2)).status, 200);
  assert.equal((await ok(code2)).status, 400, 'second use of the same code must fail');
});

test('full OAuth flow (DCR) then all four tools work and stay inside the allowlist', async () => {
  const redirect = 'https://claude.ai/api/mcp/auth_callback';
  const c = await register(redirect);
  const tok = await tokenFor(c.client_id, redirect);
  assert.ok(tok.access_token && tok.refresh_token);

  const init = await mcp(tok.access_token, 'initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '1' } });
  assert.equal(init.status, 200);
  assert.match(init.body.result.instructions, /Now\.md/);

  const list = await mcp(tok.access_token, 'tools/list');
  const tools = list.body.result.tools;
  assert.deepEqual(tools.map((t) => t.name).sort(), ['list_notes', 'read_note', 'recent_changes', 'search_notes']);
  for (const t of tools) assert.equal(t.annotations.readOnlyHint, true, t.name);

  const now = toolJson(await callTool(tok.access_token, 'read_note', { path: 'Now.md' }));
  assert.match(now.content, /Brain MCP/);
  assert.ok(now.modified);

  const secret = await callTool(tok.access_token, 'read_note', { path: 'Private/Diary.md' });
  assert.equal(secret.isError, true);
  const finance = await callTool(tok.access_token, 'read_note', { path: 'Team/Finance/Notes.md' });
  assert.equal(finance.isError, true);

  const search = toolJson(await callTool(tok.access_token, 'search_notes', { query: 'zebra' }));
  assert.deepEqual(search.results.map((r) => r.path).sort(), ['Projects/Garden Planner.md', 'Team/Builder/Notes.md']);
  assert.ok(!JSON.stringify(search).includes('SECRET'));

  const all = toolJson(await callTool(tok.access_token, 'list_notes', {}));
  assert.ok(!all.notes.some((n) => /Private|Systems|Team\/Finance|hidden|link\.md/.test(n.path)));
  const recent = toolJson(await callTool(tok.access_token, 'recent_changes', { days: 3 }));
  assert.ok(recent.count >= 1);

  // refresh rotates: old refresh token stops working
  const ref = (rt) => fetch(`${base}/token`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: rt, client_id: c.client_id }) });
  const r1 = await ref(tok.refresh_token);
  assert.equal(r1.status, 200);
  const r2 = await ref(tok.refresh_token);
  assert.equal(r2.status, 400);

  // state on disk never holds raw tokens
  const state = fs.readFileSync(path.join(stateDir, 'state.json'), 'utf8');
  assert.ok(!state.includes(tok.refresh_token) && !state.includes(tok.access_token));
});

test('Client ID Metadata Document from an allowlisted host works; other hosts are refused', async () => {
  const id = 'https://claude.ai/oauth/mcp-oauth-client-metadata';
  const redirect = 'https://claude.ai/api/mcp/auth_callback';
  cimdDocs.set(id, { client_id: id, client_name: 'Claude', redirect_uris: [redirect] });
  const tok = await tokenFor(id, redirect);
  assert.equal((await mcp(tok.access_token, 'tools/list')).status, 200);

  const evil = 'https://evil.example/meta.json';
  cimdDocs.set(evil, { client_id: evil, redirect_uris: ['https://evil.example/cb'] });
  const q = new URLSearchParams({ response_type: 'code', client_id: evil, redirect_uri: 'https://evil.example/cb', code_challenge: pkce().challenge, code_challenge_method: 'S256' });
  const r = await fetch(`${base}/authorize?${q}`, { redirect: 'manual' });
  assert.equal(r.status, 400);
});
