// Brain MCP: read-only remote MCP server for an Obsidian vault.
import express from 'express';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { mcpAuthRouter, createOAuthMetadata, getOAuthProtectedResourceMetadataUrl } from '@modelcontextprotocol/sdk/server/auth/router.js';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import { z } from 'zod';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Vault, VaultError, makeStamper } from './vault.mjs';
import { BrainAuthProvider, BRAIN_SCOPE } from './auth.mjs';

const VERSION = '0.1.0';

/**
 * Server instructions sent to the AI client. Owner, writer and time zone come from config
 * (env BRAIN_OWNER / BRAIN_WRITER / BRAIN_TZ, or brain.config.json in the state dir).
 */
export function buildInstructions({ owner = 'the owner', writer = 'their assistant', timeZone = 'UTC' } = {}) {
  const poss = owner === 'the owner' ? "the owner's" : `${owner}'s`;
  const stamp = makeStamper(timeZone)(new Date());
  const m = stamp.match(/([+-]\d\d):(\d\d)$/);
  const offset = m ? `UTC${m[1].replace(/^([+-])0/, '$1')}${m[2] === '00' ? '' : ':' + m[2]}` : 'UTC';
  const zone = timeZone === 'UTC' ? 'UTC' : `${timeZone}, ${offset}`;
  return `Brain is ${poss} shared, read-only notes, written and kept current by ${writer}.
Use it for ${poss} projects, career, plans and past decisions. Read Now.md first if it exists: it says what is in progress.
Brain is the source of truth for those topics; if it disagrees with your memory, trust Brain and say so.
Always cite the note path and its modified date. All dates are ${poss} local time (${zone}); quote them as given, do not convert to another time zone. Notes can be out of date: check the date before relying on one.
You cannot change Brain. Never claim you updated it.`;
}

const READ_ONLY = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false };

export function buildMcpServer(vault, instructions = buildInstructions()) {
  const server = new McpServer({ name: 'brain', version: VERSION }, { instructions });
  const ok = (obj) => ({ content: [{ type: 'text', text: JSON.stringify(obj, null, 2) }] });
  const fail = (e) => {
    if (e instanceof VaultError) return { isError: true, content: [{ type: 'text', text: e.message }] };
    throw e;
  };

  server.registerTool(
    'search_notes',
    {
      title: 'Search notes',
      description: 'Search shared notes by words (all words must match). Returns note paths, modified dates and snippets. Then use read_note.',
      inputSchema: {
        query: z.string().min(1).max(200).describe('Words to search for'),
        folder: z.string().max(200).optional().describe('Limit to a folder, e.g. "Projects" or "Career"'),
        limit: z.number().int().min(1).max(25).optional().describe('Max results (default 10)'),
      },
      annotations: READ_ONLY,
    },
    async ({ query, folder, limit }) => {
      try {
        return ok({ results: await vault.search(query, { folder, limit }) });
      } catch (e) {
        return fail(e);
      }
    },
  );

  server.registerTool(
    'read_note',
    {
      title: 'Read note',
      description: 'Read one shared note in full (Markdown). Returns path, modified date and content. Start with "Now.md".',
      inputSchema: { path: z.string().min(1).max(512).describe('Note path from search_notes or list_notes, e.g. "Now.md"') },
      annotations: READ_ONLY,
    },
    async ({ path }) => {
      try {
        return ok(await vault.readNote(path));
      } catch (e) {
        return fail(e);
      }
    },
  );

  server.registerTool(
    'list_notes',
    {
      title: 'List notes',
      description: 'List shared note paths with modified dates, newest first. Optionally limit to a folder.',
      inputSchema: { folder: z.string().max(200).optional().describe('Folder, e.g. "Projects"') },
      annotations: READ_ONLY,
    },
    async ({ folder }) => {
      try {
        const notes = await vault.listNotes(folder);
        return ok({ count: notes.length, notes: notes.slice(0, 300) });
      } catch (e) {
        return fail(e);
      }
    },
  );

  server.registerTool(
    'recent_changes',
    {
      title: 'Recent changes',
      description: 'Notes changed in the last N days (default 7), newest first. Use it to see what is being worked on right now.',
      inputSchema: { days: z.number().int().min(1).max(90).optional().describe('Look-back window in days') },
      annotations: READ_ONLY,
    },
    async ({ days }) => {
      try {
        const notes = await vault.recentChanges(days ?? 7);
        return ok({ days: days ?? 7, count: notes.length, notes: notes.slice(0, 100) });
      } catch (e) {
        return fail(e);
      }
    },
  );

  return server;
}

export function createApp(cfg) {
  const publicUrl = new URL(cfg.publicUrl); // e.g. https://brain.example.com
  const resourceUrl = new URL('/mcp', publicUrl);
  const vault = new Vault({ root: cfg.vaultRoot, allow: cfg.allow, deny: cfg.deny, timeZone: cfg.timeZone || 'UTC' });
  const instructions = buildInstructions({ owner: cfg.owner, writer: cfg.writer, timeZone: cfg.timeZone || 'UTC' });
  const provider = new BrainAuthProvider({
    passwordHash: cfg.passwordHash,
    resourceUrl,
    stateDir: cfg.stateDir,
    cimdHosts: cfg.cimdHosts,
    fetchJson: cfg.fetchJson,
  });

  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', cfg.trustProxy ?? 1); // one hop: Traefik

  app.get('/healthz', (_req, res) => res.type('text/plain').send('ok'));

  // Advertise Client ID Metadata Document support on top of the SDK's metadata.
  const asMeta = {
    ...createOAuthMetadata({ provider, issuerUrl: publicUrl, scopesSupported: [BRAIN_SCOPE] }),
    client_id_metadata_document_supported: true,
  };
  app.get('/.well-known/oauth-authorization-server', (_req, res) => res.json(asMeta));

  app.use(
    mcpAuthRouter({
      provider,
      issuerUrl: publicUrl,
      resourceServerUrl: resourceUrl,
      scopesSupported: [BRAIN_SCOPE],
      resourceName: 'Brain (read-only notes)',
    }),
  );
  app.use(provider.loginRouter());

  const bearer = requireBearerAuth({
    verifier: provider,
    requiredScopes: [BRAIN_SCOPE],
    resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(resourceUrl),
    expectedResource: resourceUrl,
  });

  // Stateless Streamable HTTP: a fresh server + transport per request.
  app.post('/mcp', bearer, express.json({ limit: '256kb' }), async (req, res) => {
    const server = buildMcpServer(vault, instructions);
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    res.on('close', () => {
      transport.close();
      server.close();
    });
    try {
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (e) {
      console.error('mcp error', e?.message);
      if (!res.headersSent) res.status(500).json({ jsonrpc: '2.0', error: { code: -32603, message: 'Internal error' }, id: null });
    }
  });
  const notAllowed = (_req, res) =>
    res.status(405).set('Allow', 'POST').json({ jsonrpc: '2.0', error: { code: -32000, message: 'Method not allowed' }, id: null });
  app.get('/mcp', bearer, notAllowed);
  app.delete('/mcp', bearer, notAllowed);

  app.use((_req, res) => res.status(404).type('text/plain').send('Not found'));
  return { app, vault, provider, resourceUrl };
}

/** Optional private settings file in the state dir: {"owner","writer","timeZone"}. Env wins. */
export function readLocalConfig(stateDir) {
  try {
    return JSON.parse(readFileSync(join(stateDir, 'brain.config.json'), 'utf8'));
  } catch {
    return {};
  }
}

export function configFromEnv(env = process.env) {
  const stateDir = env.BRAIN_STATE_DIR || '/state';
  const local = readLocalConfig(stateDir);
  const list = (v, d) => (v ?? d).split(',').map((s) => s.trim()).filter(Boolean);
  const required = (k) => {
    if (!env[k]) throw new Error(`${k} is required`);
    return env[k];
  };
  return {
    publicUrl: required('BRAIN_PUBLIC_URL'),
    vaultRoot: env.BRAIN_VAULT_DIR || '/vault',
    allow: list(env.BRAIN_ALLOW, '*'),
    deny: list(env.BRAIN_DENY, ''),
    passwordHash: required('BRAIN_PASSWORD_HASH'),
    stateDir,
    cimdHosts: list(env.BRAIN_CIMD_HOSTS, 'claude.ai,claude.com,anthropic.com'),
    owner: env.BRAIN_OWNER || local.owner || 'the owner',
    writer: env.BRAIN_WRITER || local.writer || 'their assistant',
    timeZone: env.BRAIN_TZ || local.timeZone || 'UTC',
    port: Number(env.PORT || 8788),
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const cfg = configFromEnv();
  const { app } = createApp(cfg);
  app.listen(cfg.port, '0.0.0.0', () => {
    console.log(`brain-mcp ${VERSION} on :${cfg.port}, allow=[${cfg.allow}] deny=[${cfg.deny}] tz=${cfg.timeZone}`);
  });
}
