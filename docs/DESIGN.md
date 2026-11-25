# Brain MCP: design notes

## Goal

One read-only "brain" that several AI apps can read, so the owner stops re-explaining context. A self-hosted assistant is the only writer; it keeps a `Now.md` entry note current. Outside AI apps only read.

## Options considered

| Option | Verdict |
|---|---|
| Use an existing open-source Obsidian MCP server | Most are local (stdio) or include write tools. A remote, read-only server with its own sign-in still needed custom work. |
| **Build a small server** | **Chosen.** Small enough to audit line by line, exactly the needed scope, and a portfolio piece. |
| Fork an existing server and strip it | More code to audit than to write. |

## Key decisions

- **Read-only.** Four tools, no write path. If the notes need edits, the owner's assistant makes them in the vault. This removes a whole class of risks (prompt-injected edits, accidental deletes).
- **Remote over HTTPS, not stdio.** Phone and web clients cannot run a local process. Streamable HTTP, stateless: a fresh MCP server per request, so nothing is shared between calls.
- **OAuth 2.1 with one password.** Claude's custom connectors expect OAuth. A full identity provider is too much for one user, so the server is its own authorization server: PKCE, Dynamic Client Registration, and Client ID Metadata Documents (CIMD) limited to allowlisted hosts. The password is a scrypt hash in the environment; tokens are stored as SHA-256 hashes.
- **Node.js, not Python.** The official TypeScript SDK ships the OAuth router and bearer middleware, and the host already had the `node:22-alpine` image, so there is no build step: the code is mounted read-only into a stock image.
- **Whole vault or allowlist.** `BRAIN_ALLOW=*` serves everything; a comma list narrows it. A denylist hides sub-paths. Hidden files, non-Markdown files, traversal and escaping symlinks are refused regardless.
- **Timestamps in the owner's zone.** `modified` is ISO 8601 with the offset (e.g. `2026-11-26T02:09:39+08:00`). Clients tend to convert UTC to the device's zone, which gave wrong "today" answers; the instructions also say to quote dates as given.

## Limits and costs

- Idle memory is about 96 MB (Node.js); the container is capped at 160 MB.
- After a restart, Traefik returns 404 for about 30 seconds until the first health check passes.
- Claude apps cannot scope a connector to one Project; connectors are per account and toggled per chat. Scope is therefore enforced on the server (allowlist), not in the client.
- Instructions to the client are guidance, not enforcement. The real guarantees are the read-only tools and the path rules.

## Lessons from deployment

- **CSP `form-action` also governs redirects.** With `form-action 'self'`, Chrome blocked the 302 back to the client after a correct password; a second click then showed "sign-in request expired". Fix: add the client's redirect origin to `form-action`, and make a repeated POST for the same request replay the same redirect. Both are covered by tests.
- **Reproduce browser bugs in a browser.** `curl` showed a correct 302; only headless Chromium showed the CSP violation.
