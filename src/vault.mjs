// Read-only, allowlisted access to an Obsidian vault.
// Every path from a client goes through resolveNote(); nothing else touches the disk.
import fs from 'node:fs/promises';
import path from 'node:path';

const MAX_NOTE_BYTES = 200_000; // read_note cap
const MAX_SCAN_BYTES = 1_000_000; // skip giant files while searching

export class Vault {
  /**
   * @param {object} opts
   * @param {string} opts.root      absolute vault path
   * @param {string[]} opts.allow   top-level folders or root files that may be served (e.g. "Projects", "Now.md")
   * @param {string[]} opts.deny    sub-paths inside allowed folders that stay hidden (e.g. "Team/Finance Clerk")
   * @param {string} [opts.timeZone] IANA zone for "modified" timestamps (default UTC)
   */
  constructor({ root, allow, deny = [], timeZone = 'UTC' }) {
    this.stamp = makeStamper(timeZone);
    if (!root || !path.isAbsolute(root)) throw new Error('Vault root must be an absolute path');
    this.root = path.resolve(root);
    this.allow = allow.map(norm).filter(Boolean);
    this.all = this.allow.includes('*'); // "*" = every non-hidden Markdown note in the vault
    this.deny = deny.map(norm).filter(Boolean);
    if (this.allow.length === 0) throw new Error('Vault allowlist is empty');
  }

  /** True when a vault-relative POSIX path may be served. */
  isAllowed(rel) {
    const p = norm(rel);
    if (!p || p.startsWith('..') || path.posix.isAbsolute(p)) return false;
    if (p.split('/').some((seg) => seg.startsWith('.') || seg === '')) return false; // .obsidian, .trash, dotfiles
    const inAllow = this.all || this.allow.some((a) => p === a || p.startsWith(a + '/'));
    const inDeny = this.deny.some((d) => p === d || p.startsWith(d + '/'));
    return inAllow && !inDeny;
  }

  /**
   * Resolve a client-supplied note path to an absolute file path, or throw.
   * Blocks traversal, non-Markdown files, hidden paths, denied folders and symlinks that leave the allowlist.
   */
  async resolveNote(rel) {
    if (typeof rel !== 'string' || rel.length === 0 || rel.length > 512 || rel.includes('\0')) {
      throw new VaultError('Invalid path');
    }
    const clean = norm(rel);
    if (!clean.toLowerCase().endsWith('.md')) throw new VaultError('Only Markdown notes (.md) can be read');
    if (!this.isAllowed(clean)) throw new VaultError('Note not found or not shared');
    const abs = path.resolve(this.root, clean);
    let real;
    try {
      real = await fs.realpath(abs);
    } catch {
      throw new VaultError('Note not found or not shared');
    }
    const relReal = path.relative(this.root, real).split(path.sep).join('/');
    if (relReal.startsWith('..') || !this.isAllowed(relReal)) throw new VaultError('Note not found or not shared');
    const st = await fs.stat(real);
    if (!st.isFile()) throw new VaultError('Note not found or not shared');
    return { abs: real, rel: relReal, stat: st };
  }

  /** All shared notes: [{ path, modified, bytes }], newest first. */
  async listNotes(folder) {
    const out = [];
    const prefix = folder ? norm(folder) : '';
    if (prefix && !this.all && !this.allow.some((a) => prefix === a || prefix.startsWith(a + '/') || a.startsWith(prefix + '/'))) {
      return out;
    }
    await this.#walk('', out);
    const filtered = prefix ? out.filter((n) => n.path === prefix || n.path.startsWith(prefix + '/')) : out;
    return filtered.sort((a, b) => b.modified.localeCompare(a.modified));
  }

  async readNote(rel) {
    const { abs, rel: r, stat } = await this.resolveNote(rel);
    const fh = await fs.open(abs, 'r');
    try {
      const len = Math.min(stat.size, MAX_NOTE_BYTES);
      const buf = Buffer.alloc(len);
      await fh.read(buf, 0, len, 0);
      return {
        path: r,
        modified: this.stamp(stat.mtime),
        bytes: stat.size,
        truncated: stat.size > MAX_NOTE_BYTES,
        content: buf.toString('utf8'),
      };
    } finally {
      await fh.close();
    }
  }

  /** Case-insensitive search over note paths and contents. All words must match. */
  async search(query, { folder, limit = 10 } = {}) {
    const words = String(query || '')
      .toLowerCase()
      .split(/\s+/)
      .filter(Boolean)
      .slice(0, 12);
    if (words.length === 0) return [];
    const notes = await this.listNotes(folder);
    const hits = [];
    for (const n of notes) {
      if (n.bytes > MAX_SCAN_BYTES) continue;
      let text;
      try {
        text = await fs.readFile(path.join(this.root, n.path), 'utf8');
      } catch {
        continue;
      }
      const hay = (n.path + '\n' + text).toLowerCase();
      if (!words.every((w) => hay.includes(w))) continue;
      let score = 0;
      for (const w of words) {
        score += countOccurrences(hay, w);
        if (n.path.toLowerCase().includes(w)) score += 10;
      }
      hits.push({ path: n.path, modified: n.modified, score, snippet: snippet(text, words) });
    }
    hits.sort((a, b) => b.score - a.score || b.modified.localeCompare(a.modified));
    return hits.slice(0, Math.max(1, Math.min(limit, 25)));
  }

  async recentChanges(days = 7) {
    const since = Date.now() - Math.max(1, Math.min(days, 90)) * 86_400_000;
    const notes = await this.listNotes();
    return notes.filter((n) => Date.parse(n.modified) >= since);
  }

  async #walk(relDir, out) {
    const dirAbs = path.join(this.root, relDir);
    let entries;
    try {
      entries = await fs.readdir(dirAbs, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (e.name.startsWith('.')) continue;
      const rel = relDir ? `${relDir}/${e.name}` : e.name;
      if (e.isSymbolicLink()) continue; // never follow links while listing
      if (e.isDirectory()) {
        // descend only if something under this folder could be allowed
        const couldMatch = this.all || this.allow.some((a) => a === rel || a.startsWith(rel + '/') || rel.startsWith(a + '/'));
        const denied = this.deny.some((d) => rel === d || rel.startsWith(d + '/'));
        if (couldMatch && !denied) await this.#walk(rel, out);
      } else if (e.isFile() && e.name.toLowerCase().endsWith('.md') && this.isAllowed(rel)) {
        const st = await fs.stat(path.join(this.root, rel));
        out.push({ path: rel, modified: this.stamp(st.mtime), bytes: st.size });
      }
    }
  }
}

export class VaultError extends Error {}

/**
 * Returns (date) => ISO 8601 string in the given zone with its UTC offset,
 * e.g. "2026-11-26T02:03:00+08:00" for Asia/Manila. Sorts correctly within one fixed-offset zone.
 */
export function makeStamper(timeZone = 'UTC') {
  try {
    new Intl.DateTimeFormat('en-US', { timeZone });
  } catch {
    console.error(`Unknown time zone "${timeZone}", using UTC`);
    timeZone = 'UTC';
  }
  const fmt = new Intl.DateTimeFormat('en-US', {
    timeZone, hourCycle: 'h23', year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  });
  return (date) => {
    const d = date instanceof Date ? date : new Date(date);
    const p = Object.fromEntries(fmt.formatToParts(d).map((x) => [x.type, x.value]));
    const asUtc = Date.UTC(+p.year, +p.month - 1, +p.day, +p.hour, +p.minute, +p.second);
    const offMin = Math.round((asUtc - Math.floor(d.getTime() / 1000) * 1000) / 60000);
    const sign = offMin >= 0 ? '+' : '-';
    const abs = Math.abs(offMin);
    const off = offMin === 0 ? 'Z' : `${sign}${String(Math.floor(abs / 60)).padStart(2, '0')}:${String(abs % 60).padStart(2, '0')}`;
    return `${p.year}-${p.month}-${p.day}T${p.hour}:${p.minute}:${p.second}${off}`;
  };
}

function norm(p) {
  return String(p ?? '')
    .replace(/\\/g, '/')
    .replace(/^\.\/+/, '')
    .replace(/\/+/g, '/')
    .replace(/\/$/, '')
    .trim();
}

function countOccurrences(hay, w) {
  let n = 0;
  let i = hay.indexOf(w);
  while (i !== -1 && n < 1000) {
    n++;
    i = hay.indexOf(w, i + w.length);
  }
  return n;
}

function snippet(text, words) {
  const lower = text.toLowerCase();
  let at = -1;
  for (const w of words) {
    at = lower.indexOf(w);
    if (at !== -1) break;
  }
  if (at === -1) return text.slice(0, 200).replace(/\s+/g, ' ').trim();
  const start = Math.max(0, at - 100);
  const end = Math.min(text.length, at + 200);
  return (start > 0 ? '…' : '') + text.slice(start, end).replace(/\s+/g, ' ').trim() + (end < text.length ? '…' : '');
}
