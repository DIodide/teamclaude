// Per-client API keys: named keys that grant access to the PROXYING surface
// only — never the /teamclaude/ control endpoints, which stay bound to
// loopback (or the shared proxy apiKey, for status/reload). This is what lets
// one teamclaude serve a team: each person gets their own key, a key can be
// revoked without rotating everyone else's, and the usage log (src/usage-log.js)
// can attribute every request to the key that made it.
//
// Keys are stored as SHA-256 hashes in `config.clientKeys`, so the config file
// (which already holds account tokens) never holds the client keys themselves —
// whoever issued the key holds the only plaintext copy. Lookup hashes the
// presented key first and compares digests, so comparison time is independent
// of how much of any stored hash matches.

import { createHash, timingSafeEqual } from 'node:crypto';
import { atomicConfigUpdate } from './config.js';

export function sha256Hex(key) {
  return createHash('sha256').update(key, 'utf8').digest('hex');
}

// Volatile per-process "last seen" times, surfaced by the control API. Kept out
// of the config file on purpose: writing config on every request would churn a
// file that holds account tokens, for a datum the usage log already records
// durably.
const lastUsed = new Map();

/**
 * Resolve a presented key against `config.clientKeys`. Returns the matching
 * key's identity ({ keyId, keyName }) or null. Disabled and malformed entries
 * never match.
 */
export function resolveClientKey(config, presented) {
  const keys = config?.clientKeys;
  if (!Array.isArray(keys) || !keys.length || typeof presented !== 'string' || !presented) return null;
  const digest = Buffer.from(sha256Hex(presented), 'hex');
  for (const entry of keys) {
    if (!entry || entry.enabled === false) continue;
    if (typeof entry.sha256 !== 'string' || entry.sha256.length !== 64) continue;
    const stored = Buffer.from(entry.sha256, 'hex');
    if (stored.length !== digest.length) continue;
    if (timingSafeEqual(stored, digest)) {
      if (entry.id != null) lastUsed.set(entry.id, new Date().toISOString());
      return { keyId: entry.id ?? null, keyName: entry.name ?? null };
    }
  }
  return null;
}

/** Sanitized listing for the control API — hashes are never returned. */
export function listClientKeys(config) {
  return (config?.clientKeys || []).filter(Boolean).map((k) => ({
    id: k.id ?? null,
    name: k.name ?? null,
    enabled: k.enabled !== false,
    createdAt: k.createdAt ?? null,
    lastUsedAt: k.id != null ? (lastUsed.get(k.id) ?? null) : null,
  }));
}

// Upsert/remove mutate the LIVE config object first (the auth gate reads it per
// request, so the change takes effect immediately) and then persist the same
// change via atomicConfigUpdate, which re-reads the file — so a concurrent
// `teamclaude login` writing accounts is never clobbered, and vice versa.

/** Add or replace a key by id. `sha256` is the hex digest of the plaintext key. */
export function upsertClientKey(config, { id, name, sha256, enabled } = {}) {
  if (typeof id !== 'string' || !id) throw new Error('clientKey "id" is required');
  if (typeof sha256 !== 'string' || !/^[0-9a-f]{64}$/i.test(sha256)) {
    throw new Error('clientKey "sha256" must be a 64-char hex SHA-256 digest');
  }
  const apply = (cfg) => {
    const keys = (cfg.clientKeys ||= []);
    const i = keys.findIndex((k) => k?.id === id);
    keys[i >= 0 ? i : keys.length] = {
      id,
      name: typeof name === 'string' && name ? name : id,
      sha256: sha256.toLowerCase(),
      enabled: enabled !== false,
      createdAt: (i >= 0 && keys[i]?.createdAt) || new Date().toISOString(),
    };
  };
  apply(config);
  return atomicConfigUpdate(apply);
}

/** Remove a key by id. Resolves true if the live config had it. */
export function removeClientKey(config, id) {
  const existed = (config?.clientKeys || []).some((k) => k?.id === id);
  const apply = (cfg) => {
    if (Array.isArray(cfg.clientKeys)) cfg.clientKeys = cfg.clientKeys.filter((k) => k?.id !== id);
  };
  apply(config);
  lastUsed.delete(id);
  return atomicConfigUpdate(apply).then(() => existed);
}

/**
 * The `/teamclaude/clientkeys` control endpoint. The caller has already
 * verified the client is loopback — this endpoint both reveals key metadata and
 * mints access, so unlike status/reload the shared proxy apiKey does NOT open it.
 *
 *   GET    /teamclaude/clientkeys        → { keys: [...] } (no hashes)
 *   POST   /teamclaude/clientkeys        → upsert { id, name, sha256, enabled? }
 *   DELETE /teamclaude/clientkeys/<id>   → remove
 */
export async function handleClientKeysRequest(req, res, config) {
  const respond = (status, obj) => {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(obj));
  };
  const path = (req.url || '').split('?')[0];

  if (req.method === 'GET' && path === '/teamclaude/clientkeys') {
    return respond(200, { keys: listClientKeys(config) });
  }

  if (req.method === 'POST' && path === '/teamclaude/clientkeys') {
    const chunks = [];
    let size = 0;
    for await (const chunk of req) {
      size += chunk.length;
      if (size > 64 * 1024) return respond(413, { ok: false, error: 'body too large' });
      chunks.push(chunk);
    }
    let body;
    try {
      body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    } catch {
      return respond(400, { ok: false, error: 'invalid JSON body' });
    }
    try {
      await upsertClientKey(config, body);
    } catch (err) {
      return respond(400, { ok: false, error: err.message });
    }
    return respond(200, { ok: true });
  }

  const del = path.match(/^\/teamclaude\/clientkeys\/([^/]+)$/);
  if (req.method === 'DELETE' && del) {
    const removed = await removeClientKey(config, decodeURIComponent(del[1]));
    return removed
      ? respond(200, { ok: true })
      : respond(404, { ok: false, error: 'unknown key id' });
  }

  return respond(405, { ok: false, error: 'method not allowed' });
}
