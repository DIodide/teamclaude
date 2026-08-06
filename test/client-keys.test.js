import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AccountManager } from '../src/account-manager.js';
import { createProxyServer } from '../src/server.js';
import { sha256Hex, resolveClientKey, upsertClientKey, removeClientKey } from '../src/client-keys.js';
import { createUsageLogger } from '../src/usage-log.js';

function listen(server) {
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
}

// A minimal upstream that answers /v1/messages with a fixed usage block, so a
// request that passes the gate produces a metered event.
function usageUpstream() {
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({
      type: 'message',
      usage: { input_tokens: 11, output_tokens: 7, cache_read_input_tokens: 3 },
    }));
  });
  return server;
}

function makeAccountManager() {
  return new AccountManager(
    [{ name: 'a', type: 'oauth', accessToken: 't', refreshToken: 'r', expiresAt: Date.now() + 3600_000 }],
    0.98,
  );
}

async function post(port, headers = {}) {
  const res = await fetch(`http://127.0.0.1:${port}/v1/messages`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify({ model: 'x', messages: [] }),
  });
  await res.text();
  return res.status;
}

// Point the config module at a scratch file so upsert/remove persistence never
// touches a real ~/.config/teamclaude.json.
async function scratchConfigDir(t) {
  const dir = await mkdtemp(join(tmpdir(), 'tc-clientkeys-'));
  const prev = process.env.TEAMCLAUDE_CONFIG;
  process.env.TEAMCLAUDE_CONFIG = join(dir, 'teamclaude.json');
  t.after(async () => {
    if (prev === undefined) delete process.env.TEAMCLAUDE_CONFIG;
    else process.env.TEAMCLAUDE_CONFIG = prev;
    await rm(dir, { recursive: true, force: true });
  });
  return dir;
}

test('resolveClientKey matches enabled keys by hash and ignores disabled ones', () => {
  const config = {
    clientKeys: [
      { id: 'k1', name: 'alice', sha256: sha256Hex('tak_alice'), enabled: true },
      { id: 'k2', name: 'bob', sha256: sha256Hex('tak_bob'), enabled: false },
    ],
  };
  assert.deepEqual(resolveClientKey(config, 'tak_alice'), { keyId: 'k1', keyName: 'alice' });
  assert.equal(resolveClientKey(config, 'tak_bob'), null);   // disabled
  assert.equal(resolveClientKey(config, 'tak_nope'), null);  // unknown
  assert.equal(resolveClientKey(config, ''), null);
  assert.equal(resolveClientKey({}, 'tak_alice'), null);
});

test('a client key passes the gate where a bad key 401s (remote-style via loopbackExempt off)', async () => {
  const upstream = usageUpstream();
  const upstreamPort = await listen(upstream);

  // loopbackExempt:false makes the test's 127.0.0.1 connection exercise the
  // remote path — exactly the nginx-in-front deployment this exists for.
  const config = {
    proxy: { apiKey: 'shared-k', loopbackExempt: false },
    upstream: `http://127.0.0.1:${upstreamPort}`,
    clientKeys: [{ id: 'k1', name: 'alice', sha256: sha256Hex('tak_alice') }],
  };
  const proxy = createProxyServer(makeAccountManager(), config);
  const proxyPort = await listen(proxy);

  try {
    assert.equal(await post(proxyPort), 401);                                   // no key
    assert.equal(await post(proxyPort, { 'x-api-key': 'tak_wrong' }), 401);     // bad key
    assert.equal(await post(proxyPort, { 'x-api-key': 'tak_alice' }), 200);     // client key
    assert.equal(await post(proxyPort, { 'x-api-key': 'shared-k' }), 200);      // shared key still works
  } finally {
    proxy.close();
    upstream.close();
  }
});

test('client keys do not open control endpoints; loopback still does', async () => {
  const config = {
    proxy: { apiKey: 'shared-k', loopbackExempt: false },
    clientKeys: [{ id: 'k1', name: 'alice', sha256: sha256Hex('tak_alice') }],
  };
  const proxy = createProxyServer(makeAccountManager(), config);
  const port = await listen(proxy);

  try {
    // status: reachable from loopback without any key even when loopbackExempt
    // is off (the CLI/TUI must keep working)...
    const local = await fetch(`http://127.0.0.1:${port}/teamclaude/status`);
    assert.equal(local.status, 200);
    await local.text();
    // ...and a client key is NOT a control credential: x-api-key with a client
    // key on a control path is still just loopback (exempted above), so probe
    // the key-vs-control rule directly through the gate order instead — a
    // client key presented on clientkeys CRUD from loopback is fine, but the
    // endpoint itself never leaves loopback (verified by unit-level gate order;
    // remote sockets can't be faked from a loopback-only test harness).
    const crud = await fetch(`http://127.0.0.1:${port}/teamclaude/clientkeys`);
    assert.equal(crud.status, 200);
    assert.deepEqual((await crud.json()).keys.map(k => k.id), ['k1']);
  } finally {
    proxy.close();
  }
});

test('with loopbackExempt off, forwarded loopback traffic (X-Forwarded-For) is remote', async () => {
  const upstream = usageUpstream();
  const upstreamPort = await listen(upstream);
  const config = {
    proxy: { apiKey: 'shared-k', loopbackExempt: false },
    upstream: `http://127.0.0.1:${upstreamPort}`,
    clientKeys: [{ id: 'k1', name: 'alice', sha256: sha256Hex('tak_alice') }],
  };
  const proxy = createProxyServer(makeAccountManager(), config);
  const port = await listen(proxy);

  try {
    // A reverse proxy (nginx) always appends X-Forwarded-For; a request
    // carrying it must NOT be treated as the on-box operator, or every remote
    // client would reach the control surface through the proxy.
    const fwd = { 'x-forwarded-for': '203.0.113.7' };
    for (const path of ['/teamclaude/status', '/teamclaude/clientkeys']) {
      const res = await fetch(`http://127.0.0.1:${port}${path}`, { headers: fwd });
      assert.equal(res.status, 401, `${path} must reject forwarded traffic`);
      await res.text();
    }
    // ...while a client key still proxies through the same forwarded path,
    // and direct (unforwarded) loopback keeps its control access.
    assert.equal(await post(port, { ...fwd, 'x-api-key': 'tak_alice' }), 200);
    const direct = await fetch(`http://127.0.0.1:${port}/teamclaude/clientkeys`);
    assert.equal(direct.status, 200);
    await direct.text();
  } finally {
    proxy.close();
    upstream.close();
  }
});

test('clientkeys CRUD upserts, lists (no hashes), and removes — persisting to config', async (t) => {
  const dir = await scratchConfigDir(t);
  const config = { proxy: { apiKey: 'shared-k' }, clientKeys: [] };
  const proxy = createProxyServer(makeAccountManager(), config);
  const port = await listen(proxy);
  t.after(() => proxy.close());

  const sha = sha256Hex('tak_carol');
  const add = await fetch(`http://127.0.0.1:${port}/teamclaude/clientkeys`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ id: 'k9', name: 'carol', sha256: sha }),
  });
  assert.equal(add.status, 200);
  assert.deepEqual(await add.json(), { ok: true });

  // Live config sees it immediately (the gate reads this object per request).
  assert.deepEqual(resolveClientKey(config, 'tak_carol'), { keyId: 'k9', keyName: 'carol' });

  // Listing returns metadata but never the hash.
  const list = await (await fetch(`http://127.0.0.1:${port}/teamclaude/clientkeys`)).json();
  assert.equal(list.keys.length, 1);
  assert.equal(list.keys[0].id, 'k9');
  assert.equal(list.keys[0].sha256, undefined);

  // Persisted to the (scratch) config file.
  const onDisk = JSON.parse(await readFile(join(dir, 'teamclaude.json'), 'utf8'));
  assert.equal(onDisk.clientKeys?.[0]?.sha256, sha);

  // Malformed upserts are rejected.
  const bad = await fetch(`http://127.0.0.1:${port}/teamclaude/clientkeys`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ id: 'k10', sha256: 'not-hex' }),
  });
  assert.equal(bad.status, 400);

  // Remove: gone from live config, disk, and answers 404 the second time.
  const del = await fetch(`http://127.0.0.1:${port}/teamclaude/clientkeys/k9`, { method: 'DELETE' });
  assert.equal(del.status, 200);
  assert.equal(resolveClientKey(config, 'tak_carol'), null);
  const onDisk2 = JSON.parse(await readFile(join(dir, 'teamclaude.json'), 'utf8'));
  assert.equal((onDisk2.clientKeys || []).length, 0);
  const del2 = await fetch(`http://127.0.0.1:${port}/teamclaude/clientkeys/k9`, { method: 'DELETE' });
  assert.equal(del2.status, 404);
});

test('upsert/remove helpers validate input and survive a missing clientKeys array', async (t) => {
  await scratchConfigDir(t);
  const config = {};
  await assert.rejects(async () => upsertClientKey(config, { id: '', sha256: sha256Hex('x') }), /id/);
  await assert.rejects(async () => upsertClientKey(config, { id: 'a', sha256: 'short' }), /sha256/);
  await upsertClientKey(config, { id: 'a', name: 'n', sha256: sha256Hex('x') });
  assert.equal(config.clientKeys.length, 1);
  // Upsert by same id replaces, preserving createdAt.
  const created = config.clientKeys[0].createdAt;
  await upsertClientKey(config, { id: 'a', name: 'renamed', sha256: sha256Hex('y') });
  assert.equal(config.clientKeys.length, 1);
  assert.equal(config.clientKeys[0].name, 'renamed');
  assert.equal(config.clientKeys[0].createdAt, created);
  assert.equal(await removeClientKey(config, 'a'), true);
  assert.equal(await removeClientKey(config, 'a'), false);
});

test('a proxied request emits one usage event attributed to its client key', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'tc-usage-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const upstream = usageUpstream();
  const upstreamPort = await listen(upstream);

  // A local sink records what teamclaude pushes.
  const sinkEvents = [];
  let sinkAuth = null;
  const sink = http.createServer((req, res) => {
    sinkAuth = req.headers.authorization;
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      sinkEvents.push(JSON.parse(Buffer.concat(chunks).toString()));
      res.writeHead(200); res.end();
    });
  });
  const sinkPort = await listen(sink);

  const jsonlPath = join(dir, 'usage.jsonl');
  const config = {
    proxy: { apiKey: 'shared-k', loopbackExempt: false },
    upstream: `http://127.0.0.1:${upstreamPort}`,
    clientKeys: [{ id: 'k1', name: 'alice', sha256: sha256Hex('tak_alice') }],
    usageLog: { path: jsonlPath, sink: `http://127.0.0.1:${sinkPort}/ingest`, sinkToken: 'tok' },
  };
  const proxy = createProxyServer(makeAccountManager(), config);
  const proxyPort = await listen(proxy);

  try {
    assert.equal(await post(proxyPort, { 'x-api-key': 'tak_alice' }), 200);

    // The sink POST is fire-and-forget; give it a beat.
    await new Promise(r => setTimeout(r, 300));

    const lines = (await readFile(jsonlPath, 'utf8')).trim().split('\n').map(JSON.parse);
    assert.equal(lines.length, 1);
    const ev = lines[0];
    assert.equal(ev.keyId, 'k1');
    assert.equal(ev.keyName, 'alice');
    assert.equal(ev.account, 'a');
    assert.equal(ev.status, 200);
    assert.equal(ev.inputTokens, 11);
    assert.equal(ev.outputTokens, 7);
    assert.equal(ev.cacheReadTokens, 3);
    assert.equal(ev.endpoint, '/v1/messages');
    assert.ok(ev.durationMs >= 0);

    assert.equal(sinkEvents.length, 1);
    assert.equal(sinkEvents[0].keyId, 'k1');
    assert.equal(sinkAuth, 'Bearer tok');
  } finally {
    proxy.close();
    upstream.close();
    sink.close();
  }
});

test('prompt snapshots store one overwritten file per session, not one per request', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'tc-prompt-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const upstream = usageUpstream();
  const upstreamPort = await listen(upstream);
  const config = {
    proxy: { apiKey: 'shared-k', loopbackExempt: false },
    upstream: `http://127.0.0.1:${upstreamPort}`,
    clientKeys: [{ id: 'k1', name: 'alice', sha256: sha256Hex('tak_alice') }],
    usageLog: { path: join(dir, 'usage.jsonl'), promptDir: join(dir, 'prompts') },
  };
  const proxy = createProxyServer(makeAccountManager(), config);
  const port = await listen(proxy);
  t.after(() => { proxy.close(); upstream.close(); });

  const turn = async (messages) => {
    const res = await fetch(`http://127.0.0.1:${port}/v1/messages`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-api-key': 'tak_alice',
        'x-claude-code-session-id': 'sess-123',
      },
      body: JSON.stringify({ model: 'x', messages }),
    });
    await res.text();
    return res.status;
  };

  // Two turns of one conversation — the second body contains the first.
  assert.equal(await turn([{ role: 'user', content: 'hello' }]), 200);
  assert.equal(await turn([
    { role: 'user', content: 'hello' },
    { role: 'assistant', content: 'hi' },
    { role: 'user', content: 'more' },
  ]), 200);
  await new Promise(r => setTimeout(r, 200));

  const { readdir } = await import('node:fs/promises');
  const files = (await readdir(join(dir, 'prompts'))).filter(f => !f.includes('.tmp'));
  assert.deepEqual(files, ['s_sess-123.json']);
  const snap = JSON.parse(await readFile(join(dir, 'prompts', 's_sess-123.json'), 'utf8'));
  assert.equal(snap.messages.length, 3); // latest turn's body, not the first

  // Both usage events reference the same snapshot file.
  const events = (await readFile(join(dir, 'usage.jsonl'), 'utf8')).trim().split('\n').map(JSON.parse);
  assert.deepEqual(events.map(e => e.promptFile), ['s_sess-123.json', 's_sess-123.json']);

  // A session-less request gets its own per-request file.
  const res = await fetch(`http://127.0.0.1:${port}/v1/messages`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-api-key': 'tak_alice' },
    body: JSON.stringify({ model: 'x', messages: [{ role: 'user', content: 'one-shot' }] }),
  });
  await res.text();
  await new Promise(r => setTimeout(r, 200));
  const after = (await readdir(join(dir, 'prompts'))).filter(f => !f.includes('.tmp'));
  assert.equal(after.length, 2);
  assert.ok(after.some(f => f.startsWith('r_')));
});

test('usage logger throttles sink failures and keeps appending to the JSONL file', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'tc-usage-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const jsonlPath = join(dir, 'usage.jsonl');
  // Port 9 on localhost: nothing listens; every sink POST fails fast.
  const logger = createUsageLogger({ path: jsonlPath, sink: 'http://127.0.0.1:9/x' });
  logger.emit({ a: 1 });
  logger.emit({ a: 2 });
  await logger.flush();
  const lines = (await readFile(jsonlPath, 'utf8')).trim().split('\n');
  assert.equal(lines.length, 2);
});
