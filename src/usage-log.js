// Per-request usage events, for metering client-key traffic (src/client-keys.js).
// Two destinations, both optional, both driven by `usageLog` in config:
//
//   "usageLog": {
//     "path": "/var/lib/teamclaude/usage.jsonl",            // durable JSONL append
//     "sink": "http://127.0.0.1:3000/api/internal/usage",   // fire-and-forget POST
//     "sinkToken": "..."                                    // sent as `authorization: Bearer <token>`
//   }
//
// The JSONL file is the durable record — a consumer that was down replays it.
// The sink is a convenience push so a local dashboard sees events live. A sink
// failure therefore only costs liveness, never data: it is logged (throttled to
// avoid one error line per proxied request while the consumer is down) and
// otherwise ignored. Nothing here ever blocks or fails the proxied request.
//
// One event per proxied request:
//
//   { "ts", "keyId", "keyName", "model", "upstreamModel", "account", "status",
//     "durationMs", "inputTokens", "outputTokens", "cacheReadTokens",
//     "cacheCreationTokens", "stream", "endpoint", "sessionId" }
//
// `keyId` is null for requests admitted without a client key (loopback-exempt
// or the shared proxy apiKey).

import { appendFile, mkdir, writeFile, rename } from 'node:fs/promises';
import { dirname, join } from 'node:path';

// One logger per config object: both the base-URL listener and every MITM
// terminating server share the same live config, so they share one append chain
// and one sink-failure throttle instead of interleaving.
const loggers = new WeakMap();

export function getUsageLogger(config) {
  const settings = config?.usageLog;
  if (!settings || (!settings.path && !settings.sink)) return null;
  let logger = loggers.get(config);
  if (!logger) {
    logger = createUsageLogger(settings);
    loggers.set(config, logger);
  }
  return logger;
}

export function createUsageLogger({ path, sink, sinkToken } = {}) {
  // Appends are chained so concurrent completions can't interleave partial lines.
  let writeChain = Promise.resolve();
  let dirReady = null;
  let sinkFailures = 0;

  const emit = (event) => {
    const line = JSON.stringify(event);

    if (path) {
      dirReady ||= mkdir(dirname(path), { recursive: true }).catch(() => {});
      writeChain = writeChain
        .then(() => dirReady)
        .then(() => appendFile(path, line + '\n'))
        .catch((err) => console.error(`[TeamClaude] usage log write failed: ${err.message}`));
    }

    if (sink) {
      const headers = { 'content-type': 'application/json' };
      if (sinkToken) headers.authorization = `Bearer ${sinkToken}`;
      fetch(sink, { method: 'POST', headers, body: line, signal: AbortSignal.timeout(3000) })
        .then((res) => {
          if (!res.ok) throw new Error(`sink answered ${res.status}`);
          sinkFailures = 0;
        })
        .catch((err) => {
          if (sinkFailures++ % 100 === 0) {
            console.error(`[TeamClaude] usage sink unreachable (${err.message}) — events still land in the JSONL log`);
          }
        });
    }

    return writeChain;
  };

  // flush() lets tests (and a graceful shutdown) await pending appends.
  return { emit, flush: () => writeChain };
}

// Prompt snapshots (`usageLog.promptDir`): one file per CONVERSATION, not per
// request. Claude Code resends the whole conversation on every turn, so
// logging each request body stores the same transcript again and again —
// O(turns²) disk for one session. Instead the snapshot for a session is
// OVERWRITTEN each turn: the newest body already contains everything before
// it, so one copy per conversation is the complete record. Requests without a
// session id (one-shot API calls) get a per-request file — there is no larger
// conversation to fold them into.
//
// Written atomically (tmp + rename) so a reader never sees a torn file. The
// filename is returned synchronously so the usage event can reference it;
// the write itself is fire-and-forget and never blocks the request.

const promptFileName = (sessionId, reqId) => (sessionId
  ? `s_${String(sessionId).replace(/[^A-Za-z0-9_-]/g, '')}.json`
  : `r_${String(reqId).padStart(5, '0')}_${Date.now()}.json`);

let promptDirReady = null;
let tmpCounter = 0;

export function writePromptSnapshot(config, { sessionId, reqId, body }) {
  const dir = config?.usageLog?.promptDir;
  if (!dir || !body?.length) return null;
  const filename = promptFileName(sessionId, reqId);
  const path = join(dir, filename);
  // Unique tmp per call: two concurrent turns of the same session must not
  // share a tmp file, or one rename strands the other.
  const tmp = `${path}.tmp${process.pid}-${++tmpCounter}`;
  promptDirReady ||= mkdir(dir, { recursive: true }).catch(() => {});
  promptDirReady
    .then(() => writeFile(tmp, body, { mode: 0o600 }))
    .then(() => rename(tmp, path))
    .catch((err) => console.error(`[TeamClaude] prompt snapshot write failed: ${err.message}`));
  return filename;
}
