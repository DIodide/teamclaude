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

import { appendFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';

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
