// Structured JSON logger with centralized shipping.
//
// Every record is written to stdout (so `docker logs` / any log driver works) and,
// when LOG_COLLECTOR_URL is set, buffered and shipped in batches to the
// log-collector service over a signed internal request. Shipping is best-effort:
// a slow or dead collector never blocks request handling, and the buffer is
// bounded so memory can't grow without limit.
import { signInternalRequest } from './internal-auth.js';

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };

const REDACT = new Set([
  'password', 'authorization', 'cookie', 'set-cookie', 'token', 'access_token', 'refresh_token',
  'client_secret', 'code', 'code_verifier', 'shippingaddress', 'x-internal-signature',
]);

function redact(value, depth = 0) {
  if (value === null || typeof value !== 'object' || depth > 6) return value;
  if (Array.isArray(value)) return value.map((v) => redact(v, depth + 1));
  const out = {};
  for (const [k, v] of Object.entries(value)) {
    out[k] = REDACT.has(k.toLowerCase()) ? '[REDACTED]' : redact(v, depth + 1);
  }
  return out;
}

function serializeError(err) {
  return { name: err.name, message: err.message, code: err.code, stack: err.stack };
}

export function createLogger({
  service,
  level = process.env.LOG_LEVEL || 'info',
  collectorUrl = process.env.LOG_COLLECTOR_URL,
  internalSecret = process.env.INTERNAL_SECRET,
  flushIntervalMs = 2000,
  batchSize = 500,
  maxBuffer = 5000,
  stdout = process.stdout,
} = {}) {
  const threshold = LEVELS[level] ?? LEVELS.info;
  const shipping = Boolean(collectorUrl && internalSecret);
  let buffer = [];
  let flushing = false;
  let collectorUp = true;

  async function flush() {
    if (!shipping || flushing || buffer.length === 0) return;
    flushing = true;
    const batch = buffer.splice(0, batchSize);
    const body = JSON.stringify(batch);
    const path = '/ingest';
    try {
      const headers = signInternalRequest({
        secret: internalSecret, method: 'POST', path, body,
        identity: { sub: `service:${service}`, roles: ['service'], scopes: ['logs:write'] },
      });
      const res = await fetch(new URL(path, collectorUrl), {
        method: 'POST',
        headers: { ...headers, 'content-type': 'application/json' },
        body,
        signal: AbortSignal.timeout(3000),
      });
      if (!res.ok) throw new Error(`collector responded ${res.status}`);
      if (!collectorUp) process.stderr.write(`[${service}] log collector reachable again\n`);
      collectorUp = true;
    } catch (err) {
      // Put the batch back (newest records win if we're over capacity).
      buffer = batch.concat(buffer).slice(-maxBuffer);
      if (collectorUp) process.stderr.write(`[${service}] log shipping failed, buffering: ${err.message}\n`);
      collectorUp = false;
    } finally {
      flushing = false;
    }
  }

  const timer = shipping ? setInterval(flush, flushIntervalMs) : null;
  timer?.unref();

  function make(bindings) {
    function write(lvl, msg, fields = {}) {
      if (LEVELS[lvl] < threshold) return;
      const { err, ...rest } = fields;
      const record = { ts: new Date().toISOString(), level: lvl, service, msg, ...redact(bindings), ...redact(rest) };
      if (err instanceof Error) record.err = serializeError(err);
      else if (err !== undefined) record.err = err;
      stdout.write(`${JSON.stringify(record)}\n`);
      if (shipping) {
        buffer.push(record);
        if (buffer.length > maxBuffer) buffer.splice(0, buffer.length - maxBuffer);
      }
    }
    return {
      debug: (msg, f) => write('debug', msg, f),
      info: (msg, f) => write('info', msg, f),
      warn: (msg, f) => write('warn', msg, f),
      error: (msg, f) => write('error', msg, f),
      child: (extra) => make({ ...bindings, ...extra }),
      flush,
      async close() {
        if (timer) clearInterval(timer);
        await flush();
      },
    };
  }

  return make({});
}
