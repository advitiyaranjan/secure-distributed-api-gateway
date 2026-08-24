// Forwards a request to an upstream service.
//  - strips hop-by-hop headers and anything a client could use to spoof identity
//  - adds X-Forwarded-*, the request id, and an HMAC signature over the request
//  - enforces a timeout, retries idempotent requests once on network errors,
//    and reports outcomes to the upstream's circuit breaker
import { IDENTITY_HEADERS, signInternalRequest } from '../../../shared/internal-auth.js';

const HOP_BY_HOP = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding',
  'upgrade', 'host', 'content-length', 'expect', 'accept-encoding', 'forwarded',
  'x-forwarded-for', 'x-forwarded-proto', 'x-forwarded-host', 'x-real-ip', 'cookie',
]);
const STRIP_RESPONSE = new Set(['connection', 'keep-alive', 'transfer-encoding', 'content-encoding', 'content-length', 'x-powered-by']);
const IDEMPOTENT = new Set(['GET', 'HEAD', 'OPTIONS', 'PUT', 'DELETE']);

export class UpstreamError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

export async function forward({ req, route, upstreamPath, body, identity, secret, timeoutMs, breaker }) {
  const url = new URL(upstreamPath, route.target);
  const wirePath = url.pathname + url.search;
  const method = req.method;
  const payload = method !== 'GET' && method !== 'HEAD' && body?.length ? body : undefined;

  const headers = {};
  for (const [name, value] of Object.entries(req.headers)) {
    if (HOP_BY_HOP.has(name) || IDENTITY_HEADERS.includes(name) || name === 'x-request-id') continue;
    if (name === 'authorization' && !route.forwardAuthorization) continue;
    headers[name] = Array.isArray(value) ? value.join(', ') : value;
  }
  headers['x-forwarded-for'] = req.ip;
  headers['x-forwarded-proto'] = req.secure ? 'https' : 'http';
  if (req.headers.host) headers['x-forwarded-host'] = req.headers.host;
  Object.assign(headers, signInternalRequest({
    secret,
    method,
    path: wirePath,
    body: payload,
    requestId: req.id,
    identity: identity ? { sub: identity.sub, roles: identity.roles, scopes: identity.scopes, clientId: identity.clientId } : {},
  }));

  if (!breaker.canRequest()) throw new UpstreamError(503, `Upstream ${route.name} is unavailable (circuit open)`);

  const attempts = IDEMPOTENT.has(method) ? 2 : 1;
  for (let attempt = 1; ; attempt += 1) {
    try {
      const res = await fetch(url, {
        method,
        headers,
        body: payload,
        redirect: 'manual',
        signal: AbortSignal.timeout(timeoutMs),
      });
      const buffer = Buffer.from(await res.arrayBuffer());
      if (res.status >= 500) breaker.onFailure();
      else breaker.onSuccess();
      return { status: res.status, headers: res.headers, body: buffer };
    } catch (err) {
      const timedOut = err.name === 'TimeoutError';
      if (!timedOut && attempt < attempts) continue;
      breaker.onFailure();
      throw new UpstreamError(timedOut ? 504 : 502, timedOut ? `Upstream ${route.name} timed out` : `Upstream ${route.name} unreachable`);
    }
  }
}

export function copyResponseHeaders(res, upstreamHeaders) {
  for (const [name, value] of upstreamHeaders) {
    if (!STRIP_RESPONSE.has(name)) res.setHeader(name, value);
  }
}
