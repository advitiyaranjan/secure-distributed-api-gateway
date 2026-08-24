// Service-to-service request signing.
//
// Backends sit on a private Docker network, but we still don't trust the network:
// every request a backend accepts must carry an HMAC-SHA256 signature produced by
// the gateway (or a peer service) over the method, path, body hash, timestamp and
// the caller identity. That means a compromised container on the same network
// cannot forge `x-user-roles: admin`, and a captured request can't be replayed
// outside a short time window or altered in transit.
import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

export const H = {
  timestamp: 'x-internal-timestamp',
  signature: 'x-internal-signature',
  userId: 'x-user-id',
  roles: 'x-user-roles',
  scopes: 'x-user-scopes',
  clientId: 'x-client-id',
  requestId: 'x-request-id',
};

export const IDENTITY_HEADERS = [H.timestamp, H.signature, H.userId, H.roles, H.scopes, H.clientId];

export function sha256Hex(data) {
  return createHash('sha256').update(data ?? '').digest('hex');
}

function canonicalString({ timestamp, method, path, bodyHash, identity, requestId }) {
  return [
    timestamp,
    method.toUpperCase(),
    path,
    bodyHash,
    identity.sub ?? '',
    (identity.roles ?? []).join(','),
    (identity.scopes ?? []).join(' '),
    identity.clientId ?? '',
    requestId ?? '',
  ].join('\n');
}

function hmac(secret, value) {
  return createHmac('sha256', secret).update(value).digest('hex');
}

/**
 * Returns the headers to attach to an internal request.
 * `path` must be exactly what goes on the wire (pathname + search).
 */
export function signInternalRequest({ secret, method, path, body, identity = {}, requestId, now = Date.now() }) {
  if (!secret) throw new Error('INTERNAL_SECRET is not configured');
  const timestamp = String(now);
  const signature = hmac(secret, canonicalString({
    timestamp, method, path, bodyHash: sha256Hex(body ?? ''), identity, requestId,
  }));
  const headers = { [H.timestamp]: timestamp, [H.signature]: signature };
  if (identity.sub) headers[H.userId] = identity.sub;
  if (identity.roles?.length) headers[H.roles] = identity.roles.join(',');
  if (identity.scopes?.length) headers[H.scopes] = identity.scopes.join(' ');
  if (identity.clientId) headers[H.clientId] = identity.clientId;
  if (requestId) headers[H.requestId] = requestId;
  return headers;
}

export function verifyInternalRequest(req, secret, { maxSkewMs = 30_000, now = Date.now() } = {}) {
  const timestamp = req.headers[H.timestamp];
  const signature = req.headers[H.signature];
  if (!timestamp || !signature) return { ok: false, reason: 'missing signature' };

  const ts = Number(timestamp);
  if (!Number.isFinite(ts) || Math.abs(now - ts) > maxSkewMs) return { ok: false, reason: 'stale or invalid timestamp' };

  const identity = {
    sub: req.headers[H.userId] || undefined,
    roles: (req.headers[H.roles] || '').split(',').filter(Boolean),
    scopes: (req.headers[H.scopes] || '').split(' ').filter(Boolean),
    clientId: req.headers[H.clientId] || undefined,
  };
  const expected = hmac(secret, canonicalString({
    timestamp,
    method: req.method,
    path: req.originalUrl,
    bodyHash: sha256Hex(req.rawBody ?? ''),
    identity,
    requestId: req.headers[H.requestId],
  }));

  const a = Buffer.from(expected, 'hex');
  const b = Buffer.from(String(signature), 'hex');
  if (a.length !== b.length || !timingSafeEqual(a, b)) return { ok: false, reason: 'bad signature' };
  return { ok: true, identity };
}

/** Body-parser `verify` hook: keeps the raw bytes so the signature can cover the body. */
export function captureRawBody(req, _res, buf) {
  req.rawBody = buf;
}

/**
 * Express middleware: rejects anything not signed by a trusted internal caller.
 * `exempt` lists path prefixes (e.g. health probes, JWKS) that are public by design.
 */
export function requireInternal({ secret, logger, exempt = [] }) {
  if (!secret) throw new Error('INTERNAL_SECRET is not configured');
  return (req, res, next) => {
    if (exempt.some((p) => req.path === p || req.path.startsWith(p.endsWith('/') ? p : `${p}/`))) return next();
    const result = verifyInternalRequest(req, secret);
    if (!result.ok) {
      logger?.warn('rejected unsigned internal request', {
        reason: result.reason, method: req.method, path: req.path, ip: req.socket.remoteAddress,
      });
      return res.status(401).json({ error: 'unauthorized', message: 'Requests must come through the API gateway' });
    }
    req.identity = result.identity;
    next();
  };
}
