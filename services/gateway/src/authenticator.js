// Bearer token validation. Tokens are RS256 JWTs signed by auth-service; the
// gateway only holds the public keys (fetched from JWKS, cached, and re-fetched
// on an unknown `kid`, so key rotation needs no gateway restart).
import { createRemoteJWKSet, errors, jwtVerify } from 'jose';

const BEARER_RE = /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/;

export function createAuthenticator({ jwksUrl, issuer, audience, redis, logger, revocationFailOpen = false }) {
  const jwks = createRemoteJWKSet(new URL(jwksUrl), {
    timeoutDuration: 3000,
    cooldownDuration: 30_000,
    cacheMaxAge: 10 * 60_000,
  });

  /**
   * Never throws. Returns {} (no credentials), { identity }, or { error, status }.
   * Errors are deferred so rate limiting can still apply to requests with bad tokens.
   */
  async function authenticate(header) {
    if (!header) return {};
    const match = BEARER_RE.exec(header);
    if (!match) return { error: 'Malformed Authorization header, expected Bearer token', status: 401 };

    let payload;
    try {
      ({ payload } = await jwtVerify(match[1], jwks, {
        issuer,
        audience,
        algorithms: ['RS256'], // pinned: rejects alg=none and HS256 key-confusion attacks
        typ: 'at+jwt',
        clockTolerance: 5,
        requiredClaims: ['sub', 'jti', 'exp', 'iat'],
      }));
    } catch (err) {
      if (err instanceof errors.JWKSTimeout || err.code === 'ERR_JWKS_TIMEOUT' || err.cause?.code === 'ECONNREFUSED' || err.name === 'TypeError') {
        logger.error('cannot fetch JWKS from auth-service', { err });
        return { error: 'Token validation temporarily unavailable', status: 503 };
      }
      return { error: err instanceof errors.JWTExpired ? 'Token expired' : 'Invalid token', status: 401 };
    }

    try {
      if (await redis.exists(`revoked:jti:${payload.jti}`)) return { error: 'Token has been revoked', status: 401 };
    } catch (err) {
      logger.error('revocation check failed', { err: err.message });
      if (!revocationFailOpen) return { error: 'Token validation temporarily unavailable', status: 503 };
    }

    return {
      identity: {
        sub: payload.sub,
        roles: Array.isArray(payload.roles) ? payload.roles.map(String) : [],
        scopes: typeof payload.scope === 'string' ? payload.scope.split(' ').filter(Boolean) : [],
        clientId: payload.client_id,
        jti: payload.jti,
      },
    };
  }

  return { authenticate, ping: () => jwks.reload?.() };
}
