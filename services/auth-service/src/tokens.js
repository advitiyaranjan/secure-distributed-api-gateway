import { randomUUID } from 'node:crypto';
import { SignJWT, jwtVerify } from 'jose';
import { randomToken, sha256 } from '../../../shared/crypto.js';

export class OAuthError extends Error {
  constructor(error, description, status = 400) {
    super(description);
    this.error = error;
    this.status = status;
  }
}

export function createTokenService({ db, redis, signingKey, issuer, audience, accessTtl, refreshTtl, logger }) {
  const stmts = {
    insertRefresh: db.prepare(`INSERT INTO refresh_tokens
      (token_hash, family_id, user_id, client_id, scopes, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`),
    getRefresh: db.prepare('SELECT * FROM refresh_tokens WHERE token_hash = ?'),
    revokeRefresh: db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ? AND revoked = 0'),
    revokeFamily: db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE family_id = ?'),
    purgeExpired: db.prepare('DELETE FROM refresh_tokens WHERE expires_at < ?'),
  };

  async function issueAccessToken({ sub, roles, scopes, clientId }) {
    const jti = randomUUID();
    const token = await new SignJWT({ roles, scope: scopes.join(' '), client_id: clientId })
      .setProtectedHeader({ alg: 'RS256', kid: signingKey.kid, typ: 'at+jwt' })
      .setIssuer(issuer)
      .setAudience(audience)
      .setSubject(sub)
      .setJti(jti)
      .setIssuedAt()
      .setExpirationTime(`${accessTtl}s`)
      .sign(signingKey.privateKey);
    return { token, jti };
  }

  function issueRefreshToken({ userId, clientId, scopes, familyId = randomUUID() }) {
    const raw = randomToken(32);
    const now = Math.floor(Date.now() / 1000);
    stmts.insertRefresh.run(sha256(raw), familyId, userId, clientId, JSON.stringify(scopes), now + refreshTtl, now);
    return raw;
  }

  /**
   * Refresh token rotation with reuse detection (OAuth 2.0 Security BCP §4.14).
   * A refresh token works once. If an already-used token shows up again, someone
   * has a stolen copy, so every token in that login's family is revoked.
   */
  function consumeRefreshToken(raw, clientId) {
    const row = stmts.getRefresh.get(sha256(raw));
    if (!row) throw new OAuthError('invalid_grant', 'Invalid refresh token');
    if (row.revoked) {
      stmts.revokeFamily.run(row.family_id);
      logger.warn('security: refresh token reuse detected, family revoked', {
        familyId: row.family_id, userId: row.user_id, clientId,
      });
      throw new OAuthError('invalid_grant', 'Refresh token has been revoked');
    }
    if (row.client_id !== clientId) throw new OAuthError('invalid_grant', 'Refresh token was issued to another client');
    if (row.expires_at < Date.now() / 1000) throw new OAuthError('invalid_grant', 'Refresh token expired');
    // Atomic check-and-set so two concurrent refreshes can't both succeed.
    if (stmts.revokeRefresh.run(row.token_hash).changes !== 1) {
      stmts.revokeFamily.run(row.family_id);
      throw new OAuthError('invalid_grant', 'Refresh token has been revoked');
    }
    return { userId: row.user_id, familyId: row.family_id, scopes: JSON.parse(row.scopes) };
  }

  function revokeRefreshToken(raw, clientId) {
    const row = stmts.getRefresh.get(sha256(raw));
    if (row && row.client_id === clientId) stmts.revokeFamily.run(row.family_id);
    return Boolean(row);
  }

  async function verifyAccessToken(token) {
    const { payload } = await jwtVerify(token, signingKey.publicKey, {
      issuer, audience, algorithms: ['RS256'], typ: 'at+jwt',
    });
    return payload;
  }

  /** Access tokens are stateless JWTs; revocation = deny-list the jti in Redis until it would expire anyway. */
  async function denylistAccessToken(payload) {
    const ttl = payload.exp - Math.floor(Date.now() / 1000);
    if (ttl > 0) await redis.set(`revoked:jti:${payload.jti}`, '1', 'EX', ttl);
  }

  async function isAccessTokenRevoked(jti) {
    return (await redis.exists(`revoked:jti:${jti}`)) === 1;
  }

  async function tokenResponse({ sub, roles, scopes, clientId, userId, familyId, withRefresh }) {
    const { token } = await issueAccessToken({ sub, roles, scopes, clientId });
    const body = { access_token: token, token_type: 'Bearer', expires_in: accessTtl, scope: scopes.join(' ') };
    if (withRefresh) body.refresh_token = issueRefreshToken({ userId, clientId, scopes, familyId });
    return body;
  }

  const purgeTimer = setInterval(() => stmts.purgeExpired.run(Math.floor(Date.now() / 1000)), 3600_000);
  purgeTimer.unref();

  return {
    tokenResponse,
    consumeRefreshToken,
    revokeRefreshToken,
    verifyAccessToken,
    denylistAccessToken,
    isAccessTokenRevoked,
    close: () => clearInterval(purgeTimer),
  };
}
