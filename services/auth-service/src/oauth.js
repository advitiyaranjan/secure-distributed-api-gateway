// OAuth 2.0 authorization server (RFC 6749) with:
//   - authorization_code + PKCE S256 (RFC 7636): the recommended flow for user-facing apps
//   - client_credentials: service-to-service access, no user involved
//   - refresh_token with rotation + reuse detection
//   - password grant: first-party/legacy only, enabled per client (removed in OAuth 2.1)
//   - token revocation (RFC 7009), introspection (RFC 7662), server metadata (RFC 8414)
import { createHash } from 'node:crypto';
import express from 'express';
import { DUMMY_PASSWORD_HASH, randomToken, sha256, verifyPassword } from '../../../shared/crypto.js';
import { ALL_SCOPES, intersect, scopesForRoles } from '../../../shared/rbac.js';
import { OAuthError } from './tokens.js';

const MAX_FAILED_LOGINS = 5;
const LOCKOUT_SECONDS = 15 * 60;
const AUTH_CODE_TTL = 60;
const PKCE_RE = /^[A-Za-z0-9\-._~]{43,128}$/;

export function oauthRouter({ repo, tokens, redis, logger, config }) {
  const router = express.Router();

  // ---- helpers ------------------------------------------------------------

  function parseScope(scope) {
    if (scope === undefined || scope === '') return null;
    if (typeof scope !== 'string') throw new OAuthError('invalid_scope', 'scope must be a string');
    const requested = scope.split(' ').filter(Boolean);
    const unknown = requested.filter((s) => !ALL_SCOPES.includes(s));
    if (unknown.length) throw new OAuthError('invalid_scope', `Unknown scope: ${unknown.join(' ')}`);
    return requested;
  }

  /** Least privilege: what the subject is entitled to ∩ what the client may hold ∩ what was asked for. */
  function grantScopes(entitled, client, requested) {
    const base = intersect(entitled, client.scopes);
    const granted = requested ? intersect(base, requested) : base;
    if (!granted.length) throw new OAuthError('invalid_scope', 'None of the requested scopes can be granted');
    return granted;
  }

  /** Client authentication: HTTP Basic (preferred) or client_id/client_secret in the body. */
  async function authenticateClient(req) {
    let clientId;
    let secret;
    const header = req.headers.authorization;
    if (header?.startsWith('Basic ')) {
      const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
      const i = decoded.indexOf(':');
      if (i < 0) throw new OAuthError('invalid_client', 'Malformed Basic credentials', 401);
      try {
        clientId = decodeURIComponent(decoded.slice(0, i));
        secret = decodeURIComponent(decoded.slice(i + 1));
      } catch {
        throw new OAuthError('invalid_client', 'Malformed Basic credentials', 401);
      }
    } else {
      clientId = req.body?.client_id;
      secret = req.body?.client_secret;
    }
    if (typeof clientId !== 'string' || !clientId) throw new OAuthError('invalid_client', 'Client authentication failed', 401);
    const client = repo.findClient(clientId);
    if (client?.type === 'confidential') {
      const ok = typeof secret === 'string' && await verifyPassword(secret, client.secretHash);
      if (!ok) throw new OAuthError('invalid_client', 'Client authentication failed', 401);
    } else if (!client) {
      await verifyPassword(String(secret ?? ''), DUMMY_PASSWORD_HASH);
      throw new OAuthError('invalid_client', 'Client authentication failed', 401);
    }
    return client;
  }

  function requireGrant(client, grant) {
    if (!client.grantTypes.includes(grant)) {
      throw new OAuthError('unauthorized_client', `Client is not allowed to use ${grant}`);
    }
  }

  /**
   * Username/password check with brute-force protection. Failed attempts are counted
   * in Redis (so the lockout holds across auth-service replicas), and unknown users
   * still pay the scrypt cost so response timing doesn't reveal which usernames exist.
   */
  async function authenticateUser(username, password) {
    if (typeof username !== 'string' || typeof password !== 'string' || !username || !password) {
      throw new OAuthError('invalid_request', 'username and password are required');
    }
    const failKey = `login:fail:${username.toLowerCase()}`;
    const failures = Number(await redis.get(failKey)) || 0;
    const user = repo.findUserByName(username);
    const valid = await verifyPassword(password, user?.passwordHash ?? DUMMY_PASSWORD_HASH);

    if (failures >= MAX_FAILED_LOGINS) {
      logger.warn('security: login attempt on locked account', { username });
      throw new OAuthError('invalid_grant', 'Invalid username or password');
    }
    if (!user || !valid) {
      await redis.multi().incr(failKey).expire(failKey, LOCKOUT_SECONDS).exec();
      logger.warn('security: failed login', { username, attempt: failures + 1 });
      throw new OAuthError('invalid_grant', 'Invalid username or password');
    }
    await redis.del(failKey);
    return user;
  }

  function userTokenResponse(user, client, scopes, familyId) {
    return tokens.tokenResponse({
      sub: user.id,
      roles: user.roles,
      scopes,
      clientId: client.clientId,
      userId: user.id,
      familyId,
      withRefresh: client.grantTypes.includes('refresh_token'),
    });
  }

  function noStore(res) {
    res.set({ 'Cache-Control': 'no-store', Pragma: 'no-cache' });
  }

  // ---- metadata & keys ------------------------------------------------------

  router.get('/.well-known/jwks.json', (req, res) => {
    res.set('Cache-Control', 'public, max-age=300').json({ keys: [config.signingKey.publicJwk] });
  });

  router.get('/.well-known/oauth-authorization-server', (req, res) => {
    const base = config.publicBaseUrl;
    res.json({
      issuer: config.issuer,
      authorization_endpoint: `${base}/oauth/authorize`,
      token_endpoint: `${base}/oauth/token`,
      revocation_endpoint: `${base}/oauth/revoke`,
      introspection_endpoint: `${base}/oauth/introspect`,
      jwks_uri: `${base}/.well-known/jwks.json`,
      grant_types_supported: ['authorization_code', 'client_credentials', 'refresh_token', 'password'],
      response_types_supported: ['code'],
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
      scopes_supported: ALL_SCOPES,
    });
  });

  // ---- authorization endpoint (headless) -----------------------------------
  // A real deployment renders a login + consent page here. This API-only variant
  // accepts the user's credentials as JSON and returns the redirect the browser
  // would follow, which keeps the full code + PKCE exchange testable from scripts.

  router.post('/oauth/authorize', async (req, res) => {
    const b = req.body ?? {};
    if (b.response_type !== 'code') throw new OAuthError('unsupported_response_type', 'response_type must be "code"');
    const client = repo.findClient(b.client_id);
    if (!client) throw new OAuthError('invalid_client', 'Unknown client', 401);
    requireGrant(client, 'authorization_code');
    // Exact-match redirect URIs: no prefix/wildcard matching, which prevents open redirects / code theft.
    if (!client.redirectUris.includes(b.redirect_uri)) throw new OAuthError('invalid_request', 'redirect_uri is not registered');
    if (b.code_challenge_method !== 'S256') throw new OAuthError('invalid_request', 'PKCE with code_challenge_method=S256 is required');
    if (typeof b.code_challenge !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(b.code_challenge)) {
      throw new OAuthError('invalid_request', 'code_challenge must be a base64url SHA-256 digest');
    }

    const user = await authenticateUser(b.username, b.password);
    const scopes = grantScopes(scopesForRoles(user.roles), client, parseScope(b.scope));
    const code = randomToken(32);
    repo.saveAuthCode({
      codeHash: sha256(code),
      clientId: client.clientId,
      userId: user.id,
      redirectUri: b.redirect_uri,
      codeChallenge: b.code_challenge,
      scopes,
      expiresAt: Math.floor(Date.now() / 1000) + AUTH_CODE_TTL,
    });

    const redirect = new URL(b.redirect_uri);
    redirect.searchParams.set('code', code);
    if (typeof b.state === 'string') redirect.searchParams.set('state', b.state);
    noStore(res);
    res.json({ redirect_to: redirect.toString(), code, state: b.state });
  });

  // ---- token endpoint --------------------------------------------------------

  router.post('/oauth/token', async (req, res) => {
    const b = req.body ?? {};
    const client = await authenticateClient(req);
    noStore(res);

    switch (b.grant_type) {
      case 'client_credentials': {
        requireGrant(client, 'client_credentials');
        if (client.type !== 'confidential') throw new OAuthError('unauthorized_client', 'Public clients cannot use client_credentials');
        const scopes = grantScopes(client.scopes, client, parseScope(b.scope));
        logger.info('issued client_credentials token', { clientId: client.clientId, scopes });
        return res.json(await tokens.tokenResponse({
          sub: `client:${client.clientId}`, roles: ['service'], scopes, clientId: client.clientId, withRefresh: false,
        }));
      }

      case 'password': {
        requireGrant(client, 'password');
        const user = await authenticateUser(b.username, b.password);
        const scopes = grantScopes(scopesForRoles(user.roles), client, parseScope(b.scope));
        logger.info('user logged in', { userId: user.id, clientId: client.clientId, grant: 'password' });
        return res.json(await userTokenResponse(user, client, scopes));
      }

      case 'authorization_code': {
        requireGrant(client, 'authorization_code');
        if (typeof b.code !== 'string' || typeof b.code_verifier !== 'string') {
          throw new OAuthError('invalid_request', 'code and code_verifier are required');
        }
        if (!PKCE_RE.test(b.code_verifier)) throw new OAuthError('invalid_grant', 'Malformed code_verifier');
        const codeHash = sha256(b.code);
        const row = repo.getAuthCode(codeHash);
        if (!row || row.client_id !== client.clientId) throw new OAuthError('invalid_grant', 'Invalid authorization code');
        if (!repo.markCodeUsed(codeHash)) {
          logger.warn('security: authorization code replay', { clientId: client.clientId, userId: row.user_id });
          throw new OAuthError('invalid_grant', 'Authorization code already used');
        }
        if (row.expires_at < Date.now() / 1000) throw new OAuthError('invalid_grant', 'Authorization code expired');
        if (row.redirect_uri !== b.redirect_uri) throw new OAuthError('invalid_grant', 'redirect_uri mismatch');
        const challenge = createHash('sha256').update(b.code_verifier).digest('base64url');
        if (challenge !== row.code_challenge) throw new OAuthError('invalid_grant', 'PKCE verification failed');

        const user = repo.findUserById(row.user_id);
        if (!user) throw new OAuthError('invalid_grant', 'User no longer exists');
        // Re-intersect with current roles in case they changed during the login.
        const scopes = intersect(JSON.parse(row.scopes), scopesForRoles(user.roles));
        logger.info('user logged in', { userId: user.id, clientId: client.clientId, grant: 'authorization_code' });
        return res.json(await userTokenResponse(user, client, scopes));
      }

      case 'refresh_token': {
        requireGrant(client, 'refresh_token');
        if (typeof b.refresh_token !== 'string') throw new OAuthError('invalid_request', 'refresh_token is required');
        const consumed = tokens.consumeRefreshToken(b.refresh_token, client.clientId);
        const user = repo.findUserById(consumed.userId);
        if (!user) throw new OAuthError('invalid_grant', 'User no longer exists');
        // Role changes (e.g. demotion) take effect on the next refresh.
        let scopes = intersect(consumed.scopes, scopesForRoles(user.roles));
        const requested = parseScope(b.scope);
        if (requested) scopes = intersect(scopes, requested);
        if (!scopes.length) throw new OAuthError('invalid_scope', 'No scopes remain for this token');
        return res.json(await userTokenResponse(user, client, scopes, consumed.familyId));
      }

      default:
        throw new OAuthError('unsupported_grant_type', 'Unsupported grant_type');
    }
  });

  // ---- revocation (RFC 7009) ---------------------------------------------------

  router.post('/oauth/revoke', async (req, res) => {
    const client = await authenticateClient(req);
    const token = req.body?.token;
    if (typeof token !== 'string') throw new OAuthError('invalid_request', 'token is required');

    if (token.split('.').length === 3) {
      try {
        const payload = await tokens.verifyAccessToken(token);
        if (payload.client_id === client.clientId) {
          await tokens.denylistAccessToken(payload);
          logger.info('access token revoked', { jti: payload.jti, sub: payload.sub });
        }
      } catch { /* invalid tokens are a no-op per RFC 7009 */ }
    } else if (tokens.revokeRefreshToken(token, client.clientId)) {
      logger.info('refresh token family revoked', { clientId: client.clientId });
    }
    res.status(200).json({});
  });

  // ---- introspection (RFC 7662), confidential clients only ------------------------

  router.post('/oauth/introspect', async (req, res) => {
    const client = await authenticateClient(req);
    if (client.type !== 'confidential') throw new OAuthError('invalid_client', 'Introspection requires a confidential client', 401);
    noStore(res);
    try {
      const p = await tokens.verifyAccessToken(String(req.body?.token ?? ''));
      if (await tokens.isAccessTokenRevoked(p.jti)) return res.json({ active: false });
      res.json({
        active: true, token_type: 'access_token', sub: p.sub, scope: p.scope, client_id: p.client_id,
        roles: p.roles, exp: p.exp, iat: p.iat, iss: p.iss, aud: p.aud, jti: p.jti,
      });
    } catch {
      res.json({ active: false });
    }
  });

  return router;
}

/** RFC 6749 §5.2 error format. Must be registered after the router. */
export function oauthErrorHandler() {
  return (err, req, res, next) => {
    if (!(err instanceof OAuthError)) return next(err);
    res.set({ 'Cache-Control': 'no-store', Pragma: 'no-cache' });
    if (err.status === 401 && req.headers.authorization?.startsWith('Basic ')) {
      res.set('WWW-Authenticate', 'Basic realm="oauth"');
    }
    res.status(err.status).json({ error: err.error, error_description: err.message });
  };
}
