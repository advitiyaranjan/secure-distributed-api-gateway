import assert from 'node:assert/strict';
import { once } from 'node:events';
import { after, before, describe, it } from 'node:test';
import { decodeJwt, decodeProtectedHeader } from 'jose';
import { signInternalRequest } from '../../../shared/internal-auth.js';
import { start } from '../src/server.js';

const SECRET = 's'.repeat(48);
let svc;
let base;

/** Calls auth-service the way the gateway does: form body + HMAC signature. */
async function post(path, form, { sign = true, headers = {} } = {}) {
  const body = new URLSearchParams(form).toString();
  const h = { 'content-type': 'application/x-www-form-urlencoded', ...headers };
  if (sign) Object.assign(h, signInternalRequest({ secret: SECRET, method: 'POST', path, body }));
  const res = await fetch(base + path, { method: 'POST', headers: h, body });
  return { status: res.status, body: await res.json() };
}

before(async () => {
  svc = await start({
    PORT: '0', DB_PATH: ':memory:', KEY_DIR: '', REDIS_URL: 'mock', INTERNAL_SECRET: SECRET, LOG_LEVEL: 'error',
    ADMIN_PASSWORD: 'admin-test-password', DEMO_USER_PASSWORD: 'alice-test-password', REPORTING_CLIENT_SECRET: 'reporting-secret',
  });
  if (!svc.server.listening) await once(svc.server, 'listening');
  base = `http://127.0.0.1:${svc.server.address().port}`;
});
after(async () => {
  svc.server.close();
  await svc.close();
});

describe('auth-service', () => {
  it('rejects requests that are not signed by the gateway', async () => {
    const r = await post('/oauth/token', { grant_type: 'password', client_id: 'web-app', username: 'alice', password: 'alice-test-password' }, { sign: false });
    assert.equal(r.status, 401);
  });

  it('issues RS256 access tokens with role-derived scopes', async () => {
    const r = await post('/oauth/token', { grant_type: 'password', client_id: 'web-app', username: 'alice', password: 'alice-test-password' });
    assert.equal(r.status, 200);
    const header = decodeProtectedHeader(r.body.access_token);
    const claims = decodeJwt(r.body.access_token);
    assert.equal(header.alg, 'RS256');
    assert.deepEqual(claims.roles, ['user']);
    assert.ok(!claims.scope.includes('products:write'));
    assert.ok(claims.exp - claims.iat <= 900);
  });

  it('refuses scopes the role does not grant', async () => {
    const r = await post('/oauth/token', { grant_type: 'password', client_id: 'web-app', username: 'alice', password: 'alice-test-password', scope: 'users:manage' });
    assert.equal(r.body.error, 'invalid_scope');
  });

  it('client_credentials requires the correct secret', async () => {
    const bad = await post('/oauth/token', { grant_type: 'client_credentials', client_id: 'reporting-service', client_secret: 'nope' });
    const good = await post('/oauth/token', { grant_type: 'client_credentials', client_id: 'reporting-service', client_secret: 'reporting-secret' });
    assert.equal(bad.status, 401);
    assert.equal(good.status, 200);
    assert.equal(decodeJwt(good.body.access_token).sub, 'client:reporting-service');
  });

  it('locks an account after 5 failures, even for the correct password', async () => {
    await post('/register', { username: 'mallory', password: 'mallory-password-1' });
    for (let i = 0; i < 5; i += 1) {
      await post('/oauth/token', { grant_type: 'password', client_id: 'web-app', username: 'mallory', password: 'guess' });
    }
    const r = await post('/oauth/token', { grant_type: 'password', client_id: 'web-app', username: 'mallory', password: 'mallory-password-1' });
    assert.equal(r.status, 400);
    assert.equal(r.body.error, 'invalid_grant');
  });

  it('publishes JWKS without requiring a signature', async () => {
    const res = await fetch(`${base}/.well-known/jwks.json`);
    const { keys } = await res.json();
    assert.equal(keys[0].kty, 'RSA');
    assert.equal(keys[0].d, undefined, 'private key material must never be published');
  });
});
