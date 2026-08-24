import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { describe, it } from 'node:test';
import { decryptField, encryptField, hashPassword, verifyPassword } from './crypto.js';
import { signInternalRequest, verifyInternalRequest } from './internal-auth.js';
import { intersect, scopesForRoles } from './rbac.js';
import { validate } from './validate.js';

describe('crypto', () => {
  it('hashes and verifies passwords with a per-hash salt', async () => {
    const a = await hashPassword('correct horse battery');
    const b = await hashPassword('correct horse battery');
    assert.notEqual(a, b);
    assert.ok(await verifyPassword('correct horse battery', a));
    assert.ok(!(await verifyPassword('wrong', a)));
  });

  it('AES-256-GCM round-trips and detects tampering / wrong context', () => {
    const key = randomBytes(32);
    const ct = encryptField('221B Baker Street', key, 'order-1');
    assert.equal(decryptField(ct, key, 'order-1'), '221B Baker Street');
    assert.throws(() => decryptField(ct, key, 'order-2'));
    const parts = ct.split('.');
    parts[3] = Buffer.from('tampered').toString('base64url');
    assert.throws(() => decryptField(parts.join('.'), key, 'order-1'));
    assert.throws(() => decryptField(ct, randomBytes(32), 'order-1'));
  });
});

describe('internal request signing', () => {
  const secret = 'x'.repeat(48);
  const identity = { sub: 'u1', roles: ['user'], scopes: ['orders:read'] };
  const sign = (over = {}) => signInternalRequest({ secret, method: 'POST', path: '/orders?x=1', body: '{"a":1}', identity, requestId: 'req-12345678', ...over });
  const asReq = (headers, over = {}) => ({ method: 'POST', originalUrl: '/orders?x=1', rawBody: Buffer.from('{"a":1}'), headers, ...over });

  it('accepts a valid signature and returns the identity', () => {
    const r = verifyInternalRequest(asReq(sign()), secret);
    assert.equal(r.ok, true);
    assert.deepEqual(r.identity.roles, ['user']);
  });

  it('rejects modified identity, path, body, or a wrong secret', () => {
    assert.equal(verifyInternalRequest(asReq({ ...sign(), 'x-user-roles': 'admin' }), secret).ok, false);
    assert.equal(verifyInternalRequest(asReq(sign(), { originalUrl: '/orders?x=2' }), secret).ok, false);
    assert.equal(verifyInternalRequest(asReq(sign(), { rawBody: Buffer.from('{"a":2}') }), secret).ok, false);
    assert.equal(verifyInternalRequest(asReq(sign()), 'y'.repeat(48)).ok, false);
  });

  it('rejects stale timestamps (replay window)', () => {
    const old = sign({ now: Date.now() - 60_000 });
    assert.equal(verifyInternalRequest(asReq(old), secret).reason, 'stale or invalid timestamp');
  });
});

describe('rbac', () => {
  it('derives scopes from roles and ignores unknown roles', () => {
    assert.ok(scopesForRoles(['admin']).includes('users:manage'));
    assert.ok(!scopesForRoles(['user']).includes('products:write'));
    assert.deepEqual(scopesForRoles(['root']), []);
    assert.deepEqual(intersect(['a', 'b', 'c'], ['c', 'a']), ['a', 'c']);
  });
});

describe('validate', () => {
  const schema = { name: { type: 'string', required: true, max: 5 }, qty: { type: 'integer', min: 1 } };
  it('rejects unknown fields (mass assignment) and out-of-bounds values', () => {
    assert.throws(() => validate(schema, { name: 'a', role: 'admin' }), /Validation failed/);
    assert.throws(() => validate(schema, { name: 'toolong' }));
    assert.throws(() => validate(schema, { name: 'a', qty: 0 }));
    assert.deepEqual(validate(schema, { name: ' ok ', qty: 2 }), { name: 'ok', qty: 2 });
  });
});
