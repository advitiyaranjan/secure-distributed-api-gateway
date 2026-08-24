// RS256 signing key management. The private key never leaves this service; the
// gateway verifies tokens using the public half published at /.well-known/jwks.json.
// Asymmetric signing means a compromised gateway or backend still can't mint tokens.
import { createPrivateKey, createPublicKey, generateKeyPairSync } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { calculateJwkThumbprint, exportJWK } from 'jose';

export async function loadSigningKey({ keyDir, logger }) {
  const privatePath = keyDir && join(keyDir, 'jwt-signing-key.pem');
  let privateKey;

  if (privatePath && existsSync(privatePath)) {
    privateKey = createPrivateKey(readFileSync(privatePath));
  } else {
    ({ privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 }));
    if (privatePath) {
      mkdirSync(keyDir, { recursive: true });
      writeFileSync(privatePath, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
      logger?.info('generated new RS256 signing key', { path: privatePath });
    }
  }

  const publicKey = createPublicKey(privateKey);
  const jwk = await exportJWK(publicKey);
  const kid = await calculateJwkThumbprint(jwk);
  return { privateKey, publicKey, kid, publicJwk: { ...jwk, kid, alg: 'RS256', use: 'sig' } };
}
