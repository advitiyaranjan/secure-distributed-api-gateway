import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import selfsigned from 'selfsigned';

/**
 * Uses TLS_CERT_PATH / TLS_KEY_PATH when provided (e.g. a mounted Let's Encrypt or
 * internal-CA certificate). Otherwise generates a self-signed certificate for local
 * use and persists it so restarts don't change it.
 */
export async function loadCertificate({ certPath, keyPath, generatedDir, hostname, logger }) {
  if (certPath && keyPath) {
    return { cert: readFileSync(certPath), key: readFileSync(keyPath), source: certPath };
  }
  const genCert = join(generatedDir, 'gateway.crt');
  const genKey = join(generatedDir, 'gateway.key');
  if (existsSync(genCert) && existsSync(genKey)) {
    return { cert: readFileSync(genCert), key: readFileSync(genKey), source: genCert };
  }

  const pems = await selfsigned.generate([{ name: 'commonName', value: hostname }], {
    keySize: 2048,
    algorithm: 'sha256',
    notAfterDate: new Date(Date.now() + 365 * 24 * 3600_000),
    extensions: [
      { name: 'basicConstraints', cA: false },
      { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
      { name: 'extKeyUsage', serverAuth: true },
      {
        name: 'subjectAltName',
        altNames: [{ type: 2, value: hostname }, { type: 2, value: 'localhost' }, { type: 7, ip: '127.0.0.1' }],
      },
    ],
  });
  mkdirSync(generatedDir, { recursive: true });
  writeFileSync(genCert, pems.cert);
  writeFileSync(genKey, pems.private, { mode: 0o600 });
  logger.warn('using a generated self-signed TLS certificate; mount a real one via TLS_CERT_PATH/TLS_KEY_PATH in production', { path: genCert });
  return { cert: pems.cert, key: pems.private, source: genCert };
}
