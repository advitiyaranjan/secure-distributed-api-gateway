// Writes a .env file with freshly generated secrets for docker compose.
// Usage: node scripts/gen-env.js [--force]
import { randomBytes } from 'node:crypto';
import { existsSync, writeFileSync } from 'node:fs';

const file = new URL('../.env', import.meta.url);
if (existsSync(file) && !process.argv.includes('--force')) {
  console.error('.env already exists; pass --force to overwrite (this rotates every secret).');
  process.exit(1);
}

const secret = (bytes) => randomBytes(bytes).toString('base64url');
const env = {
  INTERNAL_SECRET: secret(48),
  FIELD_ENCRYPTION_KEY: randomBytes(32).toString('base64'),
  REDIS_PASSWORD: secret(32),
  ADMIN_PASSWORD: secret(18),
  DEMO_USER_PASSWORD: secret(18),
  REPORTING_CLIENT_SECRET: secret(32),
};

writeFileSync(file, `${Object.entries(env).map(([k, v]) => `${k}=${v}`).join('\n')}\n`, { mode: 0o600 });
console.log('Wrote .env with new secrets. Admin login: admin / see ADMIN_PASSWORD in .env');
