// Runs the whole stack in ONE Node process, without Docker or a Redis server:
// every service starts on its usual port and they share an in-memory Redis mock.
// Handy for development and for running the e2e suite on a machine without Docker.
// Data goes to ./.data. Secrets come from .env if present, else dev defaults.
import { existsSync, readFileSync } from 'node:fs';

const root = new URL('../', import.meta.url);
const dotenv = existsSync(new URL('.env', root))
  ? Object.fromEntries(readFileSync(new URL('.env', root), 'utf8').split('\n').filter((l) => l.includes('=')).map((l) => {
    const i = l.indexOf('=');
    return [l.slice(0, i).trim(), l.slice(i + 1).trim()];
  }))
  : {};

const common = {
  NODE_ENV: 'development',
  LOG_LEVEL: process.env.LOG_LEVEL || 'info',
  REDIS_URL: 'mock',
  INTERNAL_SECRET: dotenv.INTERNAL_SECRET || 'dev-only-internal-secret-change-me-0123456789',
  LOG_COLLECTOR_URL: 'http://127.0.0.1:4004',
  PRODUCT_SERVICE_URL: 'http://127.0.0.1:4002',
};

const services = [
  ['log-collector', { PORT: '4004', DB_PATH: '.data/logs.db', LOG_COLLECTOR_URL: '' }],
  ['auth-service', {
    PORT: '4001', DB_PATH: '.data/auth.db', KEY_DIR: '.data/keys',
    ADMIN_PASSWORD: dotenv.ADMIN_PASSWORD || 'admin-dev-password',
    DEMO_USER_PASSWORD: dotenv.DEMO_USER_PASSWORD || 'alice-dev-password',
    REPORTING_CLIENT_SECRET: dotenv.REPORTING_CLIENT_SECRET || 'reporting-dev-secret',
  }],
  ['product-service', { PORT: '4002', DB_PATH: '.data/products.db', SIMULATED_DB_LATENCY_MS: process.env.SIMULATED_DB_LATENCY_MS || '5' }],
  ['order-service', {
    PORT: '4003', DB_PATH: '.data/orders.db',
    FIELD_ENCRYPTION_KEY: dotenv.FIELD_ENCRYPTION_KEY || Buffer.alloc(32, 7).toString('base64'), // dev-only key
  }],
  ['gateway', {
    HTTP_PORT: '8080', HTTPS_PORT: '8443', CERT_DIR: '.data/certs',
    AUTH_SERVICE_URL: 'http://127.0.0.1:4001',
    PRODUCT_SERVICE_URL: 'http://127.0.0.1:4002',
    ORDER_SERVICE_URL: 'http://127.0.0.1:4003',
    LOG_COLLECTOR_URL: 'http://127.0.0.1:4004',
    RATE_LIMIT_MULTIPLIER: process.env.RATE_LIMIT_MULTIPLIER || '1',
    CORS_ORIGINS: 'http://localhost:3000',
  }],
];

const started = [];
for (const [name, env] of services) {
  const { start } = await import(new URL(`services/${name}/src/server.js`, root));
  started.push(await start({ ...common, ...env }));
  // give each server a moment to bind before the next one depends on it
  await new Promise((r) => setTimeout(r, 150));
}
console.error('\nAll services up. Gateway: https://localhost:8443 (self-signed cert)\n');

process.on('SIGINT', async () => {
  for (const s of started.reverse()) {
    for (const srv of s.servers ?? [s.server]) srv.close();
    await s.logger.close?.();
    await s.close?.();
  }
  process.exit(0);
});
