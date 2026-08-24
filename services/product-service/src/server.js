import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { DatabaseSync } from 'node:sqlite';
import express from 'express';
import { captureRawBody, requireInternal } from '../../../shared/internal-auth.js';
import { HttpError, accessLog, errorHandler, notFound, registerHealth, requestId } from '../../../shared/http.js';
import { createLogger } from '../../../shared/logger.js';
import { requireScope } from '../../../shared/rbac.js';
import { intParam, validate } from '../../../shared/validate.js';

const SERVICE = 'product-service';

const productSchema = {
  sku: { type: 'string', required: true, min: 3, max: 32, pattern: /^[A-Z0-9-]+$/ },
  name: { type: 'string', required: true, min: 1, max: 120 },
  description: { type: 'string', max: 1000 },
  priceCents: { type: 'integer', required: true, min: 0, max: 100_000_000 },
  stock: { type: 'integer', required: true, min: 0, max: 1_000_000 },
};

function openDatabase(file) {
  if (file !== ':memory:') mkdirSync(dirname(file), { recursive: true });
  const db = new DatabaseSync(file);
  db.exec(`
    PRAGMA journal_mode = WAL;
    CREATE TABLE IF NOT EXISTS products (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      sku         TEXT NOT NULL UNIQUE,
      name        TEXT NOT NULL,
      description TEXT NOT NULL DEFAULT '',
      price_cents INTEGER NOT NULL CHECK (price_cents >= 0),
      stock       INTEGER NOT NULL CHECK (stock >= 0),
      updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    );
  `);
  if (db.prepare('SELECT COUNT(*) AS n FROM products').get().n === 0) {
    const insert = db.prepare('INSERT INTO products (sku, name, description, price_cents, stock) VALUES (?, ?, ?, ?, ?)');
    const items = ['Keyboard', 'Mouse', 'Monitor', 'Headset', 'Webcam', 'USB-C Hub', 'Laptop Stand', 'Desk Lamp',
      'SSD 1TB', 'Router', 'Microphone', 'Docking Station', 'Graphics Tablet', 'Speakers', 'Ethernet Cable'];
    items.forEach((name, i) => insert.run(`SKU-${1000 + i}`, name, `Demo ${name.toLowerCase()}`, 1999 + i * 1500, 50 + i * 10));
  }
  return db;
}

const toProduct = (r) => r && ({
  id: r.id, sku: r.sku, name: r.name, description: r.description, priceCents: r.price_cents, stock: r.stock, updatedAt: r.updated_at,
});

export async function start(env = process.env) {
  const logger = createLogger({
    service: SERVICE, level: env.LOG_LEVEL, collectorUrl: env.LOG_COLLECTOR_URL, internalSecret: env.INTERNAL_SECRET,
  });
  const port = Number(env.PORT || 4002);
  const db = openDatabase(env.DB_PATH || './data/products.db');
  // Simulates a network round trip to a remote database (SQLite is in-process and
  // unrealistically fast), which makes the gateway cache's effect measurable in load tests.
  const dbLatencyMs = Number(env.SIMULATED_DB_LATENCY_MS || 0);
  const stats = { dbQueries: 0, since: new Date().toISOString() };

  const q = {
    list: db.prepare(`SELECT * FROM products WHERE name LIKE ? ESCAPE '\\' ORDER BY id LIMIT ? OFFSET ?`),
    count: db.prepare(`SELECT COUNT(*) AS n FROM products WHERE name LIKE ? ESCAPE '\\'`),
    get: db.prepare('SELECT * FROM products WHERE id = ?'),
    bySku: db.prepare('SELECT id FROM products WHERE sku = ?'),
    insert: db.prepare('INSERT INTO products (sku, name, description, price_cents, stock) VALUES (?, ?, ?, ?, ?)'),
    update: db.prepare(`UPDATE products SET sku = ?, name = ?, description = ?, price_cents = ?, stock = ?,
      updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?`),
    remove: db.prepare('DELETE FROM products WHERE id = ?'),
  };

  async function query(fn) {
    stats.dbQueries += 1;
    if (dbLatencyMs) await sleep(dbLatencyMs);
    return fn();
  }

  const app = express();
  app.disable('x-powered-by');
  app.use(requestId());
  app.use(accessLog(logger));
  registerHealth(app, { service: SERVICE, checks: { database: () => db.prepare('SELECT 1').get() } });
  app.use(express.json({ limit: '16kb', verify: captureRawBody }));
  app.use(requireInternal({ secret: env.INTERNAL_SECRET, logger }));

  app.get('/products', requireScope('products:read'), async (req, res) => {
    const limit = intParam(req.query.limit, { name: 'limit', min: 1, max: 100, fallback: 20 });
    const offset = intParam(req.query.offset, { name: 'offset', fallback: 0 });
    const search = typeof req.query.q === 'string' ? req.query.q.slice(0, 100) : '';
    // Parameterized query; LIKE wildcards in user input are escaped, not interpreted.
    const pattern = `%${search.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;
    const [rows, total] = await query(() => [q.list.all(pattern, limit, offset), q.count.get(pattern).n]);
    res.json({ items: rows.map(toProduct), total, limit, offset });
  });

  app.get('/products/_stats', requireScope('metrics:read'), (req, res) => res.json(stats));

  app.get('/products/:id', requireScope('products:read'), async (req, res) => {
    const id = intParam(req.params.id, { name: 'id', min: 1 });
    const product = toProduct(await query(() => q.get.get(id)));
    if (!product) throw new HttpError(404, 'Product not found', { code: 'not_found' });
    res.json(product);
  });

  app.post('/products', requireScope('products:write'), async (req, res) => {
    const p = validate(productSchema, req.body ?? {});
    if (await query(() => q.bySku.get(p.sku))) throw new HttpError(409, 'SKU already exists', { code: 'conflict' });
    const { lastInsertRowid } = await query(() => q.insert.run(p.sku, p.name, p.description ?? '', p.priceCents, p.stock));
    logger.info('audit: product created', { productId: Number(lastInsertRowid), by: req.identity.sub, requestId: req.id });
    res.status(201).json(toProduct(q.get.get(lastInsertRowid)));
  });

  app.put('/products/:id', requireScope('products:write'), async (req, res) => {
    const id = intParam(req.params.id, { name: 'id', min: 1 });
    const p = validate(productSchema, req.body ?? {});
    const clash = await query(() => q.bySku.get(p.sku));
    if (clash && clash.id !== id) throw new HttpError(409, 'SKU already exists', { code: 'conflict' });
    const { changes } = await query(() => q.update.run(p.sku, p.name, p.description ?? '', p.priceCents, p.stock, id));
    if (!changes) throw new HttpError(404, 'Product not found', { code: 'not_found' });
    logger.info('audit: product updated', { productId: id, by: req.identity.sub, requestId: req.id });
    res.json(toProduct(q.get.get(id)));
  });

  app.delete('/products/:id', requireScope('products:write'), async (req, res) => {
    const id = intParam(req.params.id, { name: 'id', min: 1 });
    const { changes } = await query(() => q.remove.run(id));
    if (!changes) throw new HttpError(404, 'Product not found', { code: 'not_found' });
    logger.info('audit: product deleted', { productId: id, by: req.identity.sub, requestId: req.id });
    res.status(204).end();
  });

  app.use(notFound());
  app.use(errorHandler(logger));

  const server = app.listen(port, () => logger.info('listening', { port }));
  return { app, server, logger, close: async () => db.close() };
}
