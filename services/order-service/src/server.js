import { randomUUID } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import express from 'express';
import { decryptField, encryptField, parseEncryptionKey } from '../../../shared/crypto.js';
import { captureRawBody, requireInternal, signInternalRequest } from '../../../shared/internal-auth.js';
import { HttpError, accessLog, errorHandler, notFound, registerHealth, requestId } from '../../../shared/http.js';
import { createLogger } from '../../../shared/logger.js';
import { hasScope, requireScope } from '../../../shared/rbac.js';
import { intParam, validate } from '../../../shared/validate.js';

const SERVICE = 'order-service';
const STATUSES = ['pending', 'paid', 'shipped', 'delivered', 'cancelled'];

const createSchema = {
  items: {
    type: 'array', required: true, min: 1, max: 50,
    items: {
      type: 'object',
      schema: {
        productId: { type: 'integer', required: true, min: 1 },
        quantity: { type: 'integer', required: true, min: 1, max: 100 },
      },
    },
  },
  shippingAddress: { type: 'string', required: true, min: 5, max: 500 },
};

function openDatabase(file) {
  if (file !== ':memory:') mkdirSync(dirname(file), { recursive: true });
  const db = new DatabaseSync(file);
  db.exec(`
    PRAGMA journal_mode = WAL;
    CREATE TABLE IF NOT EXISTS orders (
      id                    TEXT PRIMARY KEY,
      user_id               TEXT NOT NULL,
      items                 TEXT NOT NULL,
      total_cents           INTEGER NOT NULL,
      status                TEXT NOT NULL,
      shipping_address_enc  TEXT NOT NULL,   -- AES-256-GCM ciphertext, never plaintext at rest
      created_at            TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    );
    CREATE INDEX IF NOT EXISTS idx_orders_user ON orders(user_id, created_at);
  `);
  return db;
}

export async function start(env = process.env) {
  const logger = createLogger({
    service: SERVICE, level: env.LOG_LEVEL, collectorUrl: env.LOG_COLLECTOR_URL, internalSecret: env.INTERNAL_SECRET,
  });
  const port = Number(env.PORT || 4003);
  const productServiceUrl = env.PRODUCT_SERVICE_URL || 'http://localhost:4002';
  const encryptionKey = parseEncryptionKey(env.FIELD_ENCRYPTION_KEY);
  const db = openDatabase(env.DB_PATH || './data/orders.db');

  const q = {
    insert: db.prepare(`INSERT INTO orders (id, user_id, items, total_cents, status, shipping_address_enc)
      VALUES (?, ?, ?, ?, 'pending', ?)`),
    get: db.prepare('SELECT * FROM orders WHERE id = ?'),
    listMine: db.prepare('SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?'),
    listAll: db.prepare('SELECT * FROM orders ORDER BY created_at DESC LIMIT ? OFFSET ?'),
    setStatus: db.prepare('UPDATE orders SET status = ? WHERE id = ?'),
  };

  // The order id is used as AAD so an encrypted address can't be copied onto another order row.
  const toOrder = (r, { includeAddress }) => r && ({
    id: r.id,
    userId: r.user_id,
    items: JSON.parse(r.items),
    totalCents: r.total_cents,
    status: r.status,
    createdAt: r.created_at,
    ...(includeAddress ? { shippingAddress: decryptField(r.shipping_address_enc, encryptionKey, r.id) } : {}),
  });

  /** Service-to-service call: signed with this service's own identity, carrying the caller's request id. */
  async function fetchProduct(id, req) {
    const path = `/products/${id}`;
    const headers = signInternalRequest({
      secret: env.INTERNAL_SECRET, method: 'GET', path, requestId: req.id,
      identity: { sub: `service:${SERVICE}`, roles: ['service'], scopes: ['products:read'] },
    });
    let res;
    try {
      res = await fetch(new URL(path, productServiceUrl), { headers, signal: AbortSignal.timeout(3000) });
    } catch (err) {
      logger.error('product-service unreachable', { requestId: req.id, err });
      throw new HttpError(503, 'Product catalogue unavailable', { code: 'dependency_unavailable' });
    }
    if (res.status === 404) return null;
    if (!res.ok) throw new HttpError(502, 'Product catalogue error', { code: 'bad_gateway' });
    return res.json();
  }

  const app = express();
  app.disable('x-powered-by');
  app.use(requestId());
  app.use(accessLog(logger));
  registerHealth(app, {
    service: SERVICE,
    checks: {
      database: () => db.prepare('SELECT 1').get(),
      productService: async () => {
        const r = await fetch(new URL('/health', productServiceUrl), { signal: AbortSignal.timeout(1500) });
        if (!r.ok) throw new Error(`status ${r.status}`);
      },
    },
  });
  app.use(express.json({ limit: '32kb', verify: captureRawBody }));
  app.use(requireInternal({ secret: env.INTERNAL_SECRET, logger }));

  app.post('/orders', requireScope('orders:write'), async (req, res) => {
    const body = validate(createSchema, req.body ?? {});
    const quantities = new Map();
    for (const { productId, quantity } of body.items) quantities.set(productId, (quantities.get(productId) ?? 0) + quantity);

    const products = await Promise.all([...quantities.keys()].map((id) => fetchProduct(id, req)));
    const items = [];
    for (const [i, [productId, quantity]] of [...quantities].entries()) {
      const p = products[i];
      if (!p) throw new HttpError(422, `Product ${productId} does not exist`, { code: 'unknown_product' });
      if (p.stock < quantity) throw new HttpError(409, `Insufficient stock for product ${productId}`, { code: 'insufficient_stock' });
      // Price comes from the catalogue, never from the client.
      items.push({ productId, sku: p.sku, name: p.name, quantity, unitPriceCents: p.priceCents });
    }
    const total = items.reduce((sum, it) => sum + it.quantity * it.unitPriceCents, 0);

    const id = randomUUID();
    q.insert.run(id, req.identity.sub, JSON.stringify(items), total, encryptField(body.shippingAddress, encryptionKey, id));
    logger.info('order created', { orderId: id, userId: req.identity.sub, totalCents: total, requestId: req.id });
    res.status(201).json(toOrder(q.get.get(id), { includeAddress: true }));
  });

  app.get('/orders', requireScope('orders:read'), (req, res) => {
    const limit = intParam(req.query.limit, { name: 'limit', min: 1, max: 100, fallback: 20 });
    const offset = intParam(req.query.offset, { name: 'offset', fallback: 0 });
    const all = req.query.all === 'true';
    if (all && !hasScope(req.identity, 'orders:read:all')) {
      throw new HttpError(403, 'Missing scope: orders:read:all', { code: 'forbidden' });
    }
    const rows = all ? q.listAll.all(limit, offset) : q.listMine.all(req.identity.sub, limit, offset);
    // Bulk listings never include decrypted PII.
    res.json({ items: rows.map((r) => toOrder(r, { includeAddress: false })), limit, offset });
  });

  app.get('/orders/:id', requireScope('orders:read'), (req, res) => {
    const row = q.get.get(String(req.params.id));
    const isOwner = row?.user_id === req.identity.sub;
    // 404 rather than 403 for other users' orders, so ids can't be probed (IDOR).
    if (!row || (!isOwner && !hasScope(req.identity, 'orders:read:all'))) {
      throw new HttpError(404, 'Order not found', { code: 'not_found' });
    }
    res.json(toOrder(row, { includeAddress: isOwner || hasScope(req.identity, 'orders:manage') }));
  });

  app.patch('/orders/:id/status', requireScope('orders:manage'), (req, res) => {
    const { status } = validate({ status: { type: 'string', required: true, enum: STATUSES } }, req.body ?? {});
    const id = String(req.params.id);
    if (!q.setStatus.run(status, id).changes) throw new HttpError(404, 'Order not found', { code: 'not_found' });
    logger.info('audit: order status changed', { orderId: id, status, by: req.identity.sub, requestId: req.id });
    res.json(toOrder(q.get.get(id), { includeAddress: false }));
  });

  app.use(notFound());
  app.use(errorHandler(logger));

  const server = app.listen(port, () => logger.info('listening', { port }));
  return { app, server, logger, close: async () => db.close() };
}
