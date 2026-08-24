// Centralized log store. Every service ships structured JSON logs here over signed
// internal requests; admins query them through the gateway (/admin/logs), e.g. to
// follow one X-Request-Id across gateway → order-service → product-service.
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import express from 'express';
import { captureRawBody, requireInternal } from '../../../shared/internal-auth.js';
import { HttpError, accessLog, errorHandler, notFound, registerHealth, requestId } from '../../../shared/http.js';
import { createLogger } from '../../../shared/logger.js';
import { requireScope } from '../../../shared/rbac.js';
import { intParam } from '../../../shared/validate.js';

const SERVICE = 'log-collector';
const LEVELS = ['debug', 'info', 'warn', 'error'];
const MAX_BATCH = 1000;

function openDatabase(file) {
  if (file !== ':memory:') mkdirSync(dirname(file), { recursive: true });
  const db = new DatabaseSync(file);
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous = NORMAL;
    CREATE TABLE IF NOT EXISTS logs (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      ts          TEXT NOT NULL,
      level       TEXT NOT NULL,
      service     TEXT NOT NULL,
      msg         TEXT NOT NULL,
      request_id  TEXT,
      data        TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs(ts);
    CREATE INDEX IF NOT EXISTS idx_logs_request ON logs(request_id);
    CREATE INDEX IF NOT EXISTS idx_logs_service_level ON logs(service, level, ts);
  `);
  return db;
}

const str = (v, max) => (typeof v === 'string' ? v.slice(0, max) : undefined);

export async function start(env = process.env) {
  // The collector logs to stdout only; shipping its own logs to itself would loop.
  const logger = createLogger({ service: SERVICE, level: env.LOG_LEVEL, collectorUrl: null });
  const port = Number(env.PORT || 4004);
  const retentionHours = Number(env.LOG_RETENTION_HOURS || 72);
  const db = openDatabase(env.DB_PATH || './data/logs.db');

  const insert = db.prepare('INSERT INTO logs (ts, level, service, msg, request_id, data) VALUES (?, ?, ?, ?, ?, ?)');
  const purge = db.prepare('DELETE FROM logs WHERE ts < ?');

  const app = express();
  app.disable('x-powered-by');
  app.use(requestId());
  app.use(accessLog(logger, { skip: ['/health', '/ready', '/ingest'] }));
  registerHealth(app, { service: SERVICE, checks: { database: () => db.prepare('SELECT 1').get() } });
  app.use(express.json({ limit: '2mb', verify: captureRawBody }));
  app.use(requireInternal({ secret: env.INTERNAL_SECRET, logger }));

  app.post('/ingest', requireScope('logs:write'), (req, res) => {
    const batch = req.body;
    if (!Array.isArray(batch) || batch.length > MAX_BATCH) {
      throw new HttpError(400, `Body must be an array of at most ${MAX_BATCH} records`);
    }
    let accepted = 0;
    db.exec('BEGIN');
    try {
      for (const rec of batch) {
        if (!rec || typeof rec !== 'object') continue;
        const { ts, level, service, msg, requestId: rid, ...rest } = rec;
        const when = str(ts, 40);
        if (!when || Number.isNaN(Date.parse(when)) || !LEVELS.includes(level) || !str(service, 64)) continue;
        insert.run(when, level, str(service, 64), str(msg, 2000) ?? '', str(rid, 64) ?? null, JSON.stringify(rest).slice(0, 8192));
        accepted += 1;
      }
      db.exec('COMMIT');
    } catch (err) {
      db.exec('ROLLBACK');
      throw err;
    }
    res.status(202).json({ accepted, rejected: batch.length - accepted });
  });

  app.get('/logs', requireScope('logs:read'), (req, res) => {
    const where = [];
    const params = [];
    const add = (sql, value) => { where.push(sql); params.push(value); };
    if (req.query.service) add('service = ?', String(req.query.service));
    if (req.query.requestId) add('request_id = ?', String(req.query.requestId));
    if (req.query.level) {
      const min = LEVELS.indexOf(String(req.query.level));
      if (min < 0) throw new HttpError(400, `level must be one of ${LEVELS.join(', ')}`);
      const allowed = LEVELS.slice(min);
      where.push(`level IN (${allowed.map(() => '?').join(',')})`);
      params.push(...allowed);
    }
    if (req.query.since) {
      const since = Date.parse(String(req.query.since));
      if (Number.isNaN(since)) throw new HttpError(400, 'since must be an ISO-8601 timestamp');
      add('ts >= ?', new Date(since).toISOString());
    }
    if (req.query.q) add('msg LIKE ?', `%${String(req.query.q).slice(0, 100)}%`);
    const limit = intParam(req.query.limit, { name: 'limit', min: 1, max: 500, fallback: 100 });
    const sql = `SELECT * FROM logs ${where.length ? `WHERE ${where.join(' AND ')}` : ''} ORDER BY ts DESC, id DESC LIMIT ?`;
    const rows = db.prepare(sql).all(...params, limit);
    res.json({
      items: rows.map((r) => ({ ts: r.ts, level: r.level, service: r.service, msg: r.msg, requestId: r.request_id, ...JSON.parse(r.data) })),
      count: rows.length,
    });
  });

  app.get('/logs/stats', requireScope('logs:read'), (req, res) => {
    const since = new Date(Date.now() - 3600_000).toISOString();
    const rows = db.prepare(`SELECT service, level, COUNT(*) AS n FROM logs WHERE ts >= ? GROUP BY service, level`).all(since);
    const byService = {};
    for (const r of rows) (byService[r.service] ??= {})[r.level] = r.n;
    res.json({ window: 'last 1h', byService });
  });

  app.use(notFound());
  app.use(errorHandler(logger));

  const retention = setInterval(() => {
    const { changes } = purge.run(new Date(Date.now() - retentionHours * 3600_000).toISOString());
    if (changes) logger.info('purged old logs', { removed: changes });
  }, 600_000);
  retention.unref();

  const server = app.listen(port, () => logger.info('listening', { port, retentionHours }));
  return { app, server, logger, close: async () => { clearInterval(retention); db.close(); } };
}
