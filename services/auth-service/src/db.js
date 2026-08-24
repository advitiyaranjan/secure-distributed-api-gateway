import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

export function openDatabase(file) {
  if (file !== ':memory:') mkdirSync(dirname(file), { recursive: true });
  const db = new DatabaseSync(file);
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS users (
      id            TEXT PRIMARY KEY,
      username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
      password_hash TEXT NOT NULL,
      roles         TEXT NOT NULL,           -- JSON array
      created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    );

    CREATE TABLE IF NOT EXISTS clients (
      client_id     TEXT PRIMARY KEY,
      name          TEXT NOT NULL,
      type          TEXT NOT NULL CHECK (type IN ('public', 'confidential')),
      secret_hash   TEXT,
      grant_types   TEXT NOT NULL,           -- JSON array
      scopes        TEXT NOT NULL,           -- JSON array: max scopes this client may obtain
      redirect_uris TEXT NOT NULL DEFAULT '[]'
    );

    -- Opaque refresh tokens, stored only as SHA-256 hashes. Rotated on every use;
    -- tokens from one login share a family so reuse of an old token kills the family.
    CREATE TABLE IF NOT EXISTS refresh_tokens (
      token_hash  TEXT PRIMARY KEY,
      family_id   TEXT NOT NULL,
      user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      client_id   TEXT NOT NULL,
      scopes      TEXT NOT NULL,
      expires_at  INTEGER NOT NULL,
      revoked     INTEGER NOT NULL DEFAULT 0,
      created_at  INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_refresh_family ON refresh_tokens(family_id);

    CREATE TABLE IF NOT EXISTS auth_codes (
      code_hash       TEXT PRIMARY KEY,
      client_id       TEXT NOT NULL,
      user_id         TEXT NOT NULL,
      redirect_uri    TEXT NOT NULL,
      code_challenge  TEXT NOT NULL,
      scopes          TEXT NOT NULL,
      expires_at      INTEGER NOT NULL,
      used            INTEGER NOT NULL DEFAULT 0
    );
  `);
  return db;
}

export function rowToUser(row) {
  return row && { id: row.id, username: row.username, roles: JSON.parse(row.roles), createdAt: row.created_at };
}

export function rowToClient(row) {
  return row && {
    clientId: row.client_id,
    name: row.name,
    type: row.type,
    secretHash: row.secret_hash,
    grantTypes: JSON.parse(row.grant_types),
    scopes: JSON.parse(row.scopes),
    redirectUris: JSON.parse(row.redirect_uris),
  };
}
