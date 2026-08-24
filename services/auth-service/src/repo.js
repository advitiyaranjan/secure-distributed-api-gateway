import { randomUUID } from 'node:crypto';
import { hashPassword } from '../../../shared/crypto.js';
import { rowToClient, rowToUser } from './db.js';

export function createRepo(db) {
  const s = {
    userByName: db.prepare('SELECT * FROM users WHERE username = ?'),
    userById: db.prepare('SELECT * FROM users WHERE id = ?'),
    listUsers: db.prepare('SELECT * FROM users ORDER BY created_at LIMIT ? OFFSET ?'),
    countUsers: db.prepare('SELECT COUNT(*) AS n FROM users'),
    insertUser: db.prepare('INSERT INTO users (id, username, password_hash, roles) VALUES (?, ?, ?, ?)'),
    setRoles: db.prepare('UPDATE users SET roles = ? WHERE id = ?'),
    client: db.prepare('SELECT * FROM clients WHERE client_id = ?'),
    upsertClient: db.prepare(`INSERT INTO clients (client_id, name, type, secret_hash, grant_types, scopes, redirect_uris)
      VALUES (?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(client_id) DO UPDATE SET name = excluded.name, type = excluded.type, secret_hash = excluded.secret_hash,
        grant_types = excluded.grant_types, scopes = excluded.scopes, redirect_uris = excluded.redirect_uris`),
    insertCode: db.prepare(`INSERT INTO auth_codes (code_hash, client_id, user_id, redirect_uri, code_challenge, scopes, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)`),
    getCode: db.prepare('SELECT * FROM auth_codes WHERE code_hash = ?'),
    useCode: db.prepare('UPDATE auth_codes SET used = 1 WHERE code_hash = ? AND used = 0'),
  };

  return {
    findUserByName: (username) => {
      const row = s.userByName.get(username);
      return row && { ...rowToUser(row), passwordHash: row.password_hash };
    },
    findUserById: (id) => rowToUser(s.userById.get(id)),
    listUsers: (limit, offset) => ({ items: s.listUsers.all(limit, offset).map(rowToUser), total: s.countUsers.get().n }),
    async createUser({ username, password, roles }) {
      const id = randomUUID();
      s.insertUser.run(id, username, await hashPassword(password), JSON.stringify(roles));
      return rowToUser(s.userById.get(id));
    },
    setRoles: (id, roles) => s.setRoles.run(JSON.stringify(roles), id).changes === 1,
    findClient: (clientId) => rowToClient(s.client.get(clientId)),
    async upsertClient({ clientId, name, type, secret, grantTypes, scopes, redirectUris = [] }) {
      s.upsertClient.run(
        clientId, name, type, secret ? await hashPassword(secret) : null,
        JSON.stringify(grantTypes), JSON.stringify(scopes), JSON.stringify(redirectUris),
      );
    },
    saveAuthCode: (c) => s.insertCode.run(c.codeHash, c.clientId, c.userId, c.redirectUri, c.codeChallenge, JSON.stringify(c.scopes), c.expiresAt),
    getAuthCode: (codeHash) => s.getCode.get(codeHash),
    markCodeUsed: (codeHash) => s.useCode.run(codeHash).changes === 1,
  };
}
