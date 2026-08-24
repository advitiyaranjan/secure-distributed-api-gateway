import express from 'express';
import { HttpError } from '../../../shared/http.js';
import { isKnownRole, requireScope } from '../../../shared/rbac.js';
import { intParam, validate } from '../../../shared/validate.js';

const registerSchema = {
  username: { type: 'string', required: true, min: 3, max: 32, pattern: /^[A-Za-z0-9_.-]+$/ },
  // Length over complexity rules (NIST SP 800-63B); max bounds the scrypt input.
  password: { type: 'string', required: true, min: 10, max: 128, trim: false },
};

const rolesSchema = {
  roles: { type: 'array', required: true, min: 1, max: 5, items: { type: 'string', max: 32 } },
};

export function usersRouter({ repo, logger }) {
  const router = express.Router();

  // Self-service sign-up always yields the least-privileged role.
  router.post('/register', async (req, res) => {
    const { username, password } = validate(registerSchema, req.body ?? {});
    if (repo.findUserByName(username)) throw new HttpError(409, 'Username is already taken', { code: 'conflict' });
    const user = await repo.createUser({ username, password, roles: ['user'] });
    logger.info('user registered', { userId: user.id, requestId: req.id });
    res.status(201).json(user);
  });

  router.get('/me', requireScope('profile:read'), (req, res) => {
    const user = repo.findUserById(req.identity.sub);
    if (!user) throw new HttpError(404, 'User not found', { code: 'not_found' });
    res.json({ ...user, scopes: req.identity.scopes });
  });

  router.get('/users', requireScope('users:read'), (req, res) => {
    const limit = intParam(req.query.limit, { name: 'limit', min: 1, max: 100, fallback: 50 });
    const offset = intParam(req.query.offset, { name: 'offset', fallback: 0 });
    res.json({ ...repo.listUsers(limit, offset), limit, offset });
  });

  router.patch('/users/:id/roles', requireScope('users:manage'), (req, res) => {
    const { roles } = validate(rolesSchema, req.body ?? {});
    const unknown = roles.filter((r) => !isKnownRole(r) || r === 'service');
    if (unknown.length) throw new HttpError(400, `Unknown role: ${unknown.join(', ')}`, { code: 'validation_error' });
    if (req.params.id === req.identity.sub && !roles.includes('admin')) {
      throw new HttpError(400, 'Admins cannot remove their own admin role', { code: 'validation_error' });
    }
    if (!repo.setRoles(req.params.id, [...new Set(roles)])) throw new HttpError(404, 'User not found', { code: 'not_found' });
    logger.warn('audit: user roles changed', { targetUserId: req.params.id, roles, by: req.identity.sub, requestId: req.id });
    res.json(repo.findUserById(req.params.id));
  });

  return router;
}
