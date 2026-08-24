// Role-based access control model shared by the auth server (which mints scopes)
// and every service (which enforces them).
//
// Roles are coarse groupings; permissions are expressed as OAuth 2.0 scopes.
// At token issuance, granted scopes = role permissions ∩ requested scopes ∩ client's
// allowed scopes, so a token never carries more than the user, the request, and
// the client application are all entitled to (least privilege).

export const ROLE_PERMISSIONS = Object.freeze({
  user: ['profile:read', 'products:read', 'orders:read', 'orders:write'],
  admin: [
    'profile:read', 'products:read', 'products:write',
    'orders:read', 'orders:write', 'orders:read:all', 'orders:manage',
    'users:read', 'users:manage', 'logs:read', 'metrics:read',
  ],
  service: [],
});

export const ALL_SCOPES = Object.freeze([...new Set(Object.values(ROLE_PERMISSIONS).flat())].sort());

export function isKnownRole(role) {
  return Object.hasOwn(ROLE_PERMISSIONS, role);
}

export function scopesForRoles(roles = []) {
  return [...new Set(roles.filter(isKnownRole).flatMap((r) => ROLE_PERMISSIONS[r]))].sort();
}

export function intersect(a, b) {
  const set = new Set(b);
  return [...new Set(a)].filter((x) => set.has(x)).sort();
}

export function hasScope(identity, scope) {
  return Boolean(identity?.scopes?.includes(scope));
}

/** Express middleware: the signed caller identity must hold every listed scope. */
export function requireScope(...scopes) {
  return (req, res, next) => {
    const missing = scopes.filter((s) => !hasScope(req.identity, s));
    if (missing.length) {
      return res.status(403).json({ error: 'forbidden', message: `Missing scope: ${missing.join(' ')}` });
    }
    next();
  };
}
