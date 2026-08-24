// Route table: which prefix goes to which backend, and who may do what there.
//
// Policies are evaluated top-down; the first one whose methods + path match decides.
// Anything that matches no policy is denied (default deny). A policy may require
// roles (any-of) and/or scopes (all-of), or be explicitly `public`.

const WRITE = ['POST', 'PUT', 'PATCH', 'DELETE'];

export function buildRoutes(upstreams) {
  return [
    {
      name: 'auth',
      prefix: '/auth',
      target: upstreams.auth,
      rewrite: '',
      // Client credentials travel in `Authorization: Basic` on the token endpoint.
      forwardAuthorization: true,
      policies: [
        { methods: ['GET'], path: /^\/me$/, scopes: ['profile:read'] },
        { methods: ['POST'], path: /^\/(oauth\/(token|authorize)|register)$/, public: true, rateLimitTier: 'auth' },
        { methods: ['POST'], path: /^\/oauth\/(revoke|introspect)$/, public: true },
        { methods: ['GET'], path: /^\/\.well-known\/(jwks\.json|oauth-authorization-server)$/, public: true },
      ],
    },
    {
      name: 'products',
      prefix: '/api/products',
      target: upstreams.products,
      rewrite: '/products',
      // Catalogue responses are identical for every caller, so one shared cache entry serves all.
      cache: { ttlSeconds: 60 },
      policies: [
        { methods: ['GET'], path: /^\/_stats$/, roles: ['admin'], scopes: ['metrics:read'], cache: false },
        { methods: ['GET'], scopes: ['products:read'] },
        { methods: WRITE, roles: ['admin'], scopes: ['products:write'] },
      ],
    },
    {
      name: 'orders',
      prefix: '/api/orders',
      target: upstreams.orders,
      rewrite: '/orders',
      policies: [
        { methods: ['GET'], scopes: ['orders:read'] },
        { methods: ['POST'], path: /^\/?$/, scopes: ['orders:write'] },
        { methods: ['PATCH'], path: /^\/[^/]+\/status$/, roles: ['admin'], scopes: ['orders:manage'] },
      ],
    },
    {
      name: 'admin-users',
      prefix: '/admin/users',
      target: upstreams.auth,
      rewrite: '/users',
      policies: [
        { methods: ['GET'], path: /^\/?$/, roles: ['admin'], scopes: ['users:read'] },
        { methods: ['PATCH'], path: /^\/[^/]+\/roles$/, roles: ['admin'], scopes: ['users:manage'] },
      ],
    },
    {
      name: 'admin-logs',
      prefix: '/admin/logs',
      target: upstreams.logs,
      rewrite: '/logs',
      policies: [{ methods: ['GET'], roles: ['admin'], scopes: ['logs:read'] }],
    },
  ];
}

export function matchRoute(routes, path) {
  for (const route of routes) {
    if (path === route.prefix || path.startsWith(`${route.prefix}/`)) {
      return { route, subPath: path.slice(route.prefix.length) || '/' };
    }
  }
  return null;
}

export function findPolicy(route, method, subPath) {
  const m = method === 'HEAD' ? 'GET' : method;
  return route.policies.find((p) => p.methods.includes(m) && (!p.path || p.path.test(subPath))) ?? null;
}

/** Returns { allow: true } or { allow: false, status, reason }. */
export function authorize(policy, identity) {
  if (!policy) return { allow: false, status: 403, reason: 'No policy permits this request' };
  if (policy.public) return { allow: true };
  if (!identity) return { allow: false, status: 401, reason: 'Authentication required' };
  if (policy.roles && !policy.roles.some((r) => identity.roles.includes(r))) {
    return { allow: false, status: 403, reason: `Requires role: ${policy.roles.join(' or ')}` };
  }
  const missing = (policy.scopes ?? []).filter((s) => !identity.scopes.includes(s));
  if (missing.length) return { allow: false, status: 403, reason: `Missing scope: ${missing.join(' ')}`, insufficientScope: missing };
  return { allow: true };
}
