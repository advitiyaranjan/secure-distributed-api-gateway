# Secure Distributed API Gateway

A containerized API gateway that routes requests to several backend services. It covers OAuth 2.0 / JWT authentication, role-based access control, Redis-backed rate limiting and response caching, HTTPS, service-to-service request signing, health checks, centralized logging and load testing.

```
                     ┌─────────────────────────── edge network ───────────────────────────┐
  client ──HTTPS──▶  │  gateway :8443  (HTTP :8080 → 308 redirect)                         │
                     └───────┬────────────────────────────────────────────────────────────┘
                             │  HMAC-signed requests, X-Request-Id propagated
  ┌──────────────────────────┼──────────── backend network (internal: no host/internet) ───┐
  │                          ▼                                                             │
  │   auth-service :4001 ── OAuth 2.0 server, RS256 JWT issuer, JWKS, users ──┐            │
  │   product-service :4002 ── catalogue (SQLite)                             ├── redis    │
  │   order-service :4003 ── orders, AES-GCM-encrypted PII ──▶ product-service│  (rate     │
  │   log-collector :4004 ◀── structured logs shipped by every service        │  limits,   │
  │                                                                           │  cache,    │
  │   gateway ────────────────────────────────────────────────────────────────┘  deny-list)│
  └────────────────────────────────────────────────────────────────────────────────────────┘
```

## Gateway request pipeline

`path safety → route match → authenticate JWT → rate limit → authorize (RBAC) → body checks → cache → signed forward → cache store/invalidate`

See [services/gateway/src/app.js](services/gateway/src/app.js). Authentication runs before the rate limiter so limits can be applied per user. If a token is invalid, the gateway records the failure but only rejects the request after the rate limiter has run, so floods of bad tokens are still throttled.

## Security concepts and where they live

| Concept | Implementation |
|---|---|
| **OAuth 2.0** | [oauth.js](services/auth-service/src/oauth.js): `authorization_code` + **PKCE S256**, `client_credentials`, `refresh_token`, and `password` (first-party only, can be disabled). Also token revocation (RFC 7009), introspection (RFC 7662) and server metadata (RFC 8414). Redirect URIs must match exactly. |
| **JWT** | Access tokens are RS256 with `typ: at+jwt` and a 15-minute lifetime. The private key stays in auth-service; the gateway verifies tokens against the **JWKS** endpoint and picks up rotated keys by `kid`. The accepted algorithm is pinned, so `alg=none` and HS/RS key-confusion tokens are rejected. Issuer, audience, expiry and required claims are all checked ([authenticator.js](services/gateway/src/authenticator.js)). |
| **Token lifecycle** | Refresh tokens are opaque and stored only as SHA-256 hashes. They rotate on every use, and reusing an old one revokes the whole token family. A revoked access token's `jti` goes on a Redis deny-list until it would have expired. |
| **Authentication hardening** | scrypt password hashing. After 5 failed logins an account is locked for 15 minutes; the counter lives in Redis, so the lockout holds across replicas. Unknown usernames still go through a scrypt check, so response timing doesn't reveal which accounts exist. Errors are generic. |
| **Authorization / RBAC** | Roles map to permissions expressed as OAuth scopes ([rbac.js](shared/rbac.js)). A token gets the role's permissions ∩ the client's allowed scopes ∩ the requested scopes. Gateway route policies require roles (any of) and scopes (all of), and anything without a matching policy is denied ([routes.js](services/gateway/src/routes.js)). Services check scopes again (defense in depth). Other users' orders return 404 to prevent ID probing (IDOR). |
| **HTTPS** | TLS 1.2+ on the gateway. Plain HTTP only issues a 308 redirect, and the redirect target comes from config, never the Host header. Responses carry HSTS. The gateway uses a self-signed certificate unless `TLS_CERT_PATH`/`TLS_KEY_PATH` are mounted. |
| **REST API security** | Helmet headers (strict CSP, nosniff, frame-deny, no-referrer); CORS allow-list; body size limit (413); only JSON/form bodies accepted (415); schema validation that rejects unknown fields (no mass assignment); parameterized SQL; path-traversal and encoded-separator blocking; `Cache-Control: no-store` on user data; header and request timeouts against slowloris. Clients cannot spoof identity headers because the gateway strips them. |
| **Rate limiting** | Redis sliding-window counter with O(1) memory per client, shared by all gateway replicas ([rateLimiter.js](services/gateway/src/rateLimiter.js)). Tiers: anonymous, user, service, admin, plus a strict per-IP `auth` tier for login, token and register. Responses carry `RateLimit-*` and `Retry-After` headers. Rejected requests don't use up quota. If Redis is down the limiter fails open, which is configurable. |
| **Caching** | Redis response cache for routes whose responses don't depend on the caller ([cache.js](services/gateway/src/cache.js)). Authorization is checked before the cache lookup. `X-Cache: HIT/MISS/BYPASS`, the client can send `Cache-Control: no-cache` to skip it, and any successful write invalidates the whole route. |
| **Encryption basics** | AES-256-GCM encrypts the shipping address at rest, with the order id as AAD so ciphertext can't be moved to another row. HMAC-SHA256 signs requests between services. scrypt is used for secrets, SHA-256 for stored tokens, and constant-time comparison everywhere ([crypto.js](shared/crypto.js)). |
| **Network protocols / zero trust** | Backends are on an `internal` Docker network. Every internal request still needs an HMAC signature over method, path, body hash, identity, request id and timestamp (30-second replay window) ([internal-auth.js](shared/internal-auth.js)). Hop-by-hop headers are stripped. `X-Forwarded-*` is set correctly. A per-upstream circuit breaker and timeouts cover failures. |

## Distributed-ops features

- **Health checks:** each service exposes `/health` (liveness) and `/ready` (readiness: DB, Redis, dependencies). Dockerfile `HEALTHCHECK` probes `/ready`, and compose uses `depends_on: service_healthy` for startup order. Admins can call `GET /health/services` for an aggregated view.
- **Centralized logging:** structured JSON goes to stdout and is also shipped in batches to `log-collector`. Shipping is bounded and non-blocking, and secrets and PII are redacted. Each request has an `X-Request-Id` that is passed from gateway → order-service → product-service. Search with `GET /admin/logs?requestId=…&level=warn&service=…`.
- **Metrics:** `GET /admin/metrics` returns request counts, status classes, cache hit ratio, rate-limit hits, upstream errors, p50/p95/p99 latency, a histogram, and circuit states.
- **Container hardening:** non-root user, read-only root filesystem, `cap_drop: ALL`, `no-new-privileges`, CPU/memory limits, log rotation, and Redis with a password and `noeviction`. Only the gateway publishes ports.

## Run it

**Docker** (verified on Docker Engine 29.8 / Compose v5.6: all six containers report healthy, and the e2e suite passes 35/35 against the stack):

```bash
npm run gen-env                     # writes .env with random secrets
docker compose up --build -d
docker compose ps                   # all services should become "healthy"
```

**Without Docker** (single process, in-memory Redis mock, useful for development):

```bash
npm install
npm run dev                         # https://localhost:8443
```

### Try it

```bash
# login (password grant; admin password is in .env, or admin-dev-password for npm run dev)
TOKEN=$(curl -sk https://localhost:8443/auth/oauth/token \
  -d grant_type=password -d client_id=web-app -d username=admin -d password="$ADMIN_PASSWORD" | jq -r .access_token)

curl -sk -i https://localhost:8443/api/products -H "Authorization: Bearer $TOKEN"        # X-Cache: MISS, then HIT
curl -sk https://localhost:8443/api/orders -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' -d '{"items":[{"productId":1,"quantity":2}],"shippingAddress":"1 Main St"}'
curl -sk "https://localhost:8443/admin/logs?level=warn" -H "Authorization: Bearer $TOKEN"
```

| Route | Upstream | Access |
|---|---|---|
| `POST /auth/register`, `/auth/oauth/{token,authorize,revoke,introspect}` | auth-service | public (`auth` rate tier on login/token/register) |
| `GET /auth/.well-known/{jwks.json,oauth-authorization-server}` | auth-service | public |
| `GET /auth/me` | auth-service | `profile:read` |
| `GET /api/products[/:id]` | product-service | `products:read` (cached 60s) |
| `POST/PUT/DELETE /api/products[/:id]` | product-service | role `admin` + `products:write` |
| `GET /api/orders[/:id]`, `?all=true` | order-service | `orders:read` (+ `orders:read:all`) |
| `POST /api/orders` | order-service | `orders:write` |
| `PATCH /api/orders/:id/status` | order-service | `admin` + `orders:manage` |
| `GET /admin/users`, `PATCH /admin/users/:id/roles` | auth-service | `admin` + `users:read` / `users:manage` |
| `GET /admin/logs[/stats]` | log-collector | `admin` + `logs:read` |
| `GET /admin/metrics`, `/health/services` | gateway | `admin` + `metrics:read` |

OAuth clients: `web-app` is a public client, so it must use PKCE; `reporting-service` is a confidential client using `client_credentials` with read-only access to all orders.

## Tests

```bash
npm test          # 23 unit tests: crypto, request signing, RBAC, validation, rate limiter, cache, circuit breaker, auth-service
npm run e2e       # 35 end-to-end checks against a running stack (docker compose or npm run dev)
```

The e2e suite covers the OAuth flows (PKCE, code replay, refresh-token reuse, revocation), tampered and `alg=none` JWTs, RBAC denials, spoofed identity headers, path traversal, 413/415 responses, cache hits and invalidation, encrypted PII never appearing in listings or logs, one request traced across three services in the central logs, CORS, and brute-force throttling. The auth rate tier allows 20 login/token calls per minute and the suite uses most of them, so wait a minute between runs.

## Load testing

```bash
docker compose -f docker-compose.yml -f docker-compose.loadtest.yml up --build -d
npm run loadtest                      # DURATION=10 CONNECTIONS=10,50,100 by default
```

This runs autocannon over: a `/health` baseline; product reads with and without the cache, counting DB queries; a concurrency sweep at 10/50/100 connections; order creation (the write path, including a service-to-service call and encryption); and a brute-force attack on the token endpoint. It writes a Markdown report to `loadtest/results/`.

**Measured result: Docker Compose stack.** Six containers with real Redis 7.4 and a 1-CPU / 256 MB limit per service, on Docker Engine 29.8 in WSL2 (Ubuntu 24.04). The load generator ran on the Windows host, going through WSL2 port forwarding. 5 ms simulated DB latency, 10 s per run, **0 errors across all runs**. The full report is in `loadtest/results/`.

| Scenario | Conns | Req/s | p50 ms | p99 ms | Notes |
|---|---|---|---|---|---|
| GET /health (baseline) | 50 | 5,172 | 6 | 63 | TLS + gateway only |
| GET /api/products, cache bypassed | 50 | 660 | 73 | 206 | 6,646 DB queries |
| GET /api/products, cached | 50 | 1,869 | 16 | 92 | **0 DB queries**, 100% hit ratio |
| GET /api/products, cached | 100 | 2,019 | 35 | 101 | throughput holds as concurrency doubles |
| POST /api/orders | 50 | 224 | 210 | 528 | JWT + validation + 2 product lookups + AES-GCM + write |
| Token endpoint brute force | 20 | 2,084 | 6 | 51 | 10,400 / 10,419 rejected with **429** at the gateway |

Caching gave **~2.8× the throughput and ~2.2× lower p99** on the read path and eliminated repeated DB reads. The rate limiter rejected 99.8% of a credential-stuffing burst at the gateway; only the 19 requests within the auth tier's per-minute allowance reached auth-service.

For comparison, the same suite on the single-process `npm run dev` stack (in-memory Redis mock, no container or network hops) reached 6,224 req/s cached vs 1,673 uncached (3.7×), at p99 10 ms vs 54 ms.

## Configuration

Secrets come from `.env` (see [.env.example](.env.example)). Other useful variables: `RATE_LIMIT_{ANONYMOUS,USER,SERVICE,ADMIN,AUTH}` (requests per minute), `RATE_LIMIT_MULTIPLIER` (does not apply to the auth tier), `RATE_LIMIT_FAIL_OPEN`, `REVOCATION_FAIL_OPEN` (default false: the gateway returns 503 if Redis is down rather than accept possibly-revoked tokens), `CORS_ORIGINS`, `ACCESS_TOKEN_TTL`, `TLS_CERT_PATH`/`TLS_KEY_PATH`, `TRUST_PROXY`, `SIMULATED_DB_LATENCY_MS`.

## Known limitations

- `/oauth/authorize` is headless: it takes credentials as JSON instead of rendering a login and consent page, so the code + PKCE flow can be scripted.
- Each service uses SQLite on its own volume, so the stateful services can't be horizontally scaled as-is. The gateway is stateless (all shared state is in Redis) and can be.
- Order creation checks stock but doesn't reserve or decrement it; that would need a saga or outbox pattern across services.
- The 30-second replay window on internal signatures has no nonce store, so a captured request could be replayed within that window on the internal network.
- `npm audit` reports a moderate advisory in `uuid`, which autocannon pulls in through `hyperid`. It only affects the load-test tool and isn't part of any service image.
