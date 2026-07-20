# AuthKit — Performance Analysis

**Project:** AuthKit — Express 5 + Prisma 7 (PostgreSQL via `@prisma/adapter-pg`) + Redis (ioredis) auth microservice.
**Scope:** Backend services, data layer, Prisma schema, Redis usage, build artifact, and infrastructure. Read-only.
**Date:** 2026-07-03

> **Note on the "Frontend" section.** This repository is a **backend-only API** — there is no client bundle in the tree. The frontend-performance checklist (bundle size, code-splitting, hydration, re-renders, image/font optimization) is therefore **Not Applicable**. The equivalent build-artifact concerns for this service (tsup output, sourcemaps, image size) are captured under Infrastructure (`LT-4`, `LT-5`).

## Headline

The single highest-ROI issue is that the **`Session` table has no secondary indexes** (only `token` is `@unique`), yet nearly every service filters `Session` by `userId`, and the JWT authentication middleware — the hottest code path in the service — loads a user _with all their sessions_ on every cache miss. Fixing the indexes and the auth-path query (`QW-1`, `QW-2`, `QW-3`) addresses the bulk of the real-world latency risk.

---

# Quick Wins (< 1 day)

## QW-1 — Add missing indexes on `Session` (highest ROI in the repo)

### Problem

`prisma/schema.prisma` defines `Session` with `@unique` only on `token`. There is no index on `userId`, `deviceFingerprint`, `expiresAt`, or `isRevoked` — yet almost every session query filters by `userId`.

### Impact

Postgres performs a **sequential scan** of the `session` table for every session lookup. Cost grows linearly with the total number of sessions across _all_ users, degrading login, refresh, logout, admin operations, and the per-request auth path.

### Current Implementation

`prisma/schema.prisma:62-82` — no `@@index`. Affected queries: `metadata.ts:~59` (`checkForNewDevice`), `session.service.ts:~21,~116`, `admin.service.ts:~108,~120,~226`, `auth.service.ts:~462,~478`.

### Better Implementation

```prisma
model Session {
  // ...existing fields...
  @@index([userId])
  @@index([userId, deviceFingerprint])    // checkForNewDevice
  @@index([userId, isRevoked, expiresAt]) // active-session listing
  @@map("session")
}
```

Then `pnpm db:migrate` (or `db:push`).

### Expected Performance Gain

Session lookups move from O(N) seq-scan to O(log N) index scan — on a table with 100k+ rows, a 10–100× latency reduction on every login/refresh/auth-miss.

### Priority

**High.**

---

## QW-2 — `checkForNewDevice` runs unindexed on every login

### Problem

`checkForNewDevice` runs `prisma.session.findFirst({ where: { userId, deviceFingerprint } })` on the login critical path, with no supporting index.

### Impact

Adds a full sequential scan to _every_ successful credential / OAuth / magic-link / MFA login.

### Current Implementation

`src/core/common/utils/metadata.ts:55-67`:

```ts
const existingSession = await prisma.session.findFirst({
  where: { userId, deviceFingerprint },
});
```

### Better Implementation

Covered by the `@@index([userId, deviceFingerprint])` from QW-1; add `select: { id: true }` to avoid hydrating the full row.

### Expected Performance Gain

Removes a seq-scan from every login; sub-millisecond with the index.

### Priority

**High.**

---

## QW-3 — JWT auth caches the full user with ALL sessions on every cache miss

### Problem

The JWT strategy (runs on every authenticated request) fetches `prisma.user.findUnique({ where: { id }, include: { sessions: true } })`, finds the session in JS, and caches the entire user-with-all-sessions blob in Redis.

### Impact

1. Loads _every_ session a user has ever had into memory on each miss (unbounded — no expiry/revocation filter).
2. Caches a large blob keyed by a single session, wasting Redis memory and serialization CPU.
3. (Also a security issue — see `security-audit.md` SEC-H2 — it caches the password hash and 2FA secret.)

### Current Implementation

`src/core/common/strategies/jwt.strategy.ts:36-57`:

```ts
const user = await prisma.user.findUnique({
  where: { id: payload.userId },
  include: { sessions: true },
});
const session = user.sessions.find(s => s.id === payload.sessionId);
// ...
await setCache(`session:${payload.sessionId}`, JSON.stringify(user), ONE_DAY);
```

### Better Implementation

Fetch only the single session by primary key and a sanitized user, and filter validity in the DB:

```ts
const session = await prisma.session.findUnique({
  where: { id: payload.sessionId },
  include: { user: { select: { id: true, email: true, name: true, role: true, enable2FA: true } } },
});
if (
  !session ||
  session.userId !== payload.userId ||
  session.isRevoked ||
  session.expiresAt < new Date()
)
  return done(null, false);
const { user, ...sessionMeta } = session;
const value = { ...user, sessions: [sessionMeta] };
await setCache(`session:${payload.sessionId}`, JSON.stringify(value), ONE_DAY);
return done(null, value);
```

`Session.id` is the PK, so this is an index hit regardless of QW-1.

### Expected Performance Gain

Constant-size query and cache value regardless of session history; eliminates the unbounded `sessions` load and shrinks Redis memory/serialization on the hottest path.

### Priority

**High.**

---

## QW-4 — Sequential (and blocking) emails in `register()`

### Problem

`register` awaits the verification email and the welcome email sequentially, and blocks the HTTP response on email delivery.

### Impact

Response latency = verification-email RTT + welcome-email RTT (serial). Resend calls are network-bound (~hundreds of ms each).

### Current Implementation

`src/api/v1/services/auth.service.ts:103-111` — two sequential `await this.emailService....` calls guarded by `NODE_ENV === 'production'`.

### Better Implementation

```ts
if (config.NODE_ENV === 'production') {
  await Promise.all([
    this.emailService.sendEmailVerification(email, verificationUrl, name),
    this.emailService.sendWelcomeEmail(email, name),
  ]);
}
```

Better still, move email delivery to a background queue (see `feature-recommendations.md` — background jobs) so registration does not block on email at all.

### Expected Performance Gain

~2× faster email phase; ~1 email RTT removed from register latency (and near-zero if queued).

### Priority

**Medium.**

---

## QW-5 — bcrypt runs _inside_ the register transaction

### Problem

`register` opens a Prisma `$transaction`, then calls `await hashPassword(password)` (bcrypt, ~100 ms CPU-bound) inside it before creating the account row.

### Impact

The transaction holds a DB connection (and any row locks) open for the full bcrypt duration, reducing connection-pool throughput under load — compounded by the default pool size of 10 (see LT-3).

### Current Implementation

`src/api/v1/services/auth.service.ts:72-90`:

```ts
const newUser = await prisma.$transaction(async tx => {
  const newUser = await tx.user.create({
    /* ... */
  });
  const hashedPassword = await hashPassword(password); // ~100ms inside txn
  await tx.account.create({ data: { /* ..., */ password: hashedPassword } });
  return newUser;
});
```

### Better Implementation

```ts
const hashedPassword = await hashPassword(password); // before the txn
const newUser = await prisma.$transaction(async tx => {
  const u = await tx.user.create({
    /* ... */
  });
  await tx.account.create({ data: { userId: u.id, /* ..., */ password: hashedPassword } });
  return u;
});
```

### Expected Performance Gain

Cuts transaction/connection hold time by ~100 ms per registration; materially better pool utilization under concurrency.

### Priority

**Medium.**

---

## QW-6 — Sequential Redis `deleteCache` loops (revoke-all flows)

### Problem

Several flows loop over sessions and `await deleteCache(...)` one at a time — N sequential Redis round-trips.

### Impact

For a user with M active sessions, revocation costs M serial round-trips. Affects `resetPassword`, `changePassword`, revoke-all-sessions, and admin session revocation.

### Current Implementation

Repeated pattern at `auth.service.ts:~488-490`, `session.service.ts:~130-132`, `admin.service.ts:~131-133`:

```ts
for (const session of activeSessions) {
  await deleteCache(`session:${session.id}`);
}
```

### Better Implementation

```ts
// redis-helpers.ts
export const deleteCacheMany = async (keys: string[]) => {
  if (keys.length) await redis.del(...keys);
};
// callers
await deleteCacheMany(activeSessions.map(s => `session:${s.id}`));
```

### Expected Performance Gain

M round-trips → 1. Meaningful for users with many sessions and removes serial latency from revoke-all flows.

### Priority

**Medium.**

---

## QW-7 — Redis client has no resilience configuration

### Problem

`new Redis({ host, port })` with no `maxRetriesPerRequest`, `enableReadyCheck`, `retryStrategy`, or `connectTimeout`. The same client backs `rate-limit-redis` and every cache read.

### Impact

Default ioredis behavior can queue commands unbounded during a connection blip; no tuned backoff. A Redis hiccup can pile up commands and spike latency across auth and rate limiting.

### Current Implementation

`src/core/database/redis.ts:5-10`.

### Better Implementation

```ts
const redisClient = new Redis({
  host: config.REDIS.HOST,
  port: Number(config.REDIS.PORT),
  maxRetriesPerRequest: 3,
  enableReadyCheck: true,
  connectTimeout: 10_000,
  retryStrategy: times => Math.min(times * 200, 2_000),
});
```

(Also add `password`/TLS per SEC-H5.)

### Expected Performance Gain

Predictable failure behavior; avoids command pile-up and latency spikes during Redis instability.

### Priority

**Low.**

---

## QW-8 — `getAppVersion` dynamically imports `package.json` on every health call

### Problem

`getAppVersion` does `await import('../../../../package.json')` per call; used by both health endpoints, which load balancers poll frequently.

### Impact

Repeated dynamic import + module resolution on a hot polling endpoint; pulls `package.json` into the bundle graph.

### Current Implementation

`src/core/common/utils/metadata.ts:16-23`.

### Better Implementation

Read `process.env.npm_package_version`, or cache the value in a module-level constant on first read.

### Expected Performance Gain

Removes filesystem/module work from every health poll.

### Priority

**Low.**

---

# Medium Improvements (1–3 days)

## M-1 — No pagination on list endpoints

**Problem:** `admin.getAllUsers` does `findMany({ orderBy })` over the entire `user` table; `getSessions`/`getUserSessions` return all matching sessions unbounded.
**Impact:** Unbounded DB reads, JSON serialization, and network transfer that degrade (and eventually OOM/timeout) as data grows.
**Current:** `admin.service.ts:~182-184`, `session.service.ts:~21-30`, `admin.service.ts:~226-235`.
**Better:** Add cursor/offset pagination (`take` + `skip`/`cursor`) with a sane default page size, and populate the `X-Total-Count`/`X-Page-Count` headers already declared in CORS `exposedHeaders` (`src/api/index.ts:65`) but never set.
**Gain:** Bounded, predictable query/serialization cost. **Priority: Medium.**

## M-2 — `getSessionById` Redis fast-path is unreliable

**Problem:** Reads `session:<id>`, `JSON.parse`, then searches `user.sessions?.find(...)` — the cached blob's shape is coupled to the auth-user cache (QW-3), so the fast-path frequently misses and falls through to a DB query anyway, after a wasted Redis round-trip.
**Impact:** A frequently-useless Redis round-trip plus a DB read.
**Current:** `src/api/v1/services/session.service.ts:49-71`.
**Better:** Either cache session metadata under its own dedicated key shape and read it directly, or drop the Redis attempt here (the DB read is on PK `id`, already fast). Decouple the session-cache shape from the auth-user cache shape.
**Gain:** Removes a wasted round-trip; deterministic caching. **Priority: Medium.**

## M-3 — Redundant pre-fetch queries before writes

**Problem:** Several flows `findUnique` to check existence, then issue a separate write that would already fail on a missing row.

- `resetPassword` (`auth.service.ts:~443`) fetches the user before an `updateMany` scoped by email.
- `admin.deleteUser` (`admin.service.ts:~51`) does `findUnique` then `delete`.
- `promoteUserToAdmin` (`admin.service.ts:~25`) does `findUnique` then `update`.
  **Impact:** One extra DB round-trip per operation.
  **Better:** Rely on `update`/`delete` throwing `P2025` (catch → NotFound), or use `updateMany` and check `count`.
  **Gain:** ~1 fewer round-trip per admin/reset op. **Priority: Low–Medium.**

## M-4 — Dev compose runs `db:push` on every container start

**Problem:** `docker-compose.dev.yml` builds `target: deps`, bind-mounts the repo, and runs `pnpm db:generate && pnpm db:push && pnpm dev` on each start.
**Impact:** `db:push` on every start adds startup latency and risks schema drift.
**Better:** Add a dedicated lightweight `dev` build stage and run `db:push` as a one-shot init service (mirroring the prod `migrator`) rather than every start.
**Gain:** Faster, more deterministic dev startup. **Priority: Low.**

---

# Long-term Optimizations

## LT-1 — Compression is default gzip only

**Problem:** `app.use(compression())` — default gzip, no Brotli, no `threshold`/`level` tuning.
**Impact:** JSON responses and Swagger UI compress better with Brotli; default settings also compress tiny responses where overhead exceeds benefit.
**Current:** `src/api/index.ts:35`.
**Better:** Terminate compression/Brotli at a reverse proxy (nginx/Caddy/LB); if kept in-app, set `threshold: 1024`. **Priority: Low.**

## LT-2 — No HTTP/2 or reverse proxy in front of Node

**Problem:** `app.listen` serves HTTP/1.1 directly; both compose files map the Node port to the host with no TLS/HTTP-2 terminator — despite `oidc.config.ts` setting `provider.proxy = true` (which assumes a proxy exists).
**Impact:** No HTTP/2 multiplexing or header compression; TLS and connection concurrency unmanaged.
**Better:** Front with nginx/Caddy/Traefik for TLS, HTTP/2, and compression. **Priority: Low.**

## LT-3 — Prisma `pg.Pool` uses all defaults (max 10, no timeouts)

**Problem:** `new Pool({ connectionString })` — no `max`, `idleTimeoutMillis`, `connectionTimeoutMillis`, or statement timeout (default pool max is 10).
**Impact:** Under concurrency, requests queue on 10 connections with no fast-fail; a slow query (e.g. bcrypt-in-transaction, QW-5) holds a connection and starves others.
**Current:** `src/core/database/prisma.ts:8`.
**Better:** Size the pool to workload (`max`, `connectionTimeoutMillis`, `idleTimeoutMillis`, statement timeout) aligned with Postgres `max_connections`.
**Gain:** Predictable behavior under load. **Priority: Medium** (raised from Low because it compounds QW-5).

## LT-4 — Build artifact: sourcemaps in prod, target mismatch

**Problem:** `tsup.config.ts` emits ESM with `sourcemap: true`, no `minify`, `target: 'es2022'`, while `tsconfig.json` targets `es2021`. Prod images ship sourcemaps.
**Impact:** Larger `dist/` and Docker layer; sourcemaps leak source structure into the production image.
**Better:** Gate `sourcemap` to non-prod (or emit external maps not copied into the runner), align `tsup.target` with the Node 22 runtime and tsconfig, consider `minify: true`. **Priority: Low.**

## LT-5 — Dockerfile: no pnpm store cache mount; native-module compat only at build

**Problem:** No BuildKit cache mount for the pnpm store, so installs aren't cached across builds beyond layer caching. `libc6-compat` is installed in `deps` but not in the `runner` stage that actually runs native modules (bcrypt).
**Impact:** Slower CI rebuilds; potential native-module runtime risk in `runner`.
**Current:** `Dockerfile:15-19,42,47-59`.
**Better:** `RUN --mount=type=cache,target=/pnpm/store pnpm install`; verify bcrypt loads in `runner` (add `libc6-compat` there if needed). The multi-stage layout and non-root user are otherwise good. **Priority: Low.**

## LT-6 — Logger: dual transports + per-line JSON stringify in all envs

**Problem:** Winston runs both a colorized console transport and a daily-rotate file transport in every environment; `logFormat` `JSON.stringify(metadata)` per line.
**Impact:** Under high request volume, per-line stringify + dual transports add CPU/I/O; file logging writes to a stateful `logs/` dir inside the container.
**Current:** `src/core/common/utils/logger.ts:9-40`.
**Better:** In production, log to stdout only (let the platform collect), drop the file transport and colorize; consider `pino` if throughput is high. **Priority: Low.**

---

## Already Fine (verified — no action needed)

- OTP / verification / magic-link tokens correctly use Redis with TTLs (not the DB).
- `incrementCache` uses atomic `INCR` + conditional `EXPIRE` — correct.
- Rate limiting uses a shared Redis store — correct for horizontal scaling.
- `User.email` and `Session.token` are `@unique` (indexed); `Account` has `@@unique([providerId, accountId])`. The `include: { accounts: { where: { providerId } } }` filter operates over a user's tiny account set — not a real N+1.
- MFA backup-code loop does ≤ 5 sequential bcrypt compares, short-circuited by a TOTP check first — acceptable.

## Top 3 to do first

1. **QW-1 + QW-2** — add `@@index([userId])` and `@@index([userId, deviceFingerprint])` to `Session` (biggest win, ~2 lines).
2. **QW-3** — fetch a single session by PK in the JWT strategy instead of the full user + all sessions (hottest path).
3. **QW-5 + QW-6** — move bcrypt out of the register transaction and batch the Redis session deletions.
