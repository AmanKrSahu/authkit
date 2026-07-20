# AuthKit — Scalability & Modern Feature Recommendations

**Project:** AuthKit — self-hostable Identity Provider / IAM microservice.
**Date:** 2026-07-03
**Benchmarks:** Auth0, Clerk, WorkOS, Supabase Auth, Better-Auth.

---

## 1. Architecture Summary

AuthKit is a **self-hostable Identity Provider (IdP) / IAM microservice** in Node/TypeScript that exposes two authentication surfaces:

1. **Direct REST auth** — first-party register / login / MFA / session management, issuing its own HS256 JWT access + refresh tokens.
2. **OIDC 1.0 / OAuth 2.0 Provider** — a standards-compliant IdP (via the certified `oidc-provider` library) enabling third-party apps to do SSO against AuthKit, with a "session bridge" that unifies the two surfaces.

**Tech stack:** Node.js + Express 5 (ESM, TypeScript, built with `tsup`); PostgreSQL via Prisma 7 (`@prisma/adapter-pg`); Redis via `ioredis` (session cache, OIDC state, rate-limit counters, ephemeral tokens); `bcrypt` (passwords, client secrets, backup codes); `jsonwebtoken` (HS256 first-party tokens); `oidc-provider` with RS256 JWKS; `speakeasy` + `qrcode` (TOTP); `passport` + `passport-google-oauth20`/`passport-jwt`; Zod validation; `swagger-jsdoc`/`swagger-ui-express`; Resend email; `helmet`/`cors`/`compression`/`express-rate-limit` + `rate-limit-redis`; Winston logging. **No test framework is present** (all `*.test.ts` matches are inside `node_modules`).

**Layered structure** (clean, DI-based):

```
                         ┌─────────────────────────────────────────────┐
  Client / 3rd-party ───▶│  Express app  (src/api/index.ts)             │
  app / Browser          │  helmet · cors · compression ·               │
                         │  globalRateLimiter · cookieParser · passport │
                         └───────────────────┬─────────────────────────┘
                                             │  /api/v1
                         ┌───────────────────▼─────────────────────────┐
                         │  Router (routes/index.ts)                    │
                         │  guards: authenticateJWT · roleGuard ·       │
                         │  CSRF (requireAuthAction) · rate limiters    │
                         └──┬────────┬─────────┬────────┬───────────────┘
       ┌────────────────────┘        │         │        └────────────────┐
       ▼                             ▼         ▼                         ▼
  Direct API                   OIDC IdP    Federation               System
  /auth /mfa /magic-link       /oidc/*     /oauth/google            /health
  /user /session /admin        (oidc-provider + custom
       │                        interaction UI endpoints)
       ▼
  Controllers ──▶ Services ──▶ ┌──────────────────────────────────────┐
   (manual DI via modules/)    │  Prisma (PostgreSQL)   │   Redis      │
                               │  User·Account·Session  │  session ·   │
                               │  ·OidcClient           │  OIDC state ·│
                               │                        │  OTP/magic/  │
                               │                        │  verify      │
                               └────────────────────────┴──────────────┘
                               Resend (email)      Google OAuth (external)
```

**Data model (`prisma/schema.prisma`) — only 4 models:** `User` (role USER/ADMIN, `emailVerified`, MFA fields), `Account` (multi-provider credentials + OAuth tokens; `@@unique([providerId, accountId])` enables account linking), `Session` (DB-backed with IP/UA/device fingerprint/revocation), `OidcClient` (hashed secret, redirect URLs, grant types).

---

## 2. Existing Features (verified in code)

- **Password auth & lifecycle:** register with email verification (Redis, 24h TTL), login with HS256 access+refresh tokens, logout, refresh-token rotation with sliding expiry, forgot-password via OTP (Redis, attempt-limited), reset-password (revokes all sessions), change-password, resend verification.
- **MFA — TOTP with backup codes:** Speakeasy enrollment with QR, secret staged in Redis before commit, AES-256-GCM-encrypted persisted secret, 5 bcrypt-hashed single-use backup codes, in-service MFA rate limiting, revoke MFA.
- **Passwordless — magic link:** email link (Redis, 15-min TTL), MFA-aware, can resume an OIDC flow via carried `uid`.
- **Social login — Google OAuth:** via Passport; automatic account linking by email; auto-creates verified users.
- **OIDC / OAuth2 IdP:** full `oidc-provider` engine — discovery, JWKS, `/auth`, `/token`, `/me`, introspection, revocation, RP-initiated logout; **PKCE mandatory**; refresh-token rotation; RS256 signing; DB-backed dynamic clients (bcrypt-hashed secrets); custom `role` claim; **session bridge** for true SSO from an existing first-party session.
- **Sessions:** list/get/revoke one/revoke-all-others; device fingerprinting + new-device email alerts; Redis-first validation with DB fallback.
- **Admin / RBAC:** `roleGuard(Role.ADMIN)`; promote to admin, delete user, list/get users, list user sessions, revoke sessions, register OIDC clients.
- **Cross-cutting:** tiered rate limiting, CSRF double-submit, tuned Helmet CSP, strict-ish CORS, response sanitization (`sanitizeUser`), health checks, Swagger `/docs`, secret-generation script.

---

## 3. Gaps vs. Modern Competitors

Ordered by recommended priority. Complexity/effort assume the existing module→service→Prisma/Redis pattern. IDs (`FR-1`…) are referenced by [`task.md`](./task.md).

---

### FR-1 — Automated test suite

**Why it is useful:** Zero application tests exist. An auth service is the highest-blast-radius component in any system; untested crypto/session/OIDC flows block safe refactoring and adoption. (This audit already found two directly-exploitable auth bypasses — `SEC-C1`, `SEC-C2` — exactly the class of regression tests catch.)
**Business value:** Trust, safe refactoring, CI gating, contributor confidence.
**Technical complexity:** Medium.
**Suggested implementation:** `vitest` (fits ESM/tsup) + `supertest` for router integration tests; `ioredis-mock` or Testcontainers for Redis; a Prisma test DB (Testcontainers Postgres). Unit-test services with mocked Prisma/Redis; integration-test the auth/mfa/oidc flows end-to-end. Add `test`/`test:ci` scripts and a GitHub Actions workflow.
**Dependencies:** `vitest`, `supertest`, `@testcontainers/postgresql`, `ioredis-mock`.
**Estimated effort:** 2–3 weeks to meaningful coverage.
**Priority:** **Highest.**

---

### FR-2 — Audit logs / security event trail

**Why it is useful:** No persistent audit trail exists (only Winston app logs). Every competitor ships an immutable audit log of logins, MFA changes, session revocations, and admin actions.
**Business value:** Compliance (SOC 2 / GDPR), incident forensics, a data source for an admin dashboard, enterprise-sales requirement.
**Technical complexity:** Medium.
**Suggested implementation:** Add an `AuditLog` model (`actorId`, `event`, `targetId`, `ip`, `userAgent`, `metadata Json`, `createdAt`); a thin `AuditService` invoked from existing services at key mutation points (login success/fail, password change, MFA enable/revoke, session revoke, admin ops, OIDC client create); expose `GET /admin/audit-logs` with pagination.
**Dependencies:** None new (Prisma).
**Estimated effort:** ~1 week.
**Priority:** **High.**

---

### FR-3 — Webhooks / outbound event system

**Why it is useful:** No outbound events. Clerk/WorkOS/Auth0 emit webhooks (`user.created`, `session.revoked`, …) so downstream apps stay in sync — a core auth-as-a-service primitive AuthKit lacks.
**Business value:** Makes AuthKit integrable as a platform, not just a login box; unlocks provisioning/deprovisioning.
**Technical complexity:** Medium–High (reliable delivery).
**Suggested implementation:** `WebhookEndpoint` + `WebhookDelivery` Prisma models; an internal event bus fed by the `AuditService` (build alongside FR-2 — shared event catalog); a delivery worker with retry/backoff and an HMAC-SHA256 signature header; admin CRUD under `/admin/webhooks`.
**Dependencies:** Redis-backed queue or BullMQ; `node:crypto` for signing.
**Estimated effort:** ~2 weeks.
**Priority:** **High.**

---

### FR-4 — Passkeys / WebAuthn

**Why it is useful:** The single biggest modern differentiator; every competitor now leads with passkeys. AuthKit has TOTP and magic links but no FIDO2/WebAuthn.
**Business value:** Phishing-resistant auth, better UX, table-stakes for 2025+ positioning.
**Technical complexity:** High (ceremony state, attestation).
**Suggested implementation:** `Authenticator` model (credentialId, publicKey, counter, transports, userId); a `WebAuthnService` mirroring `mfa.service.ts`; register/authenticate routes under `/webauthn`; store challenges in Redis (reuse `redis-helpers`); wire into both direct login and the OIDC interaction pipeline (as MFA already is).
**Dependencies:** `@simplewebauthn/server`.
**Estimated effort:** 2–3 weeks.
**Priority:** **High.**

---

### FR-5 — Multi-tenancy / Organizations

**Why it is useful:** The data model is single-tenant (flat User/Session/OidcClient, global USER/ADMIN roles). WorkOS/Clerk/Auth0 are built around Organizations, membership, invitations, and org-scoped roles — the biggest architectural gap for B2B.
**Business value:** Unlocks all B2B SaaS scenarios (per-org SSO, per-org admin, team invites) — the highest-revenue segment.
**Technical complexity:** High (touches the schema and every query's scoping).
**Suggested implementation:** `Organization`, `Membership` (userId + orgId + role), `Invitation` models; scope `OidcClient`/`AuditLog`/webhooks to `orgId`; extend `roleGuard` to org-aware permission checks; add org context to the JWT/session. Best delivered as a deliberate v2 milestone.
**Dependencies:** None new; pairs with FR-2/FR-3.
**Estimated effort:** 4–6 weeks.
**Priority:** **Medium-High (strategic).**

---

### FR-6 — Enterprise SSO (inbound SAML 2.0 / OIDC RP)

**Why it is useful:** AuthKit is an OIDC _provider_ but cannot act as a _relying party_ to enterprise IdPs (Okta, Azure AD, Google Workspace SAML). WorkOS's entire business is this direction.
**Business value:** Enterprise deal-closer ("Log in with your company IdP").
**Technical complexity:** High.
**Suggested implementation:** Add SAML/OIDC connections as another `providerId` in `Account` (linking already works via `@@unique([providerId, accountId])`); per-org connection config (depends on FR-5); new Passport strategies alongside `google.strategy.ts`.
**Dependencies:** `@node-saml/passport-saml` and/or `openid-client`.
**Estimated effort:** 3–4 weeks single-tenant, more with orgs.
**Priority:** **Medium (gated by target market).**

---

### FR-7 — Observability: metrics & tracing

**Why it is useful:** Only Winston logs + a basic health endpoint. No `/metrics`, no tracing, no request IDs.
**Business value:** Production operability, SLOs, faster incident response.
**Technical complexity:** Medium.
**Suggested implementation:** `prom-client` default + custom counters (login success/fail, token issuance, rate-limit hits) at `/metrics`; a request-ID middleware feeding Winston; optional OpenTelemetry auto-instrumentation for HTTP/Prisma/Redis.
**Dependencies:** `prom-client`, optional `@opentelemetry/sdk-node`.
**Estimated effort:** 3–5 days.
**Priority:** **Medium.**

---

### FR-8 — Real dependency health checks

**Why it is useful:** `health.service.ts` returns a hardcoded `status: 'healthy'` — it never actually pings Postgres or Redis, so "detailed health" does not reflect dependency state. Kubernetes readiness/liveness needs real probes.
**Business value:** Correct orchestration behavior; avoids routing traffic to a broken instance.
**Technical complexity:** Low.
**Suggested implementation:** In `getDetailedHealth`, run `prisma.$queryRaw\`SELECT 1\``and`redis.ping()`with timeouts; return per-dependency status; set`degraded`/`unhealthy`+ HTTP 503. Split`/health/live`vs`/health/ready`.
**Dependencies:** None.
**Estimated effort:** ~1 day.
**Priority:** **Medium (quick win).**

---

### FR-9 — SMS + pluggable notification providers

**Why it is useful:** Email is hardwired to Resend (`core/mailers/resend.ts`); no SMS channel (so no SMS-OTP MFA).
**Business value:** Broader MFA/notification reach; avoids vendor lock-in.
**Technical complexity:** Low–Medium.
**Suggested implementation:** Extract an `EmailProvider` interface (Resend as one impl); add an SMS provider interface; add SMS-OTP as an MFA method reusing the existing OTP Redis pattern.
**Dependencies:** `nodemailer` (SMTP) and/or Twilio SDK.
**Estimated effort:** 3–5 days (email abstraction) + ~1 week (SMS MFA).
**Priority:** **Medium.**

---

### FR-10 — OpenAPI completeness + generated SDK

**Why it is useful:** Swagger exists (hand-written JSDoc) but there's no typed client SDK — the primary integration path for competitors.
**Business value:** Adoption velocity; a generated TS client is the fastest "install and go."
**Technical complexity:** Low–Medium.
**Suggested implementation:** Validate every route has complete Swagger schemas, then generate a typed client in CI from the emitted `swaggerSpec`.
**Dependencies:** `openapi-typescript` / `openapi-generator`.
**Estimated effort:** ~1 week.
**Priority:** **Medium.**

---

### FR-11 — Explicit API versioning & deprecation policy

**Why it is useful:** Path is `/api/v1` but there's no deprecation/sunset policy or version negotiation. Fine now; worth formalizing before public consumers exist.
**Business value:** Non-breaking evolution once external clients depend on the API.
**Technical complexity:** Low.
**Suggested implementation:** Document a versioning policy; add `Deprecation`/`Sunset` header middleware.
**Estimated effort:** 1–2 days.
**Priority:** **Low.**

---

### FR-12 — Admin dashboard (UI)

**Why it is useful:** Admin capabilities are API-only; every competitor ships a management console.
**Business value:** Usability for non-developer admins; strong demo/sales asset.
**Technical complexity:** Medium–High (separate frontend).
**Suggested implementation:** Consume the existing `/admin/*` and `/session` APIs plus the proposed audit-log/webhook APIs. Best after FR-2/FR-3 land.
**Dependencies:** A frontend stack (out of this repo's scope).
**Estimated effort:** 3–4 weeks.
**Priority:** **Low–Medium.**

---

### FR-13 — i18n for emails & errors

**Why it is useful:** Email templates and error messages are English-only inline HTML in `resend.ts`.
**Business value:** International reach.
**Technical complexity:** Low–Medium.
**Suggested implementation:** Extract templates/strings to locale files; pick locale from `Accept-Language`/user preference. (Combine with FR-9's email refactor and SEC-M5's escaping fix.)
**Dependencies:** `i18next`.
**Estimated effort:** ~1 week.
**Priority:** **Low.**

---

### FR-14 — Feature flags

**Why it is useful:** Method availability is env-config only; no runtime toggles for enabling MFA methods / social providers per deployment or tenant.
**Business value:** Safer rollouts; per-tenant capability control (pairs with FR-5).
**Technical complexity:** Low–Medium.
**Suggested implementation:** A Redis-backed flag service consulted by routes/services; admin toggle endpoint.
**Estimated effort:** 3–5 days.
**Priority:** **Low.**

---

## 4. Smaller Improvements Worth Flagging

- **Rate-limit tiering is incomplete** — magic-link and `/oauth` routes rely only on the global limiter (also raised as `SEC-H4`). The in-service `checkRateLimit` pattern already exists and should be applied to magic-link sends.
- **Doc vs. code drift** — `docs/security_architecture.md` cites a global limit of "100 req/15min" but `rate-limit.constant.ts` sets 200; it describes PPI (pairwise pseudonymous identifiers) as configurable, but `oidc.config.ts` does not enable it. Reconcile the docs.
- **First-party access tokens are HS256/opaque to third parties** — fine internally, but if resource servers should validate first-party tokens without a shared secret, consider RS256 (the JWKS infra already exists for OIDC).

## 5. Suggested Feature Roadmap (by phase)

- **Foundation (do first):** FR-1 (tests), FR-2 (audit logs), FR-8 (real health checks).
- **Platform primitives:** FR-3 (webhooks), FR-7 (observability), FR-10 (SDK).
- **Auth parity:** FR-4 (passkeys), FR-9 (SMS/providers).
- **Enterprise / scale:** FR-5 (organizations), FR-6 (enterprise SSO), FR-12 (admin UI).
- **Polish:** FR-11 (versioning), FR-13 (i18n), FR-14 (feature flags).
