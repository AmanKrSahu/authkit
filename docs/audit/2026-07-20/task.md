# AuthKit — Master Task Plan & Execution Roadmap

**Date:** 2026-07-03
**Inputs:** [`security-audit.md`](./security-audit.md), [`performance.md`](./performance.md), [`feature-recommendations.md`](./feature-recommendations.md), [`supplementary-findings.md`](./supplementary-findings.md).

This roadmap sequences remediation and modernization across three phases to **minimize risk and avoid regressions**. Each task lists Priority, Complexity, Dependencies, and Expected Impact, and cross-references its source finding ID.

Legend — Complexity: **S** (< 1 day), **M** (1–5 days), **L** (1–3 weeks), **XL** (> 3 weeks).

---

## Phase 1 — Critical Fixes (security-first, deploy ASAP)

Goal: close directly-exploitable auth bypasses, rotate compromised secrets, and remove insecure defaults. Do these before any feature work.

| #    | Task                                                                                                                                                                            | Source          | Priority | Complexity | Dependencies    | Expected Impact                                      | Status   |
| ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------- | -------- | ---------- | --------------- | ---------------------------------------------------- | -------- |
| 1.1  | **Bind password-reset to the token identity** — derive target from `payload.email`, check `payload.purpose`; ignore body email                                                  | SEC-C1          | P0       | S          | none            | Closes full account-takeover                         | **Done** |
| 1.2  | **Add `return` in OIDC `loginInteraction`** after the MFA-required response                                                                                                     | SEC-C2          | P0       | S          | none            | Closes MFA bypass over SSO                           | **Done** |
| 1.3  | **Rotate ALL secrets** (JWT×4, OIDC RSA keypair, cookie keys, authenticator key, Google secret, Resend key, DB password); move to a secrets manager; URL-encode the DB password | SEC-C3, SEC-L11 | P0       | M          | secrets manager | Restores trust base integrity                        | **Done** |
| 1.4  | **Remove the `AUTHENTICATOR_APP_SECRET` default**; require + validate ≥32B entropy at boot                                                                                      | SEC-C4          | P0       | S          | 1.3             | Prevents predictable TOTP-encryption key             | **Done** |
| 1.5  | **CORS exact-origin allowlist** — remove `origin.includes(...)` substring checks                                                                                                | SEC-H1          | P0       | S          | none            | Closes credentialed cross-origin bypass              | **Done** |
| 1.6  | **Sanitize + re-validate the JWT session cache** — cache minimal fields; re-check `isRevoked`/`expiresAt` on every request                                                      | SEC-H2          | P0       | M          | none            | Closes revocation bypass; removes secrets from Redis | **Done** |
| 1.7  | **Configure `trust proxy` + `req.ip`; add per-account login lockout** (supplementary proxy/Nginx findings in [`supplementary-findings.md`](./supplementary-findings.md))        | SEC-H3          | P0       | M          | none            | Restores brute-force protection                      | **Done** |
| 1.8  | **Add rate limiters to magic-link & MFA-verify routes** (+ per-`userId` MFA counter)                                                                                            | SEC-H4          | P1       | S          | 1.7             | Stops OTP/backup brute force & email bombing         | **Done** |
| 1.9  | **Secure Redis** — `requirepass` + client password, TLS in prod, stop publishing dev port; encrypt/shorten `mfa_setup` TTL                                                      | SEC-H5          | P1       | M          | none            | Protects tokens/TOTP secrets at rest                 | Todo     |
| 1.10 | **Verify OAuth `state` server-side** (issue random state, store in Redis, check on callback)                                                                                    | SEC-H6          | P1       | M          | none            | Closes login-CSRF                                    | Todo     |
| 1.11 | **Uniform recovery responses** — no user enumeration on forgot-password/resend/magic-link; rate-limit before lookup                                                             | SEC-H7          | P1       | S          | none            | Removes account enumeration                          | Todo     |

**Phase 1 exit criteria:** all Critical + High findings resolved and verified; secrets rotated; a smoke test covers reset, OIDC-login-with-MFA, and revocation.

---

## Phase 2 — Stability & Performance

Goal: harden the medium-risk surface, add the safety net (tests, monitoring), and land the high-ROI performance fixes.

### 2A — Remaining security hardening (Medium/Low)

| #    | Task                                                                                                                                                      | Source    | Priority | Complexity | Dependencies | Status |
| ---- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- | -------- | ---------- | ------------ | ------ |
| 2.1  | CSPRNG OTP (`crypto.randomInt`)                                                                                                                           | SEC-M1    | P1       | S          | none         | Todo   |
| 2.2  | 80-bit MFA backup codes                                                                                                                                   | SEC-M2    | P1       | S          | none         | Todo   |
| 2.3  | Strip `error.message` from 500 responses                                                                                                                  | SEC-M3    | P1       | S          | none         | Todo   |
| 2.4  | Redact tokens/OTPs from logs                                                                                                                              | SEC-M4    | P1       | S          | none         | Todo   |
| 2.5  | HTML-escape email template interpolation                                                                                                                  | SEC-M5    | P2       | S          | none         | Todo   |
| 2.6  | Raise bcrypt cost to 12 (configurable)                                                                                                                    | SEC-M6    | P2       | S          | none         | Todo   |
| 2.7  | Constant-time CSRF/OTP compares                                                                                                                           | SEC-M7    | P2       | S          | none         | Todo   |
| 2.8  | Single-use, context-bound MFA-login nonce                                                                                                                 | SEC-M8    | P2       | M          | 1.6          | Todo   |
| 2.9  | Enforce CSRF origin check in all envs                                                                                                                     | SEC-M9    | P2       | S          | none         | Todo   |
| 2.10 | Scope CSP (drop global `unsafe-inline`; nonces for OIDC pages)                                                                                            | SEC-M10   | P2       | M          | none         | Todo   |
| 2.11 | Cookie hardening (`domain` scope, `sameSite: strict`, unconditional `secure` in prod)                                                                     | SEC-M11   | P2       | S          | none         | Todo   |
| 2.12 | Low-tier cleanup: pin JWT `algorithms`, email-verify gate, MFA re-auth, refresh single-use, gate `/docs`, password max-length, remove dead `sessionToken` | SEC-L1–L8 | P3       | M          | none         | Todo   |

### 2B — Performance (high-ROI first)

| #    | Task                                                                                           | Source           | Priority | Complexity | Expected Impact                                        | Status   |
| ---- | ---------------------------------------------------------------------------------------------- | ---------------- | -------- | ---------- | ------------------------------------------------------ | -------- |
| 2.13 | **Add `Session` indexes** (`userId`, `userId+deviceFingerprint`, `userId+isRevoked+expiresAt`) | perf QW-1/QW-2   | P1       | S          | 10–100× faster session lookups; removes login seq-scan | Todo     |
| 2.14 | **JWT strategy: fetch single session by PK** (combine with 1.6)                                | perf QW-3        | P1       | M          | Constant-size hottest-path query & cache               | **Done** |
| 2.15 | Move bcrypt out of the register transaction                                                    | perf QW-5        | P2       | S          | ~100ms less connection hold per register               | Todo     |
| 2.16 | Batch Redis session deletions (`deleteCacheMany`)                                              | perf QW-6        | P2       | S          | M round-trips → 1 on revoke-all                        | Todo     |
| 2.17 | Parallelize/queue registration emails                                                          | perf QW-4        | P2       | S          | ~1 email RTT off register latency                      | Todo     |
| 2.18 | Paginate `getAllUsers`/`getSessions` (+ populate count headers)                                | perf M-1         | P2       | M          | Bounded admin payloads at scale                        | Todo     |
| 2.19 | Tune Redis client resilience + Prisma pool sizing/timeouts                                     | perf QW-7/LT-3   | P2       | S          | Predictable behavior under load                        | Todo     |
| 2.20 | Fix/simplify `getSessionById` cache path; drop redundant pre-fetches                           | perf M-2/M-3     | P3       | S          | Fewer wasted round-trips                               | Todo     |
| 2.21 | Cache `getAppVersion`; build/Docker/logger tuning                                              | perf QW-8/LT-4–6 | P3       | M          | Smaller image, lower logging overhead                  | Todo     |

### 2C — Safety net & operability

| #    | Task                                                                     | Source  | Priority | Complexity | Dependencies | Status |
| ---- | ------------------------------------------------------------------------ | ------- | -------- | ---------- | ------------ | ------ |
| 2.22 | **Automated test suite** (vitest + supertest + Testcontainers) + CI      | FR-1    | P1       | L          | none         | Todo   |
| 2.23 | **Audit logs** (`AuditLog` model + `AuditService` + `/admin/audit-logs`) | FR-2    | P1       | M          | none         | Todo   |
| 2.24 | **Real dependency health checks** (`/health/live`, `/health/ready`)      | FR-8    | P2       | S          | none         | Todo   |
| 2.25 | **Observability** (`prom-client` `/metrics`, request IDs, optional OTel) | FR-7    | P2       | M          | none         | Todo   |
| 2.26 | Reconcile docs vs. code (rate-limit numbers, PPI)                        | feat §4 | P3       | S          | none         | Todo   |

**Phase 2 exit criteria:** all Medium findings resolved; test coverage on auth/mfa/oidc flows in CI; metrics + real health checks live; performance indexes migrated.

---

## Phase 3 — Modernization & Feature Development

Goal: reach competitive feature parity and B2B/enterprise readiness. Sequenced so platform primitives precede the features that depend on them.

| #    | Task                                       | Source | Priority | Complexity | Dependencies                | Expected Impact                   | Status |
| ---- | ------------------------------------------ | ------ | -------- | ---------- | --------------------------- | --------------------------------- | ------ |
| 3.1  | **Webhooks / event system**                | FR-3   | P1       | L          | 2.23 (shared event catalog) | Platform integrability            | Todo   |
| 3.2  | **Generated SDK + OpenAPI completeness**   | FR-10  | P2       | M          | 2.22                        | Adoption velocity                 | Todo   |
| 3.3  | **Passkeys / WebAuthn**                    | FR-4   | P1       | L          | 2.22                        | Phishing-resistant, modern auth   | Todo   |
| 3.4  | **SMS + pluggable notification providers** | FR-9   | P2       | M          | 2.5 (email refactor)        | Broader MFA/reach                 | Todo   |
| 3.5  | **Organizations / multi-tenancy**          | FR-5   | P1       | XL         | 2.23, 3.1                   | B2B revenue segment               | Todo   |
| 3.6  | **Enterprise SSO (SAML/OIDC RP)**          | FR-6   | P2       | XL         | 3.5                         | Enterprise deal-closer            | Todo   |
| 3.7  | **Admin dashboard (UI)**                   | FR-12  | P2       | XL         | 2.23, 3.1                   | Non-dev usability                 | Todo   |
| 3.8  | API versioning policy                      | FR-11  | P3       | S          | none                        | Safe evolution                    | Todo   |
| 3.9  | i18n (emails/errors)                       | FR-13  | P3       | M          | 3.4                         | International reach               | Todo   |
| 3.10 | Feature flags                              | FR-14  | P3       | M          | 3.5                         | Safe rollouts, per-tenant control | Todo   |

---

## Recommended Execution Order (risk-minimizing)

1. **Ship Phase 1 as a single security release** — items 1.1–1.5 are near-one-line, highest-exploitability fixes; batch them, add a regression test for each, deploy immediately. Then 1.6–1.11. Rotate secrets (1.3) in the same window since the bypasses are being closed anyway.
2. **Land the test harness (2.22) early in Phase 2** — before broad refactoring, so the Medium-tier hardening and performance changes are regression-guarded. Practically, write characterization tests for the flows touched in Phase 1 first.
3. **Combine coupled changes:** 1.6 (cache sanitize/revalidate) + 2.14 (single-session fetch) are the same edit to `jwt.strategy.ts` — do them together. 2.5 (email escaping) naturally precedes 3.4/3.9 (provider refactor + i18n).
4. **Performance indexes (2.13) are a safe, isolated migration** — deploy alongside the test harness; near-zero regression risk, large upside.
5. **Add observability (2.24/2.25) before Phase 3** so feature rollouts are measurable.
6. **Sequence Phase 3 by dependency:** audit logs (2.23) → webhooks (3.1) → organizations (3.5) → enterprise SSO (3.6) and admin UI (3.7). Passkeys (3.3) and the SDK (3.2) are independent and can run in parallel once tests exist.

**Guardrails throughout:** every Phase 1/2 fix gets a regression test; secret rotation is coordinated with any live OIDC clients (new signing key ⇒ clients re-fetch JWKS); schema migrations (indexes, audit log, organizations) are additive and deployed with `prisma migrate` (not `db push`) in production.
