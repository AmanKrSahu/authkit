# AuthKit — Security Audit

**Project:** AuthKit — self-hostable Identity Provider / IAM microservice (Node.js + Express 5, TypeScript, Prisma/PostgreSQL, Redis, `oidc-provider`).
**Scope:** Full source tree (`src/**`), configuration, Docker, Prisma schema, scripts. Read-only review.
**Date:** 2026-07-03
**Method:** Manual code review corroborated across four independent analysis passes; the highest-impact findings were re-verified directly against source before publishing.

> **How to read this document.** Findings are grouped by severity and given stable IDs (`SEC-C1`, `SEC-H1`, …) referenced by [`task.md`](./task.md). Each includes the exact file/line, verbatim evidence, an attack scenario, and a concrete fix. Duplicate observations raised by multiple review passes have been merged into a single canonical finding.

---

## Summary

| Severity       | Count  | IDs              |
| -------------- | ------ | ---------------- |
| **Critical**   | 4      | SEC-C1 – SEC-C4  |
| **High**       | 7      | SEC-H1 – SEC-H7  |
| **Medium**     | 11     | SEC-M1 – SEC-M11 |
| **Low / Info** | 11     | SEC-L1 – SEC-L11 |
| **Total**      | **33** |                  |

**Fix first (directly exploitable for account takeover / auth bypass):** `SEC-C1` (reset-token account takeover) and `SEC-C2` (MFA bypass in OIDC login), then `SEC-C3` (rotate live secrets) and `SEC-C4` (TOTP encryption key default).

**What is already done well:** OIDC PKCE is mandatory; OIDC client secrets are bcrypt-hashed and compared with bcrypt; persisted TOTP secrets are AES-256-GCM encrypted; session/magic-link tokens use a CSPRNG (`crypto.randomBytes`); redirect validation (`getValidRedirectUrl`) uses an anchored `url.origin` allowlist; Prisma parameterizes all queries (no SQL injection surface); the Dockerfile runs as a non-root user with `dumb-init`; admin routes are correctly guarded with `authenticateJWT, roleGuard(Role.ADMIN)` at the router (`src/api/v1/routes/index.ts:38`) — no admin IDOR was found. `.env` is correctly gitignored and was never committed.

---

# Critical Severity

## SEC-C1 — Password-reset account takeover (reset token not bound to target account)

### Severity

**Critical.** Directly exploitable; results in takeover of any account with a known email address.

### Description

The reset-password flow issues a JWT whose payload contains the target `email` and `purpose: 'PASSWORD_RESET'`, but `resetPassword` selects the account to modify using the **request-body `email`** and only verifies the token's _signature_ — it never checks that `payload.email === email` or that `payload.purpose === 'PASSWORD_RESET'`.

### Why it is dangerous

1. Attacker runs `forgot-password` → `verify-otp` on **their own** account, obtaining a legitimately-signed `resetToken` cookie (+ CSRF cookie).
2. Attacker calls `POST /auth/reset-password` with body `{ email: "victim@example.com", password: "attacker-chosen", resetToken: <their own valid token> }`.
3. The token verifies (valid signature), the victim's account is located by the body email, and the victim's password is overwritten. All victim sessions are revoked and the attacker now controls the account.

The absence of the `purpose` check also means a token minted for a different purpose could be accepted if any two JWT secrets were ever shared.

### Location

- File: `src/api/v1/services/auth.service.ts`
- Function: `resetPassword` (lines ~439–457); token issued in `verifyOtp` (line ~428)
- Validator confirms the gap: `src/core/common/validators/auth.validator.ts` `resetPasswordSchema` does not tie the token to the email.

### Evidence

```ts
// verifyOtp — token carries the email + purpose
const resetToken = signJwtToken({ email, purpose: 'PASSWORD_RESET' }, resetTokenSignOptions);

// resetPassword — email comes from the request body, token only signature-checked
const { email, password, resetToken } = resetPasswordData;
const user = await prisma.user.findUnique({ where: { email } }); // body email
if (!user) {
  throw new NotFoundException('User not found');
}
const { payload } = verifyJwtToken<ResetTPayload>(resetToken, {
  secret: resetTokenSignOptions.secret,
});
if (!payload) {
  throw new UnauthorizedException('Invalid reset token');
}
// payload.email and payload.purpose are NEVER compared to `email`
```

### Recommendation

Bind the reset operation to the token, not to a user-supplied field. Ignore the body email entirely and derive the target from `payload.email`.

### Example Fix

```ts
const { payload } = verifyJwtToken<ResetTPayload>(resetToken, {
  secret: resetTokenSignOptions.secret,
});
if (!payload || payload.purpose !== 'PASSWORD_RESET') {
  throw new UnauthorizedException('Invalid reset token');
}
// Use the identity FROM the token, never the request body:
const user = await prisma.user.findUnique({ where: { email: payload.email } });
if (!user) throw new UnauthorizedException('Invalid reset token');
```

### References

CWE-640 (Weak Password Recovery), CWE-639 (Authorization Bypass Through User-Controlled Key), OWASP A01:2021 (Broken Access Control).

---

## SEC-C2 — MFA bypass in the OIDC login interaction (missing `return`)

### Severity

**Critical.** Completely defeats two-factor authentication for any user logging in through the OIDC/SSO flow.

### Description

In `OidcController.loginInteraction`, when a 2FA-enabled user authenticates with a correct password, the `mfaRequired` branch writes the "MFA verification required" response but does **not `return`**. Execution falls through to `submitLogin`, which finishes the OIDC login **without ever verifying a TOTP code or backup code**.

### Why it is dangerous

Any attacker who knows a victim's password (credential stuffing, reuse, phishing) can complete SSO login against any relying-party application, bypassing the victim's 2FA entirely. The direct REST login path (`AuthController.login`) handles this correctly with a `return`, so the vulnerability is specific to the OIDC surface.

### Location

- File: `src/api/v1/controllers/oidc.controller.ts`
- Function: `loginInteraction` (lines ~82–98)

### Evidence

```ts
if (mfaRequired) {
  if (!mfaLoginToken) {
    throw new AppError(/* ... */);
  }

  setMfaLoginCookie({ res, mfaLoginToken }).status(HTTPSTATUS.OK).json({
    success: true,
    mfaRequired: true,
    message: 'MFA verification required',
    uid: req.params.uid,
  });
  // <-- MISSING `return`
}

await this.oidcService.submitLogin(req, res, user.id); // runs even when MFA was required
```

### Recommendation

Return immediately after sending the MFA-required response.

### Example Fix

```ts
  setMfaLoginCookie({ res, mfaLoginToken }).status(HTTPSTATUS.OK).json({ /* ... */ });
  return;   // stop the login until MFA is verified
}
await this.oidcService.submitLogin(req, res, user.id);
```

### References

CWE-306 (Missing Authentication for Critical Function), CWE-287 (Improper Authentication), OWASP A07:2021.

---

## SEC-C3 — Live third-party secrets present in the working-tree `.env`

### Severity

**Critical.** Real, working credentials for the entire trust base of the system are stored in plaintext on disk.

### Description

`.env` is correctly gitignored and was **never committed** (verified: `git ls-files` lists only `.env.example`; `git log --all -- .env` is empty). However, the working-tree `.env` contains what appear to be **real, live** secrets rather than placeholders — including the OIDC RSA **private** key. Git hygiene prevents repo leakage, but it does not undo the fact that live credentials exist in cleartext and should be treated as exposed.

### Why it is dangerous

Possession of this file allows an attacker to: forge OIDC ID tokens for any user (RSA private key in `OIDC_JWKS`), forge every first-party JWT (HMAC secrets), decrypt all stored TOTP secrets (`AUTHENTICATOR_APP_SECRET`, see `SEC-C4`), send email as the organization (Resend key), impersonate the app to Google, and connect to the database.

### Location

`.env` — lines 12, 14, 22, 31–34, 37, 41, 44, 47.

### Evidence

```
POSTGRES_PASSWORD="Amansahu@09"
DATABASE_URL="postgresql://admin:Amansahu@09@localhost:5432/authkit?schema=public"   # note: unescaped '@' also breaks URL parsing
GOOGLE_CLIENT_SECRET="GOCSPX-..."      # real GOCSPX- prefix
RESEND_API_KEY="re_..."                # real re_ prefix
JWT_SECRET / JWT_REFRESH_SECRET / JWT_RESET_SECRET / JWT_MFA_LOGIN_SECRET   # real 64-hex values
OIDC_JWKS='{"keys":[{"kty":"RSA","n":"...","d":"...","p":"...","q":"..."}]}'   # RSA PRIVATE key
```

### Recommendation

Treat **all** of these as compromised and rotate them: regenerate JWT / cookie / authenticator secrets (`pnpm generate:secrets`), generate a fresh OIDC RSA keypair, roll the Google client secret in Google Cloud Console, revoke + reissue the Resend key, change the Postgres password. Move production secrets into a secrets manager (Vault / AWS Secrets Manager / Doppler) rather than a flat file. URL-encode the DB password (`Amansahu%4009`) to fix the parsing bug.

### References

CWE-798 (Hardcoded Credentials), CWE-312 (Cleartext Storage of Sensitive Information), OWASP A07:2021.

---

## SEC-C4 — TOTP encryption key uses a predictable hardcoded default

### Severity

**Critical.** If the env var is unset, every user's 2FA secret is encrypted with a key derivable from the public source code.

### Description

The AES-256-GCM key that encrypts every user's `twoFactorSecret` is derived from `config.AUTHENTICATOR_APP_SECRET`, which **defaults to the public string `'authenticator-app-secret-dev'`** when the environment variable is unset. Unlike the JWT secrets (which have no default and fail fast), this default silently disables the requirement.

### Why it is dangerous

If the variable is missing in any environment, the encryption key becomes `SHA-256("authenticator-app-secret-dev")` — fully predictable. An attacker with read access to the `twoFactorSecret` column (via the compromised DB credentials in `SEC-C3`, a backup, or any future injection) can decrypt every user's TOTP seed and generate valid codes indefinitely, defeating MFA for the entire user base.

### Location

- Key source: `src/core/config/app.config.ts:32-35`
- Usage: `src/core/common/utils/crypto.ts:9,33` (`encrypt`/`decrypt`)

### Evidence

```ts
// app.config.ts
AUTHENTICATOR_APP_SECRET: getEnvironment('AUTHENTICATOR_APP_SECRET', 'authenticator-app-secret-dev'),

// crypto.ts
const key = crypto.createHash('sha256').update(config.AUTHENTICATOR_APP_SECRET).digest();
```

### Recommendation

Remove the default so the app fails fast when the key is missing (match the JWT-secret pattern), require ≥ 32 bytes of entropy, and prefer a raw random key over `sha256(string)`. Add a boot-time validation that rejects known/default/short secrets.

### Example Fix

```ts
AUTHENTICATOR_APP_SECRET: getEnvironment('AUTHENTICATOR_APP_SECRET'),   // no default → throws if unset
```

### References

CWE-321 (Use of Hard-coded Cryptographic Key), CWE-1188 (Insecure Default Initialization), OWASP A02:2021.

---

# High Severity

## SEC-H1 — CORS allows any origin containing `DOMAIN_URL` as a substring (with credentials)

### Severity

**High.**

### Description

The CORS origin callback accepts an origin if it merely **contains** `config.DOMAIN_URL` (or `localhost:PORT`) as a substring, while `credentials: true` is set.

### Why it is dangerous

`origin.includes(config.DOMAIN_URL)` is an unanchored substring match. With `DOMAIN_URL="localhost"` (the default), `https://localhost.attacker.com` is accepted; with `DOMAIN_URL="example.com"`, `https://example.com.evil.com` and `https://notexample.com` are accepted. Because credentialed requests are allowed, a malicious site can make authenticated cross-origin calls and read the responses (session bridge, user data, tokens). Requests with no `Origin` header are also unconditionally allowed.

### Location

`src/api/index.ts:40-53` (CORS `origin` callback).

### Evidence

```ts
if (
  config.FRONTEND_ORIGINS.includes(origin) ||
  origin.includes(config.DOMAIN_URL) ||
  origin.includes(`http://localhost:${config.PORT}`)
) {
  return callback(null, true);
}
```

### Recommendation

Match origins by exact equality against an explicit allowlist. Never use substring matching for origins.

### Example Fix

```ts
const allowed = new Set(config.FRONTEND_ORIGINS);
if (!origin || allowed.has(origin)) return callback(null, true);
return callback(new Error('Not allowed by CORS'));
```

### References

CWE-942 (Overly Permissive CORS), CWE-346 (Origin Validation Error), OWASP A05:2021.

---

## SEC-H2 — JWT session cache bypasses revocation and stores sensitive fields in Redis

### Severity

**High.**

### Description

Two related weaknesses in the Passport JWT strategy (the hottest auth path):

1. **Revocation bypass:** on a Redis cache hit, the strategy returns the cached user immediately, without re-checking `isRevoked` / `expiresAt`. Only the DB-fallback path validates session state. A revoked session whose cache entry still exists continues to authenticate for up to 24h.
2. **Sensitive data at rest:** the **entire** Prisma `user` object — including the bcrypt `password` hash, `twoFactorSecret`, and `backupCodes` — is JSON-serialized into `session:<id>` and cached for a day, and returned as `req.user`. Privilege changes (e.g. `promoteUserToAdmin`) are not reflected until cache expiry.

### Why it is dangerous

Logout / password-change / admin revocation may not terminate an active access token within the cache window; authorization decisions are made from stale, mutable cache data. Any Redis exposure (`SEC-H5`) leaks password hashes and 2FA seeds.

### Location

`src/core/common/strategies/jwt.strategy.ts:28-33` (cache hit) and `:36-57` (full-user fetch + cache write).

### Evidence

```ts
const cachedUser = await getCache(`session:${payload.sessionId}`);
if (cachedUser) {
  req.sessionId = payload.sessionId;
  return done(null, JSON.parse(cachedUser)); // no isRevoked / expiry re-check
}
// ...
await setCache(`session:${payload.sessionId}`, JSON.stringify(user), ONE_DAY); // full user incl. password hash, 2FA secret, backup codes
```

### Recommendation

Cache only a sanitized subset (id, role, email, sessionId), and re-validate session validity on every request (or cache session validity separately and invalidate on revocation/privilege change). Fetch the single session by primary key rather than the whole user with all sessions (see `performance.md` QW-3).

### Example Fix

```ts
const session = await prisma.session.findUnique({
  where: { id: payload.sessionId },
  include: { user: { select: { id: true, email: true, role: true, name: true, enable2FA: true } } },
});
if (
  !session ||
  session.userId !== payload.userId ||
  session.isRevoked ||
  session.expiresAt < new Date()
)
  return done(null, false);
```

### References

CWE-613 (Insufficient Session Expiration), CWE-312 (Cleartext Storage), OWASP A07:2021.

---

## SEC-H3 — Brute-force protection is IP-only and bypassable via `X-Forwarded-For` spoofing

### Severity

**High.**

### Description

`getClientIP` trusts the client-supplied `X-Forwarded-For` header unconditionally, and Express `trust proxy` is never configured. The login rate limiter is per-IP only (with `skipSuccessfulRequests: true`) and there is no per-account lockout.

### Why it is dangerous

An attacker rotating the `X-Forwarded-For` header makes each request appear to come from a different IP, resetting the rate-limit bucket and fully bypassing the 5-attempt/15-min limit. The same spoofable IP feeds the MFA/OTP limiter keys (`mfa_limit:<email>:<ip>`) and device-fingerprint / new-device detection. Password spraying across many accounts is unthrottled.

### Location

- `src/core/common/utils/metadata.ts:39-45` (`getClientIP`)
- `src/api/v1/middlewares/rate-limiter.middleware.ts` (`authRateLimiter`)

### Evidence

```ts
return ((req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.connection?.remoteAddress) ...
```

### Recommendation

Set `app.set('trust proxy', <exact hop count>)` matching your deployment topology and derive the IP from `req.ip` (which Express validates against the trusted-proxy chain). Add a per-account failed-login counter with temporary lockout.

For additional analysis on proxy trust configurations, IP spoofing prevention, and multi-tenant Nginx setup dependencies discovered during remediation planning, see [`supplementary-findings.md`](./supplementary-findings.md).

### References

CWE-307 (Improper Restriction of Excessive Authentication Attempts), CWE-290 (Authentication Bypass by Spoofing), CWE-348.

---

## SEC-H4 — Missing dedicated rate limiting on magic-link and MFA-verify routes

### Severity

**High.**

### Description

The auth routes apply `authRateLimiter`, but the magic-link routes (`login`, `verify`) and MFA-verify route have no route-level limiter — only the generous global limiter applies. The in-service MFA limiter is keyed on email + (spoofable) IP.

### Why it is dangerous

- `magic-link/login` with no throttle allows email-bombing and Resend cost abuse against known addresses.
- Combined with `SEC-H3` (IP spoofing) and `SEC-M2` (32-bit backup codes), TOTP/backup-code brute force at scale becomes feasible.

### Location

`src/api/v1/routes/magic-link.routes.ts`, `src/api/v1/routes/mfa.routes.ts` (compare `src/api/v1/routes/auth.routes.ts` which applies `authRateLimiter`).

### Recommendation

Apply `authRateLimiter` to magic-link and MFA-verify routes. For MFA, enforce a per-`userId` counter (not just email + IP) so IP rotation cannot reset the budget. Reuse the existing in-service `checkRateLimit` pattern for magic-link sends.

### References

CWE-307, OWASP A07:2021.

---

## SEC-H5 — Redis has no authentication or TLS; stores plaintext MFA setup secrets and login tokens

### Severity

**High.**

### Description

The ioredis client is created with only host/port — no password, no TLS. Redis holds security-critical material: the `mfa_setup:<userId>` TOTP secret **in plaintext** (unlike the AES-encrypted persisted copy), magic-link tokens (valid login credentials), OIDC authorization codes / access / refresh tokens, and rate-limit counters. The dev compose additionally publishes Redis to the host.

### Why it is dangerous

Anyone reaching Redis (published dev port, shared container network, lateral movement) can read plaintext MFA setup secrets, steal a magic-link token to log in as any user mid-flow, and read OIDC tokens.

### Location

- `src/core/database/redis.ts:5-10` (no `password`/TLS)
- `docker-compose.dev.yml` (Redis port published to host)
- `mfa.service.ts` (`mfa_setup:<userId>` stored unencrypted)

### Evidence

```ts
const redisConfig = { host: config.REDIS.HOST, port: Number(config.REDIS.PORT) };
const redisClient = new Redis(redisConfig);
```

### Recommendation

Set `requirepass` and pass `REDIS_PASSWORD` to ioredis; enable TLS in production; do not publish the Redis port to the host in dev; encrypt (or shorten the TTL of) the `mfa_setup` secret.

### References

CWE-306 (Missing Authentication for Critical Function), CWE-311 (Missing Encryption of Sensitive Data), OWASP A05:2021.

---

## SEC-H6 — OAuth `state` is not integrity-protected (login CSRF); client JSON parsed from `state`

### Severity

**High.**

### Description

The Google OAuth callback parses `redirectUrl` and `uid` out of the `state` query parameter as JSON, but the server never issues and verifies a random `state` value. The standard OAuth CSRF protection is therefore absent — `state` is used only as a client-controlled data carrier.

### Why it is dangerous

An attacker can craft a callback with an arbitrary `state.uid` to drive the OIDC `submitLogin` path (login CSRF). The open-redirect component is contained by `getValidRedirectUrl` (anchored origin allowlist — good), but redirect validation and CSRF protection are different controls, and the latter is missing.

### Location

`src/api/v1/controllers/oauth.controller.ts:33-46,56-57`.

### Evidence

```ts
const state = req.query.state as string;
const parsed = JSON.parse(state);
if (parsed.uid) {
  await this.oidcService.submitLogin(req, res, user.id);
  return;
}
redirectUrl = parsed.redirectUrl;
```

### Recommendation

Generate a random `state` server-side before redirecting to Google, store it (Redis/session) alongside the associated `uid`/`redirectUrl`, and on callback verify the returned `state` matches before trusting any embedded data.

### References

CWE-352 (CSRF), CWE-601 (Open Redirect — mitigated), OWASP A01:2021.

---

## SEC-H7 — Account / email enumeration on recovery endpoints

### Severity

**High.**

### Description

`forgot-password`, `resend-verification`, and magic-link `login` throw `NotFoundException('User not found')` for unknown emails, while known emails return a generic 200. In `forgotPassword`, the not-found throw also runs _before_ rate limiting.

### Why it is dangerous

Attackers can enumerate valid accounts by observing the status-code / body difference, defeating the deliberately generic controller messaging and enabling targeted phishing / credential stuffing.

### Location

`src/api/v1/services/auth.service.ts` (`forgotPassword` ~line 372, `resendVerification` ~line 161); `src/api/v1/services/magic-link.service.ts` (~line 40).

### Recommendation

Return the same generic success response regardless of whether the account exists (do the lookup, but never signal existence), and apply rate limiting _before_ the user lookup.

### References

CWE-203 / CWE-204 (Observable Discrepancy), OWASP A07:2021.

---

# Medium Severity

## SEC-M1 — Password-reset OTP generated with `Math.random()`

**Severity: Medium.** `generateOTP` builds the 6-digit reset OTP from `Math.random()`, which is not a CSPRNG and is predictable given observed output. Mitigated (not eliminated) by the 3–5 attempt cap.
**Location:** `src/core/common/utils/crypto.ts:52-59`.

```ts
otp += digits[Math.floor(Math.random() * digits.length)];
```

**Fix:** Use `crypto.randomInt(0, 10)` per digit (or `crypto.randomInt(0, 1_000_000)` zero-padded). _CWE-338, CWE-330._

## SEC-M2 — MFA backup codes have only 32 bits of entropy

**Severity: Medium.** `crypto.randomBytes(4)` → 8 hex chars (2³²). Codes are bcrypt-hashed and single-use (good), but the space is brute-forceable, compounding `SEC-H3`/`SEC-H4`.
**Location:** `src/api/v1/services/mfa.service.ts:128`.
**Fix:** Use `crypto.randomBytes(10)` (80 bits), rendered as base32 groups. _CWE-330._

## SEC-M3 — Internal error messages leaked to clients on 500s

**Severity: Medium.** The catch-all handler returns `error?.message` in the JSON body unconditionally (no `NODE_ENV` gate), disclosing Prisma/driver/internal details.
**Location:** `src/api/v1/middlewares/error-handler.middleware.ts:41-44`.

```ts
return response
  .status(500)
  .json({ message: 'Internal Server Error', error: error?.message ?? '...' });
```

**Fix:** Log `error.message` server-side only; return a generic body for 500s. _CWE-209._

## SEC-M4 — Sensitive tokens/OTPs written to logs in non-production

**Severity: Medium.** Reset OTPs, email-verification tokens, and the full magic-link URL are logged via `logger.info` when `NODE_ENV !== 'production'`; Winston persists to `logs/*.log` on disk. A misconfigured or internet-reachable staging box leaks valid credentials.
**Location:** `src/api/v1/services/auth.service.ts:~106,~179,~386`; `src/api/v1/services/magic-link.service.ts:~55-56`.
**Fix:** Never log token/OTP values; gate behind an explicit debug flag and redact. _CWE-532._

## SEC-M5 — Email HTML built via unescaped interpolation (email/HTML injection)

**Severity: Medium.** `name`, `deviceInfo` (User-Agent), and `ipAddress` — all attacker-influenceable — are interpolated directly into email HTML with no escaping. Enables injecting markup/phishing links into legitimately-sent, domain-reputable emails (e.g. the "new device" alert).
**Location:** `src/core/mailers/resend.ts` (template literals).
**Fix:** HTML-escape all interpolated dynamic values, or use an auto-escaping template engine. _CWE-79 (email context), CWE-80._

## SEC-M6 — Bcrypt cost factor of 10 is below current guidance

**Severity: Medium.** Applies to all password and backup-code hashing; OWASP recommends ≥ 12.
**Location:** `src/core/common/utils/bcrypt.ts:3` (`saltRounds = 10`).
**Fix:** Raise to 12 (benchmark to ~250 ms) and make it configurable. _CWE-916._

## SEC-M7 — Non-constant-time comparison of CSRF token and OTP

**Severity: Medium.** CSRF token (`csrfCookie !== csrfHeader`) and OTP (`storedOtp !== otp`) are compared with `!==`, which can leak length/prefix via timing.
**Location:** `src/api/v1/middlewares/csrf.middleware.ts:18`; `src/api/v1/services/auth.service.ts:~419`.
**Fix:** Use `crypto.timingSafeEqual` over equal-length buffers. _CWE-208._

## SEC-M8 — MFA-login token is replayable within its window (not single-use / not context-bound)

**Severity: Medium.** The `mfaLoginToken` (5-min JWT) is the sole gate between password success and full session issuance. It is not bound to device/IP and is not invalidated after use — if leaked (see `SEC-H5`, cookie scope), it can be replayed within the window.
**Location:** `src/api/v1/services/auth.service.ts:~229-239`; `mfa.service.ts` `verifyMFAForLogin`.
**Fix:** Back the MFA challenge with a server-side one-time nonce in Redis keyed to the login attempt; delete on use. _CWE-384, CWE-613._

## SEC-M9 — CSRF origin check disabled outside production

**Severity: Medium.** `requireAuthAction` only performs the origin check when `NODE_ENV === 'production'`, weakening defense-in-depth in staging/test environments that may be reachable.
**Location:** `src/api/v1/middlewares/csrf.middleware.ts:10`.
**Fix:** Enforce the origin check in all environments (allow configuring dev origins). _CWE-352._

## SEC-M10 — CSP allows `'unsafe-inline'` for scripts globally

**Severity: Medium.** `'unsafe-inline'` on `script-src` negates CSP's core XSS mitigation across the entire app, not just the OIDC interaction pages that need it.
**Location:** `src/api/index.ts:29`.
**Fix:** Scope the relaxed CSP to only the OIDC interaction routes (per-route helmet) and use nonces/hashes instead of `'unsafe-inline'`. _CWE-1021, CWE-693._

## SEC-M11 — Auth cookies scoped to `DOMAIN_URL` with `sameSite: 'lax'`

**Severity: Medium.** Cookie `domain` defaults to `config.DOMAIN_URL`; setting a bare parent domain scopes refresh/CSRF/reset/MFA cookies to all subdomains. `sameSite: 'lax'` lets the refresh cookie ride top-level navigations. A less-trusted subdomain could read the non-httpOnly CSRF cookie and receive the httpOnly cookies.
**Location:** `src/core/common/utils/cookie.ts:27-32`.
**Fix:** Omit `domain` unless subdomain sharing is required; use `sameSite: 'strict'` for auth/refresh cookies; ensure `secure` is unconditional in production. _CWE-1275, CWE-539._

---

# Low Severity / Informational

## SEC-L1 — `verifyJwtToken` does not pin the `algorithms` allowlist

**Severity: Low (defense-in-depth).** `src/core/common/utils/jwt.ts:64-81` calls `jwt.verify` without an `algorithms` list. In practice this is **not** exploitable here: all four token secrets are symmetric HMAC strings and `jsonwebtoken@9` rejects `alg: none` by default and will not switch to asymmetric verification with a string secret. The Passport strategy already pins `algorithms: ['HS256']`. Still, pin it everywhere as a best practice.
**Fix:** Add `algorithms: ['HS256']` to the `defaults` object in `jwt.ts`. _CWE-347._

> _Note: one review pass rated this Critical; it was downgraded after verifying the symmetric-secret usage and `jsonwebtoken@9` behavior._

## SEC-L2 — No email-verification gate at login

`AuthController.login` never checks `user.emailVerified`; unverified accounts can fully authenticate, undermining the verification flow. **Fix:** reject or restrict login when `!emailVerified` (if intended). _CWE-287._

## SEC-L3 — `revokeMFA` requires no re-authentication

`mfa.service.ts:~154-184` disables 2FA with only a valid access token — no password or current-TOTP step. A stolen access token can turn off 2FA. **Fix:** require password or TOTP re-auth. _CWE-306._

## SEC-L4 — First-party refresh tokens are not single-use

`auth.service.ts:~316-355` issues a new refresh token but keeps the same `sessionId` valid, so an old refresh token still verifies until session expiry (replay window). Rotation is enabled for OIDC only. **Fix:** rotate + invalidate on refresh. _CWE-613._

## SEC-L5 — Google OAuth auto-links to any existing account by email

`oauth.service.ts:~43-58` links a Google identity to a pre-existing (possibly unverified) credential account by email — a pre-account-takeover surface. **Fix:** require the credential account to be verified before auto-linking. _CWE-287._

## SEC-L6 — Swagger UI mounted unauthenticated at `/docs`

`src/api/index.ts:74` serves the full API surface with no auth or environment guard. **Fix:** gate `/docs` behind auth or disable when `NODE_ENV === 'production'`. _CWE-200._

## SEC-L7 — `sessionToken` generated but never validated

A 64-byte opaque `sessionToken` is stored on the session row but auth relies entirely on the JWT `sessionId`; the token is dead weight giving a false sense of security. **Fix:** validate against it, or remove it.

## SEC-L8 — No maximum password length (bcrypt 72-byte truncation)

`auth.validator.ts` `passwordSchema` has no `.max()`; bcrypt silently truncates at 72 bytes. **Fix:** add `.max(72)`. _CWE-521._

## SEC-L9 — Device fingerprint is trivially spoofable

`crypto.ts:65-68` fingerprints `sha256(userAgent + ipAddress)`, both attacker-controlled, so new-device alerts can be suppressed. Informational. _CWE-290._

## SEC-L10 — Dev compose bind-mounts the repo (including `.env`) into the container

`docker-compose.dev.yml` mounts `.:/app`; `.dockerignore` only affects build context, not volume mounts, so the live `.env` is present inside the dev container. Informational.

## SEC-L11 — `DATABASE_URL` has an unescaped `@` in the password

`.env:14` — the `@` in `Amansahu@09` is a URL delimiter and corrupts connection-string parsing. **Fix:** URL-encode to `Amansahu%4009`. Functional bug with security-adjacent impact (indicates hand-copied real credentials). _CWE-diagnostic._

---

## Security Summary

- **Total Critical: 4** — SEC-C1 (reset-token account takeover), SEC-C2 (OIDC MFA bypass), SEC-C3 (live secrets on disk), SEC-C4 (TOTP key default).
- **Total High: 7** — SEC-H1 (CORS substring), SEC-H2 (cache revocation + sensitive data), SEC-H3 (XFF spoof / IP-only limits), SEC-H4 (missing magic-link/MFA limits), SEC-H5 (unauthenticated Redis), SEC-H6 (OAuth state CSRF), SEC-H7 (enumeration).
- **Total Medium: 11** — SEC-M1…SEC-M11.
- **Total Low/Info: 11** — SEC-L1…SEC-L11.

### Prioritized remediation order

1. **SEC-C1, SEC-C2** — code-level auth bypasses; one-line-ish fixes, highest exploitability. Fix and deploy immediately.
2. **SEC-C3** — rotate every secret; assume compromised.
3. **SEC-C4** — remove the TOTP-key default; require + validate at boot.
4. **SEC-H1, SEC-H2, SEC-H3** — CORS exact-match, sanitized/re-validated session cache, `trust proxy` + per-account lockout.
5. **SEC-H4, SEC-H5, SEC-H6, SEC-H7** — route limiters, Redis auth/TLS, OAuth state verification, uniform recovery responses.
6. **Medium tier** — CSPRNG OTP, stronger backup codes, error-message hygiene, log redaction, email escaping, bcrypt cost, constant-time compares, single-use MFA token, CSP scoping, cookie hardening.
7. **Low tier** — pin JWT algorithms, verification gate, MFA re-auth, refresh single-use, docs auth, cleanup.
