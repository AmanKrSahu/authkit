# Security & Authentication Architecture

This document outlines the security and authentication strategy adopted in the AuthKit application. We utilize a **hybrid approach** combining the statelessness of JWTs with the control of server-side sessions, reinforced by robust defense-in-depth mechanisms like CSRF protection and Rate Limiting.

## 1. Authentication & Authorization Strategy

We implement a dual-token system (Access Token + Refresh Token) to balance security and user experience.

### 1.1. The Dual-Token System

- **Access Token (JWT)**
  - **Purpose:** Used to authenticate API requests.
  - **Storage:** Sent in the JSON response body upon login. The client is expected to store this in **memory** (not LocalStorage/Cookies).
  - **Transmission:** Sent via the `Authorization: Bearer <token>` header.
  - **Lifespan:** Short (e.g., 15 minutes).
  - **Security Benefit:** By not storing the access token in a cookie, we avoid standard CSRF attacks on API endpoints. By not storing it in LocalStorage, we mitigate the risk of XSS attacks stealing the token (though XSS can still make requests, it cannot persist the theft easily).

- **Refresh Token (JWT)**
  - **Purpose:** Used to obtain a new Access Token when the current one expires.
  - **Storage:** stored in an **`HttpOnly` Cookie**.
  - **Transmission:** Automatically sent by the browser to the `/refresh-token` endpoint.
  - **Lifespan:** Long (e.g., 7 days).
  - **Security Benefit:** `HttpOnly` prevents client-side JavaScript from reading the token, making it immune to XSS theft.

### 1.2. CSRF Protection (Double-Submit Cookie Pattern)

Since we use cookies for Refresh Tokens and Authentication actions (like Password Reset), we implement the **Double-Submit Cookie** pattern to prevent Cross-Site Request Forgery (CSRF).

- **Mechanism:**
  1.  **Cookie:** The server sets a `csrfToken` cookie (readable by client JS).
  2.  **Header:** For every state-changing request (POST, PUT, DELETE), the client must read this cookie and send its value in the `x-csrf-token` header.
  3.  **Origin Validation (Production)**: In production environments, the `requireAuthAction` middleware validates the request's `Origin` header against the unified origin policy.
  4.  **Token Comparison**: The middleware verifies that `cookie.csrfToken === header['x-csrf-token']`.
- **Workflow:**
  - **Login/MFA:** Upon successful authentication, the server generates a random UUID and sets the `csrfToken` cookie.
  - **Protected Actions:** Endpoints like `/logout`, `/refresh-token`, and `/reset-password` enforce the check.
- **Security Benefit:** Malicious sites can force a browser to send cookies, but they **cannot** read the cookie to set the custom header (due to Same-Origin Policy).

### 1.3. Headers & Cookie Configurations

- **Cookies:**
  - `HttpOnly`: true (for Refresh, MFA, Reset tokens) - Blocks JS access.
  - `Secure`: true (in Production) - HTTPS only.
  - `SameSite`: 'Lax' - Prevents CSRF on cross-site subrequests.
  - `Domain`: Restricted to the specific API domain.
- **Headers:**
  - `Cache-Control: no-store`: Applied to all sensitive endpoints (Login, MFA, Refresh) to prevent browsers or proxies from caching sensitive JSON responses (which might contain Access Tokens).

---

## 2. Core Security Measures

### 2.1. Session Management

While JWTs are stateless, we track **Sessions** in the database to allow for immediate revocation.

- **Database-Backed Role:** Every successful login creates a `Session` record in the database. The Refresh Token is inextricably linked to this Session ID.
- **Revocation:**
  - **Logout:** Marks the session as revoked.
  - **Password Change:** Revokes **all** active sessions for the user.
  - **Suspicious Activity:** Administrators can revoke specific sessions.
- **Device Fingerprinting:** We capture User-Agent and IP address to generate a device fingerprint. This helps in detecting "New Devices" and notifying the user via email.
- **Per-Account Lockout**: To prevent credential stuffing and brute-force campaigns, we enforce a per-account lockout policy. If an email address experiences 5 failed login attempts within 15 minutes, it is temporarily locked for 15 minutes. This status is checked immediately at the start of the login request (before looking up the user or running bcrypt) to protect backend database and CPU resources from denial-of-service, and to mitigate username enumeration.

### 2.2. Rate Limiting

We use **Redis** to implement sliding-window rate limiting.

- **Upstream Gateway Protection**: In production, public traffic routes through an Nginx container. Nginx terminates SSL/TLS and overwrites proxy headers (`X-Real-IP`, `X-Forwarded-For`, `X-Forwarded-Proto`), stripping out client-side header spoofing.
- **Proxy Trust Configuration**: Express is configured dynamically via the `TRUST_PROXY` environment variable. When set to trust the proxy, Express securely resolves client IPs using native `req.ip`.
- **Global Limiter:** Protects the entire API from DDoS attacks (e.g., 200 requests/15min).
- **Auth Limiter:** Stricter limits on `/auth/*` endpoints, magic-link routes, and MFA verify routes via the `authRateLimiter` middleware to prevent brute-force attacks.
- **MFA/OTP Limiter:** Very strict limits (maximum 5 attempts) on MFA verification. Attempts are tracked in Redis per `userId` globally (`mfa_limit:<userId>`) to prevent brute-force bypasses via IP rotation.
- **Magic-Link Send Limiter:** Magic link generation requests (`POST /magic-link/login`) enforce the in-service rate limit checker (`rate_limit:MAGIC_LINK:<email>:<ip>`) to prevent mail-bombing and SMTP resource abuse.

### 2.3. Data Sanitization

To prevent **Data Leakage**, we strictly sanitize objects before returning them in API responses.

- **Mechanism:** A central `sanitizeUser` utility Function.
- **Role:** Explicitly removes sensitive fields:
  - `password` (hash)
  - `twoFactorSecret` (MFA secret)
  - `backupCodes`
  - `accounts` (Prevention of relational leak)
  - `sessions`
- **Benefit:** Ensures that even if a developer accidentally returns a full User object, the sensitive data is stripped out before it reaches the client.

### 2.4. OpenID Connect (OIDC) Security

Our OIDC Provider implementation adheres to strict security standards to safely act as an Identity Provider.

- **PKCE Enforcement:** Proof Key for Code Exchange (RFC 7636) is **mandatory** for all clients. This prevents authorization code interception attacks.
- **Client Secret Hashing:** Client secrets are never stored in plaintext. They are hashed using **bcrypt** (cost 12), ensuring that even a database compromise does not leak usable secrets.
- **Pairwise Pseudonymous Identifiers (PPI):** (Optional/Configurable) Can be used to prevent correlation of users across different clients.
- **Interaction Security:**
  - **Strict Cookie Policy:** Interaction session cookies are `HttpOnly`, `Signed`, and `SameSite=Lax`.
  - **Short-Lived Sessions:** Interaction sessions expire quickly (e.g., 15 minutes) to reduce the attack window.
- **Token Rotation:** Refresh Tokens issued via OIDC are rotated upon use, detecting and preventing token theft and replay.
- **Context Preservation:** We strictly bind external authentication flows (Google, Magic Link) to the initiating OIDC transaction. For Google OAuth, the `state` parameter is a cryptographically secure random `stateId` (UUID) whose payload is cached in Redis (`oauth_state:${stateId}`). Upon callback, the state is validated, immediately deleted (single-use replay protection), and the associated `uid` and `redirectUrl` are processed. This blocks login CSRF and session injection.
- **MFA Enforcement:** Multi-Factor Authentication is enforced _within_ the OIDC interaction pipeline. If a user has MFA enabled, the OIDC flow halts until a valid TOTP code is provided, preventing bypass via single-factor entry points.

### 2.5. Session Bridging & Unified Identity

To provide a seamless Single Sign-On (SSO) experience, we implement a **Session Bridge** between our Direct API authentication and OIDC flows.

- **Mechanism:** The OIDC interaction endpoint checks for the presence of a valid `refreshToken` cookie (used by the Direct API).
- **Validation:** It uses `SessionService.validateSession` to cryptographically verify the token and check the database for revocation or expiration.
- **Safety:** This validation is **read-only** and does not rotate the token, ensuring the original session remains undisturbed while establishing a new OIDC session.
- **Result:** Users authenticated on the main platform are automatically authenticated for any OIDC client without re-entering credentials.

### 2.6. Secure Secret & Key Generation

To ensure robust cryptographic security, AuthKit includes an automated script (`pnpm generate:secrets`) that securely generates:

1. **JWT & Session Secrets**: Cryptographically secure 256-bit random strings using `node:crypto` (covering auth, refresh, reset, and MFA tokens).
2. **TOTP Encryption Key (`AUTHENTICATOR_APP_SECRET`)**: A cryptographically secure 256-bit key used to encrypt users' Google Authenticator seeds at rest. The application validates and rejects secrets under 32 bytes of secure entropy at boot.
3. **OIDC JWKS**: A securely generated RS256 keypair (using `jose`) for signing OIDC tokens.
   By keeping secret generation automated, we reduce the risk of weak, manually chosen passwords or keys being used in production.

---

## 3. The Role of Redis

Redis acts as a high-performance "Speed Layer" that facilitates security features without compromising latency.

| Feature              | How Redis is Used                                                                                                                                                     | Benefit                                                                                               |
| :------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :---------------------------------------------------------------------------------------------------- |
| **Session Caching**  | Stores sanitized session and user profiles (excluding credential hashes/TOTP secrets). The JWT Strategy validates session expiry and revocation status on cache hits. | Drastic reduction in DB load; sub-millisecond authentication checks with real-time revocation checks. |
| **Rate Limiting**    | Stores counters and expiry times for IP addresses.                                                                                                                    | Atomic increments prevent race conditions; extremely fast.                                            |
| **Login Lockout**    | Tracks per-account failure counters (`failed_attempts:<email>`) and lockout flags (`lockout:<email>`) with a 15-minute sliding TTL.                                   | Neutralizes password brute-forcing across rotating IPs.                                               |
| **Ephemeral Tokens** | Stores short-lived tokens: <br> - Encrypted MFA Setup Secrets (using AES-256-GCM) <br> - Email Verification Tokens <br> - Password Reset OTPs                         | Automatic expiration (TTL) handles cleanup; data is never persisted to disk (DB) until verified.      |

### 3.1. Redis Security Configuration

To protect transient credentials, rate limit counters, and session metadata cached in Redis:

- **Authentication**: Redis requires a secure password configured via `REDIS_PASSWORD` (loaded dynamically into the `ioredis` client and enforced in the server container via `--requirepass`).
- **Network Containment**: Redis container ports are not published to the host in development, restricting access to inside the isolated Docker bridge network.
- **Transport Security (TLS)**: Support for encrypted transport is supported via `REDIS_TLS="true"` settings.
- **Cache Encryption**: Ephemeral MFA enrollment seeds (`mfa_setup:<userId>`) are encrypted using AES-256-GCM before storage in Redis, preventing plaintext exposures to the internal network.
