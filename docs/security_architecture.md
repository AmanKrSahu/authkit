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
  3.  **Validation:** The `requireAuthAction` middleware checks if `cookie.csrfToken === header['x-csrf-token']`.
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

### 2.2. Rate Limiting

We use **Redis** to implement sliding-window rate limiting.

- **Global Limiter:** Protects the entire API from DDoS attacks (e.g., 100 requests/15min).
- **Auth Limiter:** Stricter limits on `/auth/*` endpoints (e.g., Login, Register) to prevent Brute Force and Credential Stuffing attacks.
- **MFA/OTP Limiter:** Very strict limits (e.g., 3-5 attempts) on OTP verification to prevent guessing.

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
- **Context Preservation:** We strictly bind external authentication flows (Google, Magic Link) to the initiating OIDC transaction using the `uid` parameter (via OAuth `state` or Redis). This prevents session injection attacks where a user starts a flow in one context and finishes it in another.
- **MFA Enforcement:** Multi-Factor Authentication is enforced _within_ the OIDC interaction pipeline. If a user has MFA enabled, the OIDC flow halts until a valid TOTP code is provided, preventing bypass via single-factor entry points.

### 2.5. Session Bridging & Unified Identity

To provide a seamless Single Sign-On (SSO) experience, we implement a **Session Bridge** between our Direct API authentication and OIDC flows.

- **Mechanism:** The OIDC interaction endpoint checks for the presence of a valid `refreshToken` cookie (used by the Direct API).
- **Validation:** It uses `SessionService.validateSession` to cryptographically verify the token and check the database for revocation or expiration.
- **Safety:** This validation is **read-only** and does not rotate the token, ensuring the original session remains undisturbed while establishing a new OIDC session.
- **Result:** Users authenticated on the main platform are automatically authenticated for any OIDC client without re-entering credentials.

### 2.6. Secure Secret & Key Generation

To ensure robust cryptographic security, AuthKit includes an automated script (`pnpm generate:secrets`) that securely generates:

1. **JWT & Session Secrets**: Cryptographically secure 256-bit random strings using `node:crypto`.
2. **OIDC JWKS**: A securely generated RS256 keypair (using `jose`) for signing OIDC tokens.
   By keeping secret generation automated, we reduce the risk of weak, manually chosen passwords or keys being used in production.

---

## 3. The Role of Redis

Redis acts as a high-performance "Speed Layer" that facilitates security features without compromising latency.

| Feature              | How Redis is Used                                                                                               | Benefit                                                                                          |
| :------------------- | :-------------------------------------------------------------------------------------------------------------- | :----------------------------------------------------------------------------------------------- |
| **Session Caching**  | Stores active user sessions (JSON). The JWT Strategy checks Redis _first_ before hitting the DB.                | Drastic reduction in DB load; sub-millisecond authentication checks.                             |
| **Rate Limiting**    | Stores counters and expiry times for IP addresses.                                                              | Atomic increments prevent race conditions; extremely fast.                                       |
| **Ephemeral Tokens** | Stores short-lived tokens: <br> - MFA Setup Secrets <br> - Email Verification Tokens <br> - Password Reset OTPs | Automatic expiration (TTL) handles cleanup; data is never persisted to disk (DB) until verified. |
