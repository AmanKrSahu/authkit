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
- **Auth Limiter:** stricter limits on `/auth/*` endpoints (e.g., Login, Register) to prevent Brute Force and Credential Stuffing attacks.
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

---

## 3. The Role of Redis

Redis acts as a high-performance "Speed Layer" that facilitates security features without compromising latency.

| Feature              | How Redis is Used                                                                                               | Benefit                                                                                          |
| :------------------- | :-------------------------------------------------------------------------------------------------------------- | :----------------------------------------------------------------------------------------------- |
| **Session Caching**  | Stores active user sessions (JSON). The JWT Strategy checks Redis _first_ before hitting the DB.                | drastic reduction in DB load; sub-millisecond authentication checks.                             |
| **Rate Limiting**    | Stores counters and expiry times for IP addresses.                                                              | Atomic increments prevent race conditions; extremely fast.                                       |
| **Ephemeral Tokens** | Stores short-lived tokens: <br> - MFA Setup Secrets <br> - Email Verification Tokens <br> - Password Reset OTPs | Automatic expiration (TTL) handles cleanup; data is never persisted to disk (DB) until verified. |

---

## 4. Summary of Authentication Workflow

1.  **User Logs In (without MFA):**
    - Server verifies credentials.
    - Creates Session in DB & Redis.
    - Generates Access Token (returned in Body).
    - Generates Refresh Token (returned in `HttpOnly` Cookie).
    - Generates CSRF Token (returned in Readable Cookie).
2.  **User Makes Request:**
    - Client adds `Authorization: Bearer <token>`.
    - Client adds `x-csrf-token` header (from cookie).
    - Server validates Access Token signature + expiration.
3.  **Access Token Expires:**
    - Client hits `/refresh-token`.
    - Browser sends Refresh Token cookie.
    - Client sends `x-csrf-token` header.
    - Server verifies Refresh Token against Redis/DB Session.
    - If valid, Server rotates tokens and returns new Access Token.
