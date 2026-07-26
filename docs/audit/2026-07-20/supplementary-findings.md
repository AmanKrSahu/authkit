# AuthKit — Supplementary Audit Developments

This document tracks additional architectural designs, integration discoveries, and technical developments that arose during the execution of the master audit task plan.

---

## Proxy Trust & Reverse Proxy Integration (SEC-H3 & SEC-H1)

This section details the design requirements for client IP retrieval, proxy header trust, Nginx reverse proxying, and their direct impact on the Unified Origin Validator.

### 1. SEC-H3 Overview: Vulnerabilities & Requirements

Task **1.7 (SEC-H3)** in [task.md](./task.md) addresses two core vulnerabilities from the [Security Audit Report](./security-audit.md#SEC-H3):

- **Vulnerability A (Spoofable Client IPs)**: The application currently determines the client's IP using a custom `getClientIP` utility in [metadata.ts](../../../src/core/common/utils/metadata.ts) that blindly reads the client-supplied `X-Forwarded-For` header. Attackers can send request headers like `X-Forwarded-For: 1.1.1.1` to spoof their identity, corrupt audit logs, and bypass IP-based rate limiters.
- **Vulnerability B (Absence of Per-Account Lockout)**: The current rate limiters only track client IP addresses. An attacker rotating client IPs can bypass limits and repeatedly attempt passwords against a single account (brute-forcing).

#### Changes required to implement SEC-H3:

1.  **Configure Proxy Trust**: Tell Express how to safely identify the client's IP and protocol using environment variables (e.g. `TRUST_PROXY=true`).
2.  **Harden IP Retrieval**: Modify the `getClientIP` function to rely on Express's standard `req.ip` rather than parsing header strings manually.
3.  **Implement Per-Account Lockout**: Implement a Redis-backed counter (e.g., `failed_attempts:<email>`) that temporarily locks out authentication attempts on a specific email address after 5 consecutive failures for 15 minutes.

---

### 2. Dependency Between SEC-H3 & The Unified Origin Validator

Implementing the **Unified Origin Validator** (SEC-H1) established a critical dependency on SEC-H3's proxy configurations:

- **Protocol Check Constraint**: The Unified Origin Validator enforces the `https` protocol for dynamic subdomains in production.
- **The Proxy Problem**: When deployed in production, AuthKit runs behind a reverse proxy (e.g., Nginx) that terminates SSL and proxies traffic internally over unencrypted HTTP. Without proxy trust configured in Express, `req.protocol` will evaluate to `http`, causing the Unified Origin Validator to **incorrectly reject legitimate production requests**.
- **The Solution**: Express must be configured to trust the proxy configuration (`app.set('trust proxy', 1)`). This allows Express to read the `X-Forwarded-Proto` header forwarded by Nginx and correctly evaluate the request protocol as `https`.

> [!IMPORTANT]
> Enabling proxy trust in Express is a prerequisite for the Unified Origin Validator to operate correctly in production environments behind a reverse proxy.

---

### 3. Proxy Architecture: With Nginx vs. Without Nginx

The per-account lockout logic remains identical in both deployment modes. However, the client IP and protocol detection strategy changes:

| Architectural Aspect              | Behind Nginx (Production Reverse Proxy)                                                                     | Direct Exposure (Local Runtime / No Proxy)                                                |
| :-------------------------------- | :---------------------------------------------------------------------------------------------------------- | :---------------------------------------------------------------------------------------- |
| **Express Configuration**         | `app.set('trust proxy', 1)` (trust 1 hop)                                                                   | `app.set('trust proxy', false)` (disable trust)                                           |
| **IP Header Spoofing Prevention** | Handled at the **Nginx** gateway level. Nginx overwrites/sanitizes client-supplied headers before proxying. | Handled at the **Express** level. Express ignores all incoming `X-Forwarded-For` headers. |
| **Client IP Source**              | Read from `X-Forwarded-For` (via Express `req.ip`).                                                         | Read directly from the TCP socket connection (via Express `req.ip`).                      |

---

### 4. The Dynamic Strategy (Best Approach)

To support both configurations seamlessly (portability between dev/prod), the system should use an environment-driven proxy configuration:

#### A. Dynamic Proxy Trust in Express

Define a `TRUST_PROXY` configuration parameter. In [index.ts](../../../src/api/index.ts):

```ts
if (config.TRUST_PROXY === 'true') {
  app.set('trust proxy', true);
} else if (config.TRUST_PROXY === 'false') {
  app.set('trust proxy', false);
} else if (config.TRUST_PROXY) {
  const hops = Number(config.TRUST_PROXY);
  app.set('trust proxy', isNaN(hops) ? config.TRUST_PROXY : hops);
}
```

#### B. Secure IP Retrieval

Refactor `getClientIP` in [metadata.ts](../../../src/core/common/utils/metadata.ts) to utilize Express `req.ip`:

```ts
export const getClientIP = (req: Request): string => {
  return req.ip || '127.0.0.1';
};
```

_Note: Under `trust proxy: false`, Express automatically reads `req.socket.remoteAddress`; under `trust proxy: true/1`, it reads the trusted proxy-forwarded IP, preventing header spoofing._

#### C. Nginx Gateway Configurations (Production)

In [docker-compose.prod.yml](../../../docker-compose.prod.yml), introduce a reverse-proxy Nginx gateway container.

**Nginx Header Forwarding (`nginx.conf` template):**

```nginx
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
```

The application container's direct port exposition (e.g. `8000:8000`) is removed, securing all access routes through the Nginx gateway container.
