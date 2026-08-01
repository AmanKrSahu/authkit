# Design Decision — Client IP Verification & Per-Account Lockout (SEC-H3)

This document outlines the architectural decisions and implementation strategies adopted to resolve finding **SEC-H3** (client IP spoofing vulnerabilities and lack of per-account lockout) while establishing a production-grade reverse-proxy setup.

---

## 1. The Vulnerabilities (SEC-H3)

Prior to this remediation, AuthKit suffered from two major authentication path vulnerabilities:

### A. Spoofable Client IPs (`X-Forwarded-For` injection)

The custom `getClientIP` utility in the codebase extracted IP addresses by manually splitting the client-supplied `X-Forwarded-For` header. Because the application did not verify whether the header originated from a trusted upstream gateway, an attacker could attach arbitrary headers like `X-Forwarded-For: 1.1.1.1` to reset their IP rate-limit buckets and corrupt audit logs.

### B. IP-Only Rate Limiting (Missing Account Lockout)

Rate limiting was tracked solely by client IP address. An attacker rotating their IP address (via proxy pools or header spoofing) could run brute-force password guessing against a single victim's account indefinitely without triggering a lockout.

---

## 2. Architecture & Design Decisions

To mitigate these issues while keeping the application portable between local development and production environments, we adopted a dual-strategy design:

```
[ Client Browser ]
        │ (Attaches arbitrary headers/protocols)
        ▼
[ Nginx Gateway Container (Port 80/443) ]
        │ (Terminates SSL, overwrites X-Forwarded-For with true client IP)
        ▼
[ Express API Container (Port 8000) ]
        │ (Reads headers via configured trust proxy level)
        ▼
[ Redis Session & Lockout Store ]
```

### Decision 1: Overwriting Headers at the Gateway (Nginx)

Rather than writing complex header-parsing validation logic inside Node.js, we introduce an **Nginx Reverse Proxy Container** to act as our production ingress point.

- Direct host port exposure (port `8000`) is removed from the `api` container.
- Nginx binds to ports `80` and `443` and handles all SSL termination.
- Nginx is explicitly configured to overwrite client-supplied headers before proxying requests internally to the API container:
  ```nginx
  proxy_set_header X-Real-IP $remote_addr;
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Proto $scheme;
  ```

### Decision 2: Environment-Driven Proxy Trust

To ensure the backend works seamlessly in local development (where there is no Nginx) and production (behind Nginx or cloud load balancers), we made Express's proxy trust dynamic:

- In `app.config.ts`, we expose a `TRUST_PROXY` parameter.
- At boot time in `index.ts`, Express is configured based on this value:
  - **`TRUST_PROXY=false`** (default for Dev): Express ignores all proxy headers and reads the raw TCP socket connection IP, preventing local header spoofing.
  - **`TRUST_PROXY=1`** (default for Nginx Prod): Express trusts the immediate upstream proxy (Nginx) and extracts the true client IP from `X-Forwarded-For` and protocol from `X-Forwarded-Proto` securely.
  - **`TRUST_PROXY=<number>`**: Allows nesting behind multiple proxies/CDNs (e.g. Cloudflare -> AWS ALB -> Nginx).

### Decision 3: Standardizing on Express Native `req.ip`

We refactored `getClientIP` to return `req.ip ?? '127.0.0.1'`. When `trust proxy` is configured correctly, Express natively handles header chain validation and resolves the true client IP safely, neutralizing spoofing vectors.

### Decision 4: Redis-Backed Per-Account Lockout

To stop password brute-force campaigns:

- **Lockout Rule**: If a specific email address receives 5 failed credential authentication attempts within 15 minutes, the account is temporarily locked.
- **Lockout Storage**: Tracked in Redis using two key shapes:
  - `failed_attempts:<email>`: An atomic counter incremented on every failed attempt with a 15-minute sliding TTL.
  - `lockout:<email>`: A temporary block flag set for 15 minutes when attempts exceed 5.
- **Timing and Enumeration Prevention**: Lockout status is checked _first_ at the beginning of the `login()` method before running any expensive database queries or bcrypt checks. If a login attempt fails due to a non-existent user, we still increment the counter for that email. This shields against database resource exhaustion and prevents attackers from enumerating valid usernames by observing differences in lockout behaviors.
- **Resolution**: Successful logins delete both keys, resetting the counter.
- **Placement**: All counter modifications, checks, and resets are encapsulated inside security utility helpers in `metadata.ts`, keeping the authentication service decoupled from database/cache side-effects.

---

## 3. Configuration & Integration Details

### Nginx Template Forwarding (`infra/nginx/templates/default.conf.template`)

```nginx
server {
    listen 80;
    listen [::]:80;
    server_name ${NGINX_SERVER_NAME};

    # Redirect all HTTP requests to HTTPS
    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${NGINX_SERVER_NAME};

    # SSL Certificate configuration
    ssl_certificate /etc/nginx/ssl/live/server.crt;
    ssl_certificate_key /etc/nginx/ssl/live/server.key;

    # SSL Protocol & Optimization Tuning
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    # Security Headers
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    location / {
        proxy_pass http://api:8000;
        proxy_http_version 1.1;

        # Forward crucial client headers for proxy trust validation
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Support WebSocket upgrade headers
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Port $server_port;
        proxy_set_header Connection 'upgrade';
        proxy_cache_bypass $http_upgrade;
    }
}
```

### Express Integration (`src/api/index.ts`)

```ts
if (config.TRUST_PROXY === 'true') {
  app.set('trust proxy', true);
} else if (config.TRUST_PROXY === 'false') {
  app.set('trust proxy', false);
} else if (config.TRUST_PROXY) {
  const hops = Number(config.TRUST_PROXY);
  app.set('trust proxy', Number.isNaN(hops) ? config.TRUST_PROXY : hops);
}
```

### Lockout Utilities (`src/core/common/utils/metadata.ts`)

```ts
export const checkLoginLockout = async (email: string): Promise<void> => {
  const normalizedEmail = email.trim().toLowerCase();
  const lockoutKey = `lockout:${normalizedEmail}`;

  const isLocked = await getCache(lockoutKey);
  if (isLocked) {
    throw new BadRequestException(
      'Too many failed login attempts. This account is temporarily locked. Please try again later.'
    );
  }
};

export const incrementLoginFailedAttempts = async (email: string): Promise<void> => {
  const normalizedEmail = email.trim().toLowerCase();
  const lockoutKey = `lockout:${normalizedEmail}`;
  const attemptsKey = `failed_attempts:${normalizedEmail}`;

  const attempts = await incrementCache(attemptsKey, RATE_LIMIT.AUTH.WINDOW_MS / 1000);
  if (attempts >= RATE_LIMIT.AUTH.MAX_REQUESTS) {
    await setCache(lockoutKey, 'true', RATE_LIMIT.AUTH.WINDOW_MS / 1000);
    await deleteCache(attemptsKey);
  }
};

export const clearLoginLockout = async (email: string): Promise<void> => {
  const normalizedEmail = email.trim().toLowerCase();
  const lockoutKey = `lockout:${normalizedEmail}`;
  const attemptsKey = `failed_attempts:${normalizedEmail}`;

  await deleteCache(lockoutKey);
  await deleteCache(attemptsKey);
};
```
