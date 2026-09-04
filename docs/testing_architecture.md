# AuthKit Testing Architecture & Deployment Workflows

This document describes the design, technical implementation, directory structure, and operational workflows for AuthKit's production-grade automated testing suite and deployment environments.

---

## 1. Testing Stack & Core Technologies

The test suite is built on top of a zero-dependency, 100% in-memory testing stack:

- **Vitest**: A fast, Next-Gen test runner featuring native ESModules support, TypeScript out-of-the-box, and concurrent execution.
- **Supertest**: Used to perform HTTP assertions on Express endpoints without spinning up active network port listeners.
- **In-Memory Prisma Mock (`tests/mocks/prisma.ts`)**: Modular JS `Map` backing store simulating `user`, `session`, `account`, `oidcClient`, and `auditLog` models with relation population (`user.accounts`, `session.user`), in-place record mutations, and `$transaction` support.
- **Polyfilled `ioredis-mock` (`tests/mocks/redis.ts`)**: Simulates Redis in-memory storage with custom command polyfills (`SCRIPT LOAD`, `EVALSHA`, `EVAL`) for full compatibility with `rate-limit-redis`.
- **Test Execution Reporter (`tests/helpers/test-logger.reporter.ts`)**: Custom Vitest reporter that redirects verbose logs to `logs/%DATE%-tests.log`, keeping terminal output clean.

---

## 2. The Three-Layer Testing Strategy

Our strategy partitions tests into three logical layers executed 100% in-memory out-of-the-box without requiring Docker Desktop, PostgreSQL, or Redis servers:

```
┌─────────────────────────────────────────────────────────┐
│              Layer 3: End-to-End (E2E)                  │ ──> Complete multi-step customer journeys
├─────────────────────────────────────────────────────────┤
│              Layer 2: Integration                       │ ──> Middleware, router validations, RBAC, CSRF
├─────────────────────────────────────────────────────────┤
│              Layer 1: Unit Tests                        │ ──> Service class business logic in-memory
└─────────────────────────────────────────────────────────┘
```

### Layer 1: Unit Tests (`tests/unit/`)

- **Scope**: Focuses on business logic in service classes (`UserService`, `AuthService`, `MfaService`, `OidcService`, `OAuthService`, `SessionService`, `MagicLinkService`, `HealthService`, `AuditService`).
- **Isolation**: High. Executed in-memory using modular Prisma and Redis mocks.
- **Pre-commit**: Executed on every git commit via Husky hooks.

### Layer 2: Integration Tests (`tests/integration/`)

- **Scope**: Verifies Express middlewares (CORS, CSRF double-submit tokens, role authorization, rate-limiters, and error sanitizers) and router inputs schema validation.
- **Isolation**: Medium. Runs against Express router layers backed by in-memory Prisma and Redis mocks.

### Layer 3: End-to-End Tests (`tests/e2e/`)

- **Scope**: Validates complete user-facing workflows from start to finish.
- **Covered Journeys**:
  1. _Local Credentials_: Register $\rightarrow$ verify email $\rightarrow$ login $\rightarrow$ query profile $\rightarrow$ rotate token $\rightarrow$ logout.
  2. _Magic Link_: Request login link $\rightarrow$ fetch cache token $\rightarrow$ execute verify redirection.
  3. _MFA Lifecycle_: Password auth $\rightarrow$ enroll TOTP $\rightarrow$ verify TOTP $\rightarrow$ check login challenge $\rightarrow$ use backup code recovery $\rightarrow$ disable MFA.
  4. _OIDC Pipeline_: Register OIDC client $\rightarrow$ authorize PKCE $\rightarrow$ session bridge login $\rightarrow$ consent redirection $\rightarrow$ token exchange $\rightarrow$ UserInfo fetch $\rightarrow$ Introspection $\rightarrow$ Revocation.
  5. _Password Reset & Account Lockout_: Forgot password OTP $\rightarrow$ verify OTP $\rightarrow$ reset password with token $\rightarrow$ verify old password rejection $\rightarrow$ 5 invalid attempts account lockout.
  6. _Admin Management & Audit Observability_: Admin user query $\rightarrow$ role promotion (USER $\rightarrow$ ADMIN) $\rightarrow$ target session revocation $\rightarrow$ audit log listing & detail query $\rightarrow$ RBAC 403 access control checks.

---

## 3. Directory Structure

```
tests/
├── e2e/                      # Layer 3: E2E User Journeys
│   ├── admin-journeys.test.ts
│   ├── auth-journeys.test.ts
│   └── oidc-journeys.test.ts
├── integration/              # Layer 2: Middleware & Endpoint Integrations
│   ├── auth-endpoints.test.ts
│   └── middleware.test.ts
├── unit/                     # Layer 1: Service Unit Tests
│   ├── admin.service.test.ts
│   ├── audit.service.test.ts
│   ├── auth.service.test.ts
│   ├── health.service.test.ts
│   ├── magic-link.service.test.ts
│   ├── oauth.service.test.ts
│   ├── oidc.service.test.ts
│   ├── session.service.test.ts
│   └── user.service.test.ts
├── factories/                # Data factories for generating test entities
│   ├── oidc-client.factory.ts
│   ├── session.factory.ts
│   └── user.factory.ts
├── fixtures/                 # Static data fixtures
│   └── auth.fixture.ts
├── helpers/                  # Container, DB, Redis, and Request helpers
│   ├── container.helper.ts
│   ├── db.helper.ts
│   ├── redis.helper.ts
│   ├── request.helper.ts
│   └── test-logger.reporter.ts
└── mocks/                    # Dedicated in-memory mock client modules
    ├── prisma.ts             # In-memory Prisma store & $transaction factory
    ├── redis.ts              # Polyfilled ioredis-mock factory
    └── resend.ts             # Resend email mailer spy
```

---

## 4. Environment Workflows & Configuration

This section explains how to configure, run, and test AuthKit across different deployment environments:

1. **Local Development** (No Docker, No Nginx)
2. **Docker Development** (Docker containers with direct port exposure, No Nginx)
3. **Docker Production** (Docker containers behind Nginx reverse proxy)

### Environment Variable Reference

Configure these variables inside your `.env` file for each specific environment:

| Variable            | Description                                                                                                                        | Recommended (Local Dev) | Recommended (Production / Nginx) |
| :------------------ | :--------------------------------------------------------------------------------------------------------------------------------- | :---------------------- | :------------------------------- |
| `TRUST_PROXY`       | Determines if Express trusts incoming header chains (like `X-Forwarded-For`). Can be `true`, `false`, or a numeric number of hops. | `false`                 | `1` (or `true`)                  |
| `NGINX_SERVER_NAME` | The hostname Nginx checks for incoming connections (`server_name`). _Not used by backend application code._                        | `localhost`             | `authkit.yourdomain.com`         |
| `REDIS_PASSWORD`    | The password used by the backend client to authenticate with the Redis server.                                                     | `dev_redis_secure_pass` | `your_secure_prod_password`      |
| `REDIS_TLS`         | Controls whether transport layer security (TLS) is used for the Redis client connection (`true` / `false`).                        | `false`                 | `true` (if network requires it)  |

---

### 4.1. Local Development Workflow (No Docker, No Nginx)

In this setup, the API runs directly on your local operating system (e.g. via `pnpm dev`), communicating with local PostgreSQL and Redis servers.

```
[ Client / Postman / Swagger ] ──── (Port 8000) ────> [ Express API ]
```

#### 4.1.1 Configuration (`.env`)

```ini
PORT=8000
NODE_ENV=development
TRUST_PROXY="false"
NGINX_SERVER_NAME="localhost"
```

#### 4.1.2 Accessing Endpoints

- **API Base Url**: `http://localhost:8000/api/v1`
- **Swagger Documentation**: `http://localhost:8000/docs` (Fully functional out-of-the-box)
- **cURL Example**:
  ```bash
  curl -X POST http://localhost:8000/api/v1/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"test@example.com","password":"yourpassword"}'
  ```

#### 4.1.3 Email & Token Verification (Local Mailer)

- **Behavior**: Outbound emails are **not** sent via the Resend API when `NODE_ENV !== 'production'`.
- **Retrieval**: The mailer writes styled HTML email files to the host filesystem under the local **`logs/emails/`** directory (e.g. `logs/emails/test@example.com-verify_your_email_address.html`).
- **Testing**: Open the HTML file in your browser to copy OTP codes, click magic links, or verify email layouts. A valid `RESEND_API_KEY` is not required.

#### 4.1.4 IP & Header Validation Behavior

- **Behavior**: Express ignores any incoming proxy headers like `X-Forwarded-For`.
- **Client IP**: The resolved client IP will be the raw socket address (`::1` or `127.0.0.1`).
- **Security**: IP or header spoofing has no effect, ensuring local rate-limiters are secure.

#### 4.1.5 Redis & Database Access

- **Database**: Connect directly to PostgreSQL on your local host (usually port `5432`).
- **Redis**: Connect directly to Redis on `localhost:6379`.

---

### 4.2. Docker Development Workflow (With Docker, No Nginx)

In this environment, you run the database, caching services, and API inside Docker containers. The API container exposes its port (`8000`) directly to the host machine.

```
[ Client / Postman / Swagger ] ──── (Port 8000) ────> [ Docker API Container ]
```

#### 4.2.1 Configuration (`.env`)

Ensure `docker-compose` maps the API port (e.g., `ports: - '8000:8000'`).

```ini
PORT=8000
NODE_ENV=development
TRUST_PROXY="false"
NGINX_SERVER_NAME="localhost"
```

#### 4.2.2 Accessing Endpoints

- **API Base Url**: `http://localhost:8000/api/v1`
- **Swagger Documentation**: `http://localhost:8000/docs`
- **cURL Example**: Same as Local Development.

#### 4.2.3 Email & Token Verification (Local Mailer)

- **Behavior**: Outbound emails are **not** sent via the Resend API when `NODE_ENV !== 'production'`.
- **Retrieval**: The mailer writes HTML emails inside the container under `/app/logs/emails/`.
- **Mounting**: Ensure your development `docker-compose` volume mounts `./logs:/app/logs` (host to container mapping). This lets you see and open the generated HTML files in the local `logs/emails/` folder on your host machine.
- **Testing**: Open the host's mapping folder to check the OTP/magic-link links.

#### 4.2.4 IP & Header Validation Behavior

- **Behavior**: Since there is no reverse proxy container intercepting requests, Express reads incoming client socket connections directly.
- **Security**: `TRUST_PROXY` must remain `"false"`. If set to `"true"` without an Nginx gateway, an attacker could spoof `X-Forwarded-For` headers directly.

#### 4.2.5 Redis & Database Access (Loopback Binding)

- **Database**: PostgreSQL container runs on the internal bridge network and maps port `5432` to host.
- **Redis Server**: Bound to the host loopback interface, accessible locally at `127.0.0.1:6379`.
- **Redis Insight UI**: Accessible on your local browser at `http://127.0.0.1:8001` or `http://localhost:8001`.
- **Authentication**: When connecting, you must supply the password configured in `REDIS_PASSWORD` (e.g. `dev_redis_secure_pass`).

---

### 4.3. Docker Production Workflow (With Nginx Gateway)

This is the standard production layout. The API container is isolated (no host port exposure) and can only be reached through the **Nginx reverse proxy container**, which maps host port `80` (and `443` for TLS).

```
[ Client / Postman / Swagger ] ─── (Port 80) ───> [ Nginx Container ] ─── (Internal Port 8000) ───> [ API Container ]
```

#### 4.3.1 Configuration (`.env`)

```ini
PORT=8000
NODE_ENV=production
TRUST_PROXY="1"                  # Trusts Nginx as the single upstream proxy hop
NGINX_SERVER_NAME="localhost"    # Or your production domain, e.g. authkit.yourdomain.com
```

#### 4.3.2 Accessing Endpoints (HTTP/2 & TLS/SSL)

_The Nginx gateway automatically redirects all plaintext HTTP traffic (port 80) to secure HTTPS (port 443) using HTTP/2 multiplexing._

- **API Base Url**: `https://localhost/api/v1` (or `https://authkit.yourdomain.com/api/v1`)
- **Swagger Documentation**: `https://localhost/docs` (or `https://authkit.yourdomain.com/docs`)

##### Handling Self-Signed Certificate Warnings in Development/Testing:

Because the production compose environment automatically generates temporary self-signed SSL/TLS certificates at boot (via the `nginx-init` helper container), you will encounter SSL trust warnings:

1. **In Web Browser**: Access `https://localhost/docs` or `https://localhost/api/v1/health` and click **"Advanced" -> "Proceed to localhost (unsafe)"** to allow the browser to establish the secure handshake.
2. **In Postman**: Go to **Settings -> General** and disable **"SSL certificate verification"**.
3. **In cURL**: Pass the `-k` or `--insecure` flag to bypass certificate authority validation:
   ```bash
   curl -k -L https://localhost/api/v1/health
   ```
   _(The `-L` flag is recommended to follow any redirects from HTTP to HTTPS automatically)._

##### cURL Login Example:

```bash
curl -k -L -X POST https://localhost/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"yourpassword"}'
```

#### 4.3.3 Email & Token Verification (Real Mailer)

- **Behavior**: Outbound emails are sent in real time to the user's inbox.
- **Integration**: The Resend API is active and requires a valid `RESEND_API_KEY` and verified domain in your `.env`.
- **Testing**: Check the real target inbox for verification links and OTPs.

#### 4.3.4 IP & Header Validation Behavior

- **Behavior**: Nginx intercepts all client calls, strips client-supplied `X-Forwarded-For` headers, and creates a secure header chain with the true TCP source IP (`X-Real-IP`).
- **Security**: Express trusts this single hop (`TRUST_PROXY="1"`) and extracts the client IP safely from `req.ip` without risking IP spoofing.

#### 4.3.5 Redis & Database Access (Isolated Setup)

- **Database**: PostgreSQL container is fully isolated and only accessible to backend containers inside the private bridge network.
- **Redis Server**: Maps no ports to the host machine (not even loopback), restricting connection paths to within the internal network.
- **Authentication**: The API container resolves and communicates with Redis internally using the credentials configured via `REDIS_PASSWORD`.

---

## 5. Automated Testing and CI/CD Pipeline

AuthKit implements a comprehensive automated testing execution harness mapping to these environments.

### 5.1 CLI Commands & Test Execution Options

Ensure you have run `pnpm install` first.

```bash
# Run all tests (Unit, Integration, E2E)
pnpm test

# Run Layer 1: Unit Tests
pnpm test:unit

# Run Layer 2: Integration Tests
pnpm test:integration

# Run Layer 3: E2E User Journeys
pnpm test:e2e

# Run tests in watch mode
pnpm test:watch

# Run tests with HTML coverage reports
pnpm test:coverage
```

### 5.2 Local & Husky Pre-commit Hooks

Before any commit is recorded, Husky runs staged linting and **Layer 1 Unit Tests** in memory (`pnpm test:unit`). This keeps execution extremely fast and eliminates local development friction.

### 5.3 GitHub Actions CI Quality Gate

On every pull request or merge to `dev` or `main`, GitHub Actions automatically executes `.github/workflows/ci.yml`:

1. Installs Node.js 20 & pnpm dependencies with frozen lockfile caching.
2. Runs Code Linter (`pnpm lint`) and TypeScript Type Checker (`pnpm type-check`).
3. Executes the full 100% in-memory Test Suite (`pnpm test`) with coverage reporting.
   This guarantees that any changes going to staging or production are fully verified against protocol compliance and security regressions before deployment.
