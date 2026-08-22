# AuthKit: Identity Provider (IdP) & IAM Infrastructure

<img src="https://img.shields.io/badge/TypeScript-3178C6?style=for-the-badge&logo=typescript&logoColor=white" /> <img src="https://img.shields.io/badge/Node.js-339933?style=for-the-badge&logo=node.js&logoColor=white" /> <img src="https://img.shields.io/badge/Express.js-000000?style=for-the-badge&logo=express&logoColor=white" />
<img src="https://img.shields.io/badge/Prisma-2D3748?style=for-the-badge&logo=prisma&logoColor=white" /> <img src="https://img.shields.io/badge/PostgreSQL-4169E1?style=for-the-badge&logo=postgresql&logoColor=white" /> <img src="https://img.shields.io/badge/Nginx-009639?style=for-the-badge&logo=nginx&logoColor=white" /> <img src="https://img.shields.io/badge/Redis-DC382D?style=for-the-badge&logo=redis&logoColor=white" /> <img src="https://img.shields.io/badge/Swagger-85EA2D?style=for-the-badge&logo=swagger&logoColor=black" /> <img src="https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white" />

## 1. Project Abstract

AuthKit is a production-grade **Identity Provider (IdP)** and **Identity & Access Management (IAM)** microservice. Engineered with a focus on cryptographic integrity and protocol compliance, it facilitates centralized authentication via **OpenID Connect (OIDC) 1.0** and **OAuth 2.0**. The platform abstracts complex security handshakes—including PKCE-enforced authorization flows, multi-factor verification (MFA), and stateless session orchestration—enabling rapid deployment of secure, scalable service ecosystems.

---

## Table of Contents

- [1. Project Abstract](#1-project-abstract)
- [2. Technology Stack](#2-technology-stack)
- [3. Developer Setup](#3-developer-setup)
- [4. Automated Testing Suite & Quality Gates](#4-automated-testing-suite--quality-gates)
  - [4.1 Automated Test Runners & CLI Commands](#41-automated-test-runners--cli-commands)
  - [4.2 Postman Collection & Manual Testing Specifications](#42-postman-collection--manual-testing-specifications)
- [5. Core Architecture & Security Infrastructure](#5-core-architecture--security-infrastructure)
- [6. OIDC Identity Provider (IdP) Implementation](#6-oidc-identity-provider-idp-implementation)
- [7. API Inventory & Endpoint Specifications](#7-api-inventory--endpoint-specifications)
- [8. Comprehensive Security, Performance & Feature Audit (July 2026)](#8-comprehensive-security-performance--feature-audit-july-2026)

---

## 2. Technology Stack

- **Language**: TypeScript (Node.js LTS)
- **Framework**: Express.js
- **Persistence**: PostgreSQL orchestrated via Prisma ORM
- **State Store**: High-concurrency Redis instances (OIDC State & Session Caching)
- **Validation**: Zod (Runtime Type Verification)
- **Documentation**: OpenAPI 3.0 / Swagger UI (Dev & Staging) & Postman Collection
- **Orchestration**: Docker & Docker Compose
- **Email Delivery**: Resend
- **Cryptography**: Bcrypt (Hashing), Speakeasy (MFA/TOTP), RSA-256 (JWT/JWKS)

---

## 3. Developer Setup

### 3.1 Containerized Orchestration (Docker)

**Prerequisites**: Docker & Docker Compose

1. **Clone Repository**:

   ```bash
   git clone https://github.com/AmanKrSahu/authkit.git
   ```

2. **Initialize the Environment Variables**:

   ```bash
   cp .env.example .env
   ```

3. **Generate secure tokens and JWKs**:

   ```bash
   # Populate .env with cryptographic primitives from generated-secrets.json
   pnpm generate:secrets
   ```

4. **Build and Run the Containers**:

   ```bash
   docker-compose -f docker-compose.dev.yml up --build -d
   ```

### 3.2 Native Runtime Environment (Local)

**Prerequisites**: Node.js (LTS), pnpm, PostgreSQL, Redis

1. **Dependency Resolution**:

   ```bash
   pnpm install
   ```

2. **Initialize the Environment Variables**:

   ```bash
   cp .env.example .env
   ```

3. **Generate secure tokens and JWKs**:

   ```bash
   # Populate .env with cryptographic primitives from generated-secrets.json
   pnpm generate:secrets
   ```

4. **Schema Migration & Seeding**:

   ```bash
   pnpm db:generate
   pnpm db:push
   # Optional: pnpm db:seed
   ```

5. **Run the Server**:

   ```bash
   pnpm dev
   ```

### 3.3 Access Vectors

Depending on your configured environment (direct execution vs. behind Nginx reverse proxy):

- **Local Dev API Base**: `http://localhost:8000/api/v1/`
- **Swagger Documentation Portal (Dev/Staging)**: `http://localhost:8000/docs`
- **Production Gateway API (behind Nginx)**: `https://localhost/api/v1/` (or `https://authkit.yourdomain.com/api/v1/`)

👉 Full testing guide: [**Testing Architecture & Deployment Workflows**](./docs/testing_architecture.md)

---

## 4. Automated Testing Suite & Quality Gates

AuthKit includes a production-grade, three-layer automated testing suite designed using **Vitest**, **Supertest**, and modular in-memory data store mocks ([`tests/mocks/prisma.ts`](./tests/mocks/prisma.ts) and [`tests/mocks/redis.ts`](./tests/mocks/redis.ts)), executing **100% in-memory** out-of-the-box with zero external database dependencies. It is supplemented by a Postman collection for manual verification.

For a detailed breakdown of the testing layout, coverage metrics, service mock setups, environment workflows, and execution paths, please refer to the [**Testing Architecture Documentation**](./docs/testing_architecture.md).

### 4.1 Automated Test Runners & CLI Commands

```bash
# Run all tests (Unit, Integration, E2E)
pnpm test

# Run fast, in-memory Unit Tests
pnpm test:unit

# Run Integration Tests (Middlewares & Endpoints)
pnpm test:integration

# Run End-to-End User Journeys (OIDC, Credentials, MFA, Magic Link, Admin)
pnpm test:e2e

# Run tests in watch mode
pnpm test:watch

# Run tests with HTML coverage reports
pnpm test:coverage
```

### 4.2 Postman Collection & Manual Testing Specifications

To facilitate manual testing, production verification, and client integration independent of the automated test harness, AuthKit provides an exhaustive, pre-configured **Postman Collection** and **OpenAPI 3.0 Specification** inside the dedicated [`docs/api-specs/`](./docs/api-specs/) directory.

#### Postman Collection (`docs/api-specs/AuthKit.postman_collection.json`)

The collection is structured logically into workflow folders matching realistic customer journeys and edge cases:

1. `01. Service Health & Diagnostics` (Base Status, Basic Health, Detailed System Diagnostics)
2. `02. Authentication & Account Lifecycle` (Register, Verification, Login, Token Rotation, Logout, Lockouts, Forgot/Reset/Change Password)
3. `03. Passwordless (Magic Link)` (Request Magic Link, Verify Magic Link Token)
4. `04. Multi-Factor Authentication (MFA)` (TOTP Setup, Verify Setup, Login Challenge, Backup Code Recovery, Revoke MFA)
5. `05. Social Authentication (OAuth 2.0)` (Google OAuth Redirect & Callback Handling)
6. `06. User Profile Management` (Get Authenticated User Profile)
7. `07. Session Management` (List Active Sessions Paginated, Session Details, Revoke Session by ID, Revoke All Other Sessions)
8. `08. Admin Controls & Role Management` (Role Promotion, Query System Users, Delete User, Manage Target User Sessions, Register OIDC Clients)
9. `09. OpenID Connect (OIDC 1.0) Provider Protocols` (Discovery, JWKS Keys, Authorization Code PKCE, Token Exchange, UserInfo, Introspection, Revocation)
10. `10. OIDC Custom Interaction Flows` (Interaction Prompt Details, Session Bridge Check, Submit Login/MFA/Consent, Abort Interaction)

**Features**:

- Pre-configured environment variables (`{{baseUrl}}`, `{{accessToken}}`, `{{refreshToken}}`, `{{csrfToken}}`, `{{oidcClientId}}`, `{{oidcClientSecret}}`).
- Built-in test scripts that automatically capture and set `accessToken`, `refreshToken`, and `csrfToken` into collection variables upon login.
- Includes both standard happy paths and defensive edge cases (e.g. invalid tokens, rate limit triggers, unauthorized role attempts).

👉 Direct Links: [**Postman Collection**](./docs/api-specs/AuthKit.postman_collection.json) | [**OpenAPI Specification**](./docs/api-specs/openapi.json)

---

## 5. Core Architecture & Security Infrastructure

**Systemic Architecture**:
The infrastructure adheres to a **Modular Layered Architecture (MLA)** utilizing the Controller-Service-Repository pattern. This ensures deterministic separation of concerns, facilitating high maintainability and vertical scalability. Core business logic is encapsulated within feature-isolated modules (Auth, Identity, Session Management).

**Cryptographic & Protocol Security**:

- **Bearer Tokenization**: Short-lived JWTs (Access Tokens) issued via RSA-256 signing.
- **Refresh Token Rotation (RTR)**: Cryptographically linked rotation cycles to mitigate replay attacks.
- **MFA (Multi-Factor Authentication)**: TOTP implementation via speakeasy for secondary verification.
- **Atomic Session Management**: Redis-backed session lifecycle with real-time revocation capabilities.
- **Data Integrity**: Bcrypt-hashed credentials and deterministic redirection whitelisting.
- **Defensive Middleware**: Global rate-limiting, Helmet-enforced security headers, and CORS strictness.
- **Account Enumeration Prevention**: Enforces uniform, indistinguishable success responses across forgot-password, resend-verification, and magic-link login routes, preventing user registration probing.
- **Per-Account Lockout**: Redis-backed account lockout (5 failed attempts within 15 minutes locks the account for 15 minutes) preventing distributed brute-force guess attempts.
- **Ingress Gateway Isolation**: Routing production traffic through an Nginx proxy container to isolate backend sockets.
- **Dynamic Proxy Trust**: Custom, environment-validated `TRUST_PROXY` Express configuration.
- **Enhanced Ingress Rate-Limiting**: Enforces strict route-level rate limiting across login, register, magic-link, and MFA endpoints, plus user-bound attempt budgets to prevent distributed bypasses.
- **Hardened Caching Layer**: Implements full Redis password authentication, production TLS transport options, loopback port containment, and AES-256-GCM encryption of cached TOTP setup secrets.
- **Scale-Resilient Cursor Pagination**: Employs an index-optimized cursor pager for session and user collections, preventing memory bloat and duplicate entries under real-time mutations. It concurrently calculates total record sets and populates CORS-exposed metadata headers (`X-Total-Count` / `X-Page-Count`).

👉 Full Documentation: [**Detailed Security Architecture**](./docs/security_architecture.md)

### 5.1 Architectural Design Decisions Registry

To track and audit architectural decisions, we maintain a registry of design logs detailing critical security solutions:

| Design Decision Record                                                                                         | Technical & Functional Description                                                                        | Context / Origin                                                              |
| :------------------------------------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------------------- | :---------------------------------------------------------------------------- |
| [**Unified Origin Validator**](./docs/design-decisions/audit-2026-07-20/unified-origin-validator.md)           | Unifies CORS, CSRF, and redirect whitelisting logic to block subdomain suffix spoofing and enforce HTTPS. | **July 2026 Security Audit** (Task [SEC-H1](./docs/audit/2026-07-20/task.md)) |
| [**Client IP & Lockout Security**](./docs/design-decisions/audit-2026-07-20/client-ip-and-lockout-security.md) | Formulates the Nginx reverse-proxy ingress, proxy header filtering, and Redis-backed login lockouts.      | **July 2026 Security Audit** (Task [SEC-H3](./docs/audit/2026-07-20/task.md)) |
| [**Cursor-Based Pagination**](./docs/design-decisions/audit-2026-07-20/cursor-based-pagination.md)             | Implements high-performance cursor pagination using take+1 slices, securing listing routes under scale.   | **July 2026 Security Audit** (Task [M-1](./docs/audit/2026-07-20/task.md))    |

---

## 6. OIDC Identity Provider (IdP) Implementation

AuthKit functions as a centralized IdP, supporting dynamic client registration and multi-phase authorization handshakes. The implementation conforms to strict **OpenID Connect 1.0** specifications.

> [!IMPORTANT]
> For an exhaustive technical breakdown of the OIDC handshake, token introspection, and dynamic client provisioning, refer to the [OIDC Implementation Guide](./docs/oidc_implementation.md). This documentation details the **PKCE verification**, **7-stage interaction handshake**, and **Discovery protocol (RFC 8414)**.

---

## 7. API Inventory & Endpoint Specifications

| Domain             | Functional Scope            | Protocol / Logic       | Details                                               |
| :----------------- | :-------------------------- | :--------------------- | :---------------------------------------------------- |
| **Identity (IdP)** | Auth, Token, JWKS, UserInfo | OIDC 1.0 / OAuth 2.0   | Centralized SSO & Third-party provisioning            |
| **Auth**           | Registration, Login, Logout | Password-based Auth    | Secure credential handling & session initiation       |
| **MFA**            | TOTP Setup & Verification   | RFC 6238 (speakeasy)   | Multi-factor secondary verification layer             |
| **OAuth**          | Google Social Integration   | OAuth 2.0 Protocol     | Third-party identity federation                       |
| **Magic Link**     | Passwordless Auth           | Token-based / SMTP     | Email-verified session provisioning                   |
| **User/Session**   | Profile & Active State Mgmt | REST / Redis-backed    | Real-time session tracking & profile modification     |
| **Admin**          | Moderation & Client Ops     | Restricted REST / RBAC | User lifecycle moderation & Client Registration       |
| **Audit Logs**     | Compliance & Observability  | SOC2 / NIST SP 800-92  | Append-only security audit trail & filterable queries |
| **System**         | Health & Dependency Checks  | Heartbeat Logic        | Multi-component dependency status monitoring          |
| **Metadata**       | Discovery, Key Exposition   | RFC 8414               | Automated client configuration (Well-known)           |

Comprehensive specifications including request/response schemas are accessible via the Swagger portal (in Dev/Staging) or via the [**Postman Collection**](./docs/api-specs/AuthKit.postman_collection.json).

👉 Full Documentation: [**API Endpoints Documentation**](./docs/api_endpoints.md)

---

## 8. Comprehensive Security, Performance & Feature Audit (July 2026)

To elevate **AuthKit** from a robust side-project showcase to a **production-ready, enterprise-grade Identity Provider (IdP)** meeting global standards, a thorough engineering audit was performed. This audit systematically analyzed the codebase for cryptographic rigor, protocol compliance, bottleneck optimization, and enterprise scalability.

All findings, remediations, and strategic feature additions have been structured into a master roadmap designed to prevent regressions and secure the platform's core trust base.

### 8.1 Audit Artifacts & Findings

The audit is broken down into specialized focus areas. You can review the exhaustive reports here:

- [**Master Task Plan & Execution Roadmap (`task.md`)**](./docs/audit/2026-07-20/task.md) — The central steering document outlining sequencing, complexity, and priority.
- [**Security Audit Report (`security-audit.md`)**](./docs/audit/2026-07-20/security-audit.md) — Exhaustive analysis of threat vectors, session caching vulnerabilities, and sanitization leaks.
- [**Performance & Scalability Audit (`performance.md`)**](./docs/audit/2026-07-20/performance.md) — Profiling query paths, database connection pooling, and latency-heavy transactions.
- [**Enterprise Feature Recommendations (`feature-recommendations.md`)**](./docs/audit/2026-07-20/feature-recommendations.md) — Functional specifications for B2B multi-tenancy, passkeys, webhooks, and audit trails.
- [**Supplementary Findings (`supplementary-findings.md`)**](./docs/audit/2026-07-20/supplementary-findings.md) — Additional architectural findings and recommendations discovered during the planning phase of the July 2026 security audit (specifically addressing proxy trust dynamics, header verification, and reverse-proxy deployments).

For details on individual ticket tracking, metrics, and exit criteria, refer directly to the [**Master Execution Roadmap (`task.md`)**](./docs/audit/2026-07-20/task.md).

---

## 📬 Contact

Found a bug, have a feature request, or want to contribute? Feel free to open an issue, start a discussion, or connect with me.

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/amankrsahu)
[![Discord](https://img.shields.io/badge/Discord-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discordapp.com/users/539751578866024479)
