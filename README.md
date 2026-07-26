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
- [4. Core Architecture & Security Infrastructure](#4-core-architecture--security-infrastructure)
- [5. OIDC Identity Provider (IdP) Implementation](#5-oidc-identity-provider-idp-implementation)
- [6. API Inventory & Endpoint Specifications](#6-api-inventory--endpoint-specifications)
- [7. Comprehensive Security, Performance & Feature Audit (July 2026)](#7-comprehensive-security-performance--feature-audit-july-2026)

---

## 2. Technology Stack

- **Language**: TypeScript (Node.js LTS)
- **Framework**: Express.js
- **Persistence**: PostgreSQL orchestrated via Prisma ORM
- **State Store**: High-concurrency Redis instances (OIDC State & Session Caching)
- **Validation**: Zod (Runtime Type Verification)
- **Documentation**: Swagger / OpenAPI 3.0
- **Orchestration**: Docker & Docker Compose
- **Email Delivery**: Resend
- **Cryptography**: Bcrypt (Hashing), Speakeasy (MFA/TOTP), RSA-256 (JWT/JWKS)

---

## 3. Developer Setup

### 3.1 Containerized Orchestration (Docker)

**Prerequisites**: Docker & Docker Compose

1.  **Clone Repository**:

    ```bash
    git clone https://github.com/AmanKrSahu/authkit.git
    ```

2.  **Initialize the Environment Variables**:

    ```bash
    cp .env.example .env
    ```

3.  **Generate secure tokens and JWKs**:

    ```bash
    # Populate .env with cryptographic primitives from generated-secrets.json
    pnpm generate:secrets
    ```

4.  **Build and Run the Containers**:

    ```bash
    docker-compose -f docker-compose.dev.yml up --build -d
    ```

### 3.2 Native Runtime Environment (Local)

**Prerequisites**: Node.js (LTS), pnpm, PostgreSQL, Redis

1.  **Dependency Resolution**:

    ```bash
    pnpm install
    ```

2.  **Initialize the Environment Variables**:

    ```bash
    cp .env.example .env
    ```

3.  **Generate secure tokens and JWKs**:

    ```bash
    # Populate .env with cryptographic primitives from generated-secrets.json
    pnpm generate:secrets
    ```

4.  **Schema Migration & Seeding**:

    ```bash
    pnpm db:generate
    pnpm db:push
    # Optional: pnpm db:seed
    ```

5.  **Run the Server**:

    ```bash
    pnpm dev
    ```

### 3.3 Access Vectors

Depending on your configured environment (direct execution vs. behind Nginx):

- **Local Dev API**: `http://localhost:8000/api/v1/`
- **Local Dev Swagger Portal**: `http://localhost:8000/docs`
- **Production API (behind Nginx)**: `http://localhost/api/v1/`
- **Production Swagger Portal (behind Nginx)**: `http://localhost/docs`

👉 Full testing guide: [**Testing & Deployment Workflows**](./docs/testing-workflows.md)

---

## 4. Core Architecture & Security Infrastructure

**Systemic Architecture**:
The infrastructure adheres to a **Modular Layered Architecture (MLA)** utilizing the Controller-Service-Repository pattern. This ensures deterministic separation of concerns, facilitating high maintainability and vertical scalability. Core business logic is encapsulated within feature-isolated modules (Auth, Identity, Session Management).

**Cryptographic & Protocol Security**:

- **Bearer Tokenization**: Short-lived JWTs (Access Tokens) issued via RSA-256 signing.
- **Refresh Token Rotation (RTR)**: Cryptographically linked rotation cycles to mitigate replay attacks.
- **MFA (Multi-Factor Authentication)**: TOTP implementation via speakeasy for secondary verification.
- **Atomic Session Management**: Redis-backed session lifecycle with real-time revocation capabilities.
- **Data Integrity**: Bcrypt-hashed credentials and deterministic redirection whitelisting.
- **Defensive Middleware**: Global rate-limiting, Helmet-enforced security headers, and CORS strictness.
- **Per-Account Lockout**: Redis-backed account lockout (5 failed attempts within 15 minutes locks the account for 15 minutes) preventing distributed brute-force guess attempts.
- **Ingress Gateway Isolation**: Routing production traffic through an Nginx proxy container to isolate backend sockets.
- **Dynamic Proxy Trust**: Custom, environment-validated `TRUST_PROXY` Express configuration.
- **Enhanced Ingress Rate-Limiting**: Enforces strict route-level rate limiting across login, register, magic-link, and MFA endpoints, plus user-bound attempt budgets to prevent distributed bypasses.
- **Hardened Caching Layer**: Implements full Redis password authentication, production TLS transport options, loopback port containment, and AES-256-GCM encryption of cached TOTP setup secrets.

👉 Full Documentation: [**Detailed Security Architecture**](./docs/security_architecture.md)

### 4.1 Architectural Design Decisions Registry

To track and audit architectural decisions, we maintain a registry of design logs detailing critical security solutions:

| Design Decision Record                                                                                         | Technical & Functional Description                                                                        | Context / Origin                                                              |
| :------------------------------------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------------------- | :---------------------------------------------------------------------------- |
| [**Unified Origin Validator**](./docs/design-decisions/audit-2026-07-20/unified-origin-validator.md)           | Unifies CORS, CSRF, and redirect whitelisting logic to block subdomain suffix spoofing and enforce HTTPS. | **July 2026 Security Audit** (Task [SEC-H1](./docs/audit/2026-07-20/task.md)) |
| [**Client IP & Lockout Security**](./docs/design-decisions/audit-2026-07-20/client-ip-and-lockout-security.md) | Formulates the Nginx reverse-proxy ingress, proxy header filtering, and Redis-backed login lockouts.      | **July 2026 Security Audit** (Task [SEC-H3](./docs/audit/2026-07-20/task.md)) |

---

## 5. OIDC Identity Provider (IdP) Implementation

AuthKit functions as a centralized IdP, supporting dynamic client registration and multi-phase authorization handshakes. The implementation conforms to strict **OpenID Connect 1.0** specifications.

> [!IMPORTANT]
> For an exhaustive technical breakdown of the OIDC handshake, token introspection, and dynamic client provisioning, refer to the [OIDC Implementation Guide](./docs/oidc_implementation.md). This documentation details the **PKCE verification**, **7-stage interaction handshake**, and **Discovery protocol (RFC 8414)**.

---

## 6. API Inventory & Endpoint Specifications

| Domain             | Functional Scope            | Protocol / Logic       | Details                                           |
| :----------------- | :-------------------------- | :--------------------- | :------------------------------------------------ |
| **Identity (IdP)** | Auth, Token, JWKS, UserInfo | OIDC 1.0 / OAuth 2.0   | Centralized SSO & Third-party provisioning        |
| **Auth**           | Registration, Login, Logout | Password-based Auth    | Secure credential handling & session initiation   |
| **MFA**            | TOTP Setup & Verification   | RFC 6238 (speakeasy)   | Multi-factor secondary verification layer         |
| **OAuth**          | Google Social Integration   | OAuth 2.0 Protocol     | Third-party identity federation                   |
| **Magic Link**     | Passwordless Auth           | Token-based / SMTP     | Email-verified session provisioning               |
| **User/Session**   | Profile & Active State Mgmt | REST / Redis-backed    | Real-time session tracking & profile modification |
| **Admin**          | Moderation & Client Ops     | Restricted REST / RBAC | User lifecycle moderation & Client Registration   |
| **System**         | Health & Dependency Checks  | Heartbeat Logic        | Multi-component dependency status monitoring      |
| **Metadata**       | Discovery, Key Exposition   | RFC 8414               | Automated client configuration (Well-known)       |

Comprehensive specifications including request/response schemas are accessible via the Swagger portal.

👉 Full Documentation: [**API Endpoints Documentation**](./docs/api_endpoints.md)

---

## 7. Comprehensive Security, Performance & Feature Audit (July 2026)

To elevate **AuthKit** from a robust side-project showcase to a **production-ready, enterprise-grade Identity Provider (IdP)** meeting global standards, a thorough engineering audit was performed. This audit systematically analyzed the codebase for cryptographic rigor, protocol compliance, bottleneck optimization, and enterprise scalability.

All findings, remediations, and strategic feature additions have been structured into a master roadmap designed to prevent regressions and secure the platform's core trust base.

### 7.1 Audit Artifacts & Findings

The audit is broken down into specialized focus areas. You can review the exhaustive reports here:

- [**Master Task Plan & Execution Roadmap (`task.md`)**](./docs/audit/2026-07-20/task.md) — The central steering document outlining sequencing, complexity, and priority.
- [**Security Audit Report (`security-audit.md`)**](./docs/audit/2026-07-20/security-audit.md) — Exhaustive analysis of threat vectors, session caching vulnerabilities, and sanitization leaks.
- [**Performance & Scalability Audit (`performance.md`)**](./docs/audit/2026-07-20/performance.md) — Profiling query paths, database connection pooling, and latency-heavy transactions.
- [**Enterprise Feature Recommendations (`feature-recommendations.md`)**](./docs/audit/2026-07-20/feature-recommendations.md) — Functional specifications for B2B multi-tenancy, passkeys, webhooks, and audit trails.
- [**Supplementary Findings (`supplementary-findings.md`)**](./docs/audit/2026-07-20/supplementary-findings.md) — Additional architectural findings and recommendations discovered during the planning phase of the July 2026 security audit (specifically addressing proxy trust dynamics, header verification, and reverse-proxy deployments).

---

### 7.2 Why This Audit?

Modern IAM (Identity & Access Management) systems require zero-compromise security posture. The audit was conducted to:

1.  **Harden Cryptographic Primitives**: Eliminate weak entropy, secure TOTP/MFA secrets, and enforce strict, cryptographically bound token states.
2.  **Ensure Zero-Trust Defaults**: Upgrade session invalidation, CORS handling, and OAuth state verification.
3.  **Optimize High-Concurrency Paths**: Remove expensive bottlenecks (e.g., Bcrypt execution blocking DB transactions) and introduce proper indices.
4.  **Establish B2B/Enterprise Readiness**: Define clear milestones for Multi-Tenancy (Organizations), SAML/OIDC SSO, and Webhook dispatchers.

---

### 7.3 Master Execution Roadmap

The master tasks are sequenced into three distinct phases to manage risks and safeguard production stability:

#### **Phase 1: Critical Fixes (Security-First & Immediate Deployment)**

- **Token Binding**: Explicitly bind password-reset tokens to the payload email (resolving SEC-C1).
- **SSO Hardening**: Address OIDC MFA bypasses during social SSO redirection.
- **Secret Rotation & Vaulting**: Coordination of automated secret rotation policies (JWT keys, RSA keypairs) and moving credentials to a secrets manager.
- **Strict CORS Policy**: Transition from loose substring matching to strict exact-origin allowlists.
- **Session Revocation**: Real-time validation checks for JWT session cache revocation in Redis.

#### **Phase 2: Stability & Performance**

- **Testing Harness**: Setup automated integration testing with Vitest, Supertest, and Testcontainers.
- **High-ROI DB Optimizations**: Add composite indexes on session tables and decouple slow hashing operations from atomic database transactions.
- **Observability**: Integrate Prometheus metrics (`/metrics`), tracing headers, and standard audit logs.

#### **Phase 3: Modernization & Enterprise Features**

- **Passwordless (Passkeys)**: Deploy WebAuthn-based biometrics.
- **Multi-Tenancy**: Introduce logical Organization partitioning.
- **Enterprise Integration**: Enable SAML 2.0 / OIDC RP federation and transactional Webhooks.

For details on individual ticket tracking, metrics, and exit criteria, refer directly to the [**Master Execution Roadmap (`task.md`)**](./docs/audit/2026-07-20/task.md).

---

## 📬 Contact

Found a bug, have a feature request, or want to contribute? Feel free to open an issue, start a discussion, or connect with me.

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/amankrsahu)
[![Discord](https://img.shields.io/badge/Discord-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discordapp.com/users/539751578866024479)
