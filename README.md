# AuthKit: Identity Provider (IdP) & IAM Infrastructure

<img src="https://img.shields.io/badge/TypeScript-3178C6?style=for-the-badge&logo=typescript&logoColor=white" /> <img src="https://img.shields.io/badge/Node.js-339933?style=for-the-badge&logo=node.js&logoColor=white" /> <img src="https://img.shields.io/badge/Express.js-000000?style=for-the-badge&logo=express&logoColor=white" />
<img src="https://img.shields.io/badge/Prisma-2D3748?style=for-the-badge&logo=prisma&logoColor=white" /> <img src="https://img.shields.io/badge/PostgreSQL-4169E1?style=for-the-badge&logo=postgresql&logoColor=white" /> <img src="https://img.shields.io/badge/Redis-DC382D?style=for-the-badge&logo=redis&logoColor=white" /> <img src="https://img.shields.io/badge/Swagger-85EA2D?style=for-the-badge&logo=swagger&logoColor=black" /> <img src="https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white" />

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

- **API Interface**: `http://localhost:8000/api/v1/`
- **OpenAPI/Swagger Portal**: `http://localhost:8000/docs`

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

👉 Full Documentation: [**Detailed Security Architecture**](./docs/security_architecture.md)

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

## 🚀 Need Help??

Feel free to contact me on [Linkedin](https://www.linkedin.com/in/amankrsahu)

[![Instagram URL](https://img.shields.io/badge/Instagram-E4405F?style=for-the-badge&logo=instagram&logoColor=white)](https://www.instagram.com/itz.amansahu/) &nbsp; [![Discord URL](https://img.shields.io/badge/Discord-7289DA?style=for-the-badge&logo=discord&logoColor=white)](discordapp.com/users/539751578866024479)
