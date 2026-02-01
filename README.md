# AuthKit : Authentication & User Management Microservice

<img src="https://img.shields.io/badge/TypeScript-3178C6?style=for-the-badge&logo=typescript&logoColor=white" /> <img src="https://img.shields.io/badge/Node.js-339933?style=for-the-badge&logo=node.js&logoColor=white" /> <img src="https://img.shields.io/badge/Express.js-000000?style=for-the-badge&logo=express&logoColor=white" />
<img src="https://img.shields.io/badge/Prisma-2D3748?style=for-the-badge&logo=prisma&logoColor=white" /> <img src="https://img.shields.io/badge/PostgreSQL-4169E1?style=for-the-badge&logo=postgresql&logoColor=white" /> <img src="https://img.shields.io/badge/Redis-DC382D?style=for-the-badge&logo=redis&logoColor=white" /> <img src="https://img.shields.io/badge/Swagger-85EA2D?style=for-the-badge&logo=swagger&logoColor=black" /> <img src="https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white" />

## 1. Project Abstract

AuthKit is a robust, production-ready authentication and user management microservice designed to simplify secure identity management for modern applications. It provides a comprehensive set of features including JWT-based authentication, multi-factor authentication (MFA), OAuth integration, and session management, allowing developers to focus on building core product features rather than reinventing security flows.

**Core Capabilities**:

- Secure User Registration & Login (Email/Password)
- JWT-based Access Tokens & Refresh Token Rotation
- Multi-Factor Authentication (TOTP via Authenticator Apps)
- Social Login (Google OAuth)
- Magic Link Authentication (Passwordless)
- Robust Session Management (View & Revoke active sessions)
- Admin User Management & Moderation
- Comprehensive Security Headers (Helmet, CORS) & Rate Limiting

---

## 2. Tech Stack (Short Highlight)

- **Language**: TypeScript (Node.js)
- **Framework**: Express.js
- **Database**: PostgreSQL
- **ORM**: Prisma
- **Caching/Session**: Redis
- **Validation**: Zod
- **Documentation**: Swagger / OpenAPI
- **Containerization**: Docker & Docker Compose
- **Email**: Resend
- **Crypto**: Bcrypt, Speakeasy (MFA)

---

## 3. Developer Setup

### 3.1. Using Docker & docker-compose

**Prerequisites**:

- Docker & Docker Compose

**Setup**:

1.  Clone the repository.

    ```
    git clone https://github.com/AmanKrSahu/authkit.git
    ```

2.  Create the environment file:

    ```bash
    # Update .env with your credentials.
    cp .env.example .env
    ```

3.  Build and run the services:

    ```bash
    docker-compose -f docker-compose.dev.yml up --build -d
    ```

---

### 3.2. Running locally without Docker

**Prerequisites**:

- Node.js (LTS version recommended)
- pnpm (`npm install -g pnpm`)
- PostgreSQL (Running locally)
- Redis (Running locally)

**Setup**:

1.  Install dependencies:

    ```bash
    pnpm install
    ```

2.  Configure Environment:

    ```bash
    # Update .env with your credentials.
    cp .env.example .env
    ```

3.  Run Migrations & Seeds:

    ```bash
    pnpm db:generate
    pnpm db:push
    ```

    _(Optional) Seed data if available:_ `pnpm db:seed`

4.  Start the application:
    ```bash
    pnpm dev
    ```

### 3.3 Access Endpoints

- API: `http://localhost:8000/api/v1/`
- Swagger Docs: `http://localhost:8000/docs`

---

## 4. Core Architecture & Security Overview

**System Architecture**:
The system follows a modular Layered Architecture (Controller-Service-Repository pattern) to ensure separation of concerns. The core logic is isolated in feature-based modules (Auth, User, Session, etc.), making the codebase scalable and maintainable.

**Authentication & Authorization**:

- **Access**: Short-lived JWTs (JSON Web Tokens) are used for API access, passed in the `Authorization: Bearer` header.
- **Refresh**: Long-lived Refresh Tokens are securely stored (typically in HttpOnly cookies or secure storage) to rotate access tokens without forcing re-login.
- **MFA**: Time-based One-Time Password (TOTP) is implemented using `speakeasy`, requiring a second verification step for enhanced security.
- **RBAC**: Role-based access control (e.g., Admin guards) ensures sensitive endpoints are protected.

**Security**:

- **Data Protection**: Passwords are hashed using `bcrypt` before storage. Sensitive fields are excluded from API responses.
- **Communication**: All external communications should occur over HTTPS (enforced in production). CORS and Helmet are configured to mitigate common web attacks.
- **Rate Limiting**: Global and Auth-specific rate limiters prevent brute-force and DDoS attacks.

👉 Full Documentation: [Detailed Security Architecture](./docs/security_architecture.md)

---

## 5. API Endpoints Overview

We have detailed documentation for all API endpoints, including request schemas and security requirements.

👉 Full Documentation: [**API Endpoints Documentation**](./docs/api_endpoints.md)

### Quick Overview

| Domain           | Description                                     |
| :--------------- | :---------------------------------------------- |
| **Auth**         | Registration, Login, Logout, MFA, Password Mgmt |
| **OAuth**        | Google Social Login                             |
| **Magic Link**   | Passwordless Login                              |
| **User/Session** | Profile & Active Session Management             |
| **Admin**        | User Moderation & System Ops                    |

> **Note**: For a complete and up-to-date API reference, please consult the Swagger / OpenAPI documentation.

---

## 🚀 Need Help??

Feel free to contact me on [Linkedin](https://www.linkedin.com/in/amankrsahu)

[![Instagram URL](https://img.shields.io/badge/Instagram-E4405F?style=for-the-badge&logo=instagram&logoColor=white)](https://www.instagram.com/itz.amansahu/) &nbsp; [![Discord URL](https://img.shields.io/badge/Discord-7289DA?style=for-the-badge&logo=discord&logoColor=white)](discordapp.com/users/539751578866024479)
