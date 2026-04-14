# OpenID Connect (OIDC) Implementation Guide

## 1. Why OIDC?

We implemented OpenID Connect (OIDC) to transform our authentication system into a centralized **Identity Provider (IdP)**. This architectural shift allows our application to verify user identity not just for its own frontend, but for **any** authorized third-party application or internal service.

Key motivations:

- **Standardization**: Conforms to a globally accepted standard (OIDC 1.0) built on top of OAuth 2.0.
- **Interoperability**: Connects seamlessly with any OIDC-compliant client (e.g., Salesforce, Slack, Internal Tools).
- **Security**: Centralizes credential handling. Third-party apps never see user passwords; they only receive tokens.

## 2. Enabling Single Sign-On (SSO)

OIDC is the backbone of our Single Sign-On (SSO) strategy.

- **Without OIDC**: A user would need separate credentials (username/password) for every application in our ecosystem (Main App, Dashboard, Support Portal, etc.).
- **With OIDC (SSO)**:
  1.  User logs into the **IdP** (our AuthKit app) once.
  2.  A session is established on the IdP.
  3.  When the user visits another app (e.g., Dashboard), it redirects them to the IdP.
  4.  The IdP recognizes the existing session and automatically logs them in **without re-entering credentials**.

This provides a frictionless user experience and reduces password fatigue/reuse risks.

## 3. Current Implementation Architecture

Our implementation uses the certified `oidc-provider` library, backed by a robust and scalable infrastructure.

### Core Components

- **Provider**: The OIDC engine that handles protocol logic (validation, token issuance, discovery).
- **Adapter**: A custom **Redis Adapter** persists OIDC state (Grants, Sessions, Codes) for high speed and TTL management.
- **Account**: The `findAccount` method bridges the OIDC provider with our PostgreSQL database to fetch User Profiles.
- **Interactions**: Custom API endpoints (`/oidc/interaction/*`) that render our existing Login/Consent UI, giving us full control over the user experience.

## 4. OIDC Identity Provider (IdP) Integration Flow

To verify the entire OIDC Identity Provider (IdP) capability, we can trace a real-world integration flow. This flow covers a typical dynamic authentication sequence executed by a third-party application.

The following details the interactions step-by-step, including request payloads and expected responses:

### Phase 1: Dynamic Client Registration

Before users can log in, the third-party application must be registered with the IdP.

**Endpoint:** `POST /admin/oidc/clients`
**Headers:** `Authorization: Bearer <ADMIN_TOKEN>`
**Body (JSON):**

```json
{
  "clientName": "Test Client",
  "redirectUrls": ["http://localhost:8000/callback"],
  "grantTypes": ["authorization_code", "refresh_token"],
  "scope": "openid profile email role"
}
```

**Result:**
The server returns a payload containing the `clientId` and `clientSecret`.

---

### Phase 2: Metadata & Discovery

Clients use these endpoints to automatically configure themselves.

1.  **Discovery**: `GET /oidc/.well-known/openid-configuration`
    - Verify all endpoints (auth, token, userinfo) are correctly returned.
2.  **Public Keys (JWKS)**: `GET /oidc/jwks`
    - Verify the signing keys are available for token validation.

---

### Phase 3: The Authorization & Consent Flow

Since OIDC is based on browser redirects within the user agent, the handshake follows a strict redirect sequence.

#### Step 3.1: Initiate Authorization

**Endpoint:** `GET /oidc/auth`
**Query Params:**

- `client_id`: `c79410c0...`
- `response_type`: `code`
- `scope`: `openid profile email`
- `redirect_uri`: `http://localhost:8000/callback`
- `state`: `12345`
- `code_challenge`: `<base64url-encoded-sha256-hash>` (PKCE)
- `code_challenge_method`: `S256`

**Result:** `303 See Other`
Redirects the user to `/oidc/interaction/<uid>` and sets `_interaction` session cookies.

#### Step 3.2: Fetch Interaction Details

**Endpoint:** `GET /oidc/interaction/<uid>`
**Headers:** Application must forward the `_interaction` and `_interaction.sig` cookies.

**Result:**

```json
{
  "prompt": { "name": "login" }
}
```

Indicates the user needs to establish an authenticated session.

#### Step 3.3: Submit Credentials (Login)

**Endpoint:** `POST /oidc/interaction/<uid>/login`
**Headers:** Forward `_interaction` cookies. `Content-Type: application/json`.
**Body (JSON):**

```json
{
  "email": "testuser@example.com",
  "password": "Password123!"
}
```

**Result:** `303 See Other`
Returns a successfully authenticated session (`_session` cookie) and redirects to the resume checkpoint `/oidc/auth/<uid>`.

#### Step 3.4: Resume Auth (Consent Check)

**Endpoint:** `GET /oidc/auth/<uid>`
**Headers:** Forward the `_session` and `_interaction_resume` cookies.

**Result:** `303 See Other`
Redirects to a new interaction identifier `/oidc/interaction/<new_uid>` for Consent.

#### Step 3.5: Fetch Consent Interaction Details

**Endpoint:** `GET /oidc/interaction/<new_uid>`

**Result:**

```json
{
  "prompt": {
    "name": "consent",
    "details": { "missingOIDCScope": ["openid", "profile", "email"] }
  }
}
```

#### Step 3.6: Confirm Consent

**Endpoint:** `POST /oidc/interaction/<new_uid>/confirm`

**Result:** `303 See Other`
Redirects back to the final authorization resume checkpoint `/oidc/auth/<new_uid>`.

#### Step 3.7: Final Resume (Get Auth Code)

**Endpoint:** `GET /oidc/auth/<new_uid>`

**Result:** `303 See Other`
Redirects the user agent back to the application's `redirect_uri` including the authorization code:
`http://localhost:8000/callback?code=AUTH_CODE_HERE&state=12345`

---

### Phase 4: Exchanging the Code for Tokens

Now the third-party backend trades the short-lived authorization code for actual security tokens directly with the IdP.

**Endpoint:** `POST /oidc/token`
**Headers:**

- `Content-Type: application/x-www-form-urlencoded`
- `Authorization: Basic <base64(clientId:clientSecret)>`
  **Body:**
- `grant_type`: `authorization_code`
- `code`: `AUTH_CODE_HERE`
- `redirect_uri`: `http://localhost:8000/callback`
- `code_verifier`: `<plain-text-pkce-verifier>`

**Result:**

```json
{
  "access_token": "rbv7eZr8cHWolF...",
  "id_token": "eyJhbG...",
  "expires_in": 3600,
  "scope": "openid profile email",
  "token_type": "Bearer"
}
```

---

### Phase 5: Resource Access & Validation

1.  **User Info**: `GET /oidc/me`
    - **Header**: `Authorization: Bearer <access_token>`
    - **Verify Result:**
      ```json
      {
        "sub": "cmnc0end5...",
        "name": "Test User",
        "preferred_username": "testuser",
        "email": "testuser@example.com",
        "email_verified": true
      }
      ```
2.  **Introspection**: `POST /oidc/token/introspection`
    - **Header**: `Authorization: Basic <base64(clientId:clientSecret)>`
    - **Body**: `token=<access_token>`
    - **Verify**: `active: true`.
3.  **Revocation**: `POST /oidc/token/revocation`
    - **Header**: `Authorization: Basic <base64(clientId:clientSecret)>`
    - **Body**: `token=<access_token>`

---

### Summary of Endpoints

| Phase           | Endpoint                                 | Method | Purpose                                  |
| :-------------- | :--------------------------------------- | :----- | :--------------------------------------- |
| **Admin**       | `/admin/oidc/clients`                    | POST   | Register a new service (Client)          |
| **Metadata**    | `/oidc/.well-known/openid-configuration` | GET    | Self-discovery for clients               |
| **Auth**        | `/oidc/auth`                             | GET    | Start the Login flow                     |
| **Interaction** | `/oidc/interaction/:uid`                 | GET    | Get info about the current login/consent |
| **Interaction** | `/oidc/interaction/:uid/login`           | POST   | Submit credentials                       |
| **Interaction** | `/oidc/interaction/:uid/confirm`         | POST   | Finalize consent and get the Code        |
| **Token**       | `/oidc/token`                            | POST   | Trade Code for Tokens                    |
| **Profile**     | `/oidc/me`                               | GET    | Get authenticated user profile           |
| **Security**    | `/oidc/token/introspection`              | POST   | Check if a token is still valid          |
| **Security**    | `/oidc/token/revocation`                 | POST   | Invalidate a token (Logout/Revoke)       |

## 6. Security Measures

- **PKCE (Proof Key for Code Exchange)**: Mandatory for all clients. Prevents interception of the authorization code.
- **Bcrypt Hashing**: Client Secrets are hashed in the DB, just like user passwords.
- **HttpOnly Cookies**: All interaction cookies are signed and HttpOnly to prevent XSS.
- **Redis-Backed State**: High-performance state management prevents race conditions and replay attacks.
- **Token Rotation**: Refresh tokens are rotated on every use to limit the impact of a leak.
