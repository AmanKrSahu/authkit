# API Endpoints Documentation

**Base Path**: `/api/v1`
All endpoints listed below are relative to this base path.

> **Note**: For a complete and up-to-date API reference, please consult the Swagger / OpenAPI documentation (usually available at `/docs` when the server is running).

---

## 1. Health Check (`/`, `/health`)

### 1.1. Basic Status

- **Route**: `GET /`
- **Description**: Returns a simple server status message.
- **Security**: Public

### 1.2. Detailed Health

- **Route**: `GET /health` or `GET /health/detailed`
- **Description**: Checks health of dependent services (database, Redis, etc.).
- **Security**: Public

---

## 2. Authentication (`/auth`)

### 2.1. Register User

- **Route**: `POST /auth/register`
- **Description**: Creates a new user account and sends a verification email.
- **Security**: Public

**Request Body**

```json
{
  "name": "John Doe",
  "email": "john@example.com",
  "password": "strongPassword123",
  "confirmPassword": "strongPassword123",
  "redirectUrl": "https://example.com/optional"
}
```

### 2.2. Login

- **Route**: `POST /auth/login`
- **Description**: Authenticates a user and returns access and refresh tokens. If the account experiences 5 consecutive failed logins, it is temporarily locked out for 15 minutes.
- **Security**: Public

**Request Body**

```json
{
  "email": "john@example.com",
  "password": "strongPassword123"
}
```

_Note: On lockout, the endpoint returns a `400 Bad Request` status code with a message stating that the account is temporarily locked._

### 2.3. Logout

- **Route**: `POST /auth/logout`
- **Description**: Logs out the authenticated user and clears the current session.
- **Security**: Bearer Token + CSRF

**Request Body**: None

### 2.4. Refresh Token

- **Route**: `POST /auth/refresh-token`
- **Description**: Issues a new access token using the refresh token stored in an HttpOnly cookie.
- **Security**: CSRF

**Request Body**: None

### 2.5. Verify Email

- **Route**: `POST /auth/verify-email`
- **Description**: Verifies the user's email address using a verification token.
- **Security**: Public

**Request Body**

```json
{
  "token": "verification_token_string"
}
```

### 2.6. Forgot Password

- **Route**: `POST /auth/forgot-password`
- **Description**: Sends a password reset OTP to the user's email.
- **Security**: Public

**Request Body**

```json
{
  "email": "john@example.com"
}
```

### 2.7. Verify OTP

- **Route**: `POST /auth/verify-otp`
- **Description**: Verifies the OTP sent for password reset.
- **Security**: Public

**Request Body**

```json
{
  "email": "john@example.com",
  "otp": "123456"
}
```

### 2.8. Reset Password

- **Route**: `POST /auth/reset-password`
- **Description**: Resets the user's password using the verified token (stored in cookie).
- **Security**: CSRF

**Request Body**

```json
{
  "password": "newStrongPassword123",
  "confirmPassword": "newStrongPassword123"
}
```

_Note: The email address is no longer supplied in the request body; the identity is securely derived directly from the verified reset token payload to prevent account takeover._

### 2.9. Change Password

- **Route**: `POST /auth/change-password`
- **Description**: Changes the authenticated user's password.
- **Security**: Bearer Token

**Request Body**

```json
{
  "currentPassword": "oldPassword123",
  "newPassword": "newStrongPassword123"
}
```

### 2.10. Resend Verification Email

- **Route**: `POST /auth/resend-verification`
- **Description**: Resends the verification email to the user's email address.
- **Security**: Public

**Request Body**

```json
{
  "email": "john@example.com",
  "redirectUrl": "https://example.com/optional"
}
```

---

## 3. OAuth (`/oauth`)

### 3.1. Google Login

- **Route**: `GET /oauth/google`
- **Description**: Redirects the user to Google for authentication. Accepts optional query parameters `?redirectUrl=https...` and `?uid=...`.
- **Security**: Public

### 3.2. Google Callback

- **Route**: `GET /oauth/google/callback`
- **Description**: Handles the OAuth callback from Google.
- **Security**: Public

---

## 4. Magic Link Authentication (`/magic-link`)

### 4.1. Request Magic Link

- **Route**: `POST /magic-link/login`
- **Description**: Sends a magic login link to the user's email address.
- **Security**: Public (Rate-limited via `authRateLimiter` and in-service checks)

**Request Body**

```json
{
  "email": "john@example.com",
  "uid": "optional_oidc_interaction_uid",
  "redirectUrl": "https://example.com/optional"
}
```

### 4.2. Verify Magic Link

- **Route**: `POST /magic-link/verify`
- **Description**: Verifies the magic link token and authenticates the user. If `uid` was provided during login, it resumes the OIDC flow.
- **Security**: Public (Rate-limited via `authRateLimiter`)

**Request Body**

```json
{
  "token": "magic_link_token_string"
}
```

---

## 5. Multi-Factor Authentication (MFA) (`/mfa`)

### 5.1. Setup MFA

- **Route**: `POST /mfa/setup`
- **Description**: Generates a TOTP secret and QR code for MFA enrollment.
- **Security**: Bearer Token

**Request Body**: None

### 5.2. Verify MFA Setup

- **Route**: `POST /mfa/verify-setup`
- **Description**: Verifies the TOTP code and enables MFA.
- **Security**: Bearer Token (Rate-limited via `authRateLimiter`)

**Request Body**

```json
{
  "code": "123456"
}
```

### 5.3. Verify Login (MFA)

- **Route**: `POST /mfa/verify-login`
- **Description**: Verifies the MFA code during the login flow. The intermediate `mfaLoginToken` cookie is single-use and validated against a server-side Redis nonce. Once successfully verified, the token is invalidated immediately to prevent replay attacks.
- **Security**: MFA login token cookie (Rate-limited via `authRateLimiter` and capped at 5 failed attempts per user ID)

**Request Body**

```json
{
  "code": "123456"
}
```

### 5.4. Revoke MFA

- **Route**: `POST /mfa/revoke`
- **Description**: Disables MFA for the authenticated user. For accounts with a password credential, the account password must be provided to complete the revocation.
- **Security**: Bearer Token

**Request Body**

```json
{
  "password": "yourPassword123"
}
```

---

## 6. User & Session (`/user`, `/session`)

### 6.1. Get Current User

- **Route**: `GET /user/me`
- **Description**: Retrieves the profile of the currently authenticated user.
- **Security**: Bearer Token

### 6.2. List Sessions

- **Route**: `GET /session`
- **Description**: Retrieves all active sessions for the current user using cursor-based pagination.
- **Security**: Bearer Token

**Query Parameters**

- `cursor` (optional, string): The unique session ID used as the cursor for the next page of results.
- `limit` (optional, number): The maximum number of sessions to return (default: `100`, max: `100`).

**Response Headers**

- `X-Total-Count` (number): The total count of active sessions matching the user.
- `X-Page-Count` (number): The total number of pages available based on the limit.

**Response Example**

```json
{
  "success": true,
  "message": "Sessions retrieved successfully",
  "data": {
    "sessions": [
      {
        "id": "cm0...",
        "userId": "cm0...",
        "userAgent": "Mozilla/5.0 ...",
        "ipAddress": "127.0.0.1",
        "deviceFingerprint": "fingerprint",
        "isRevoked": false,
        "createdAt": "2026-08-01T12:00:00.000Z",
        "expiresAt": "2026-08-15T12:00:00.000Z",
        "isCurrent": true
      }
    ],
    "pagination": {
      "cursor": null,
      "nextCursor": null,
      "hasMore": false,
      "limit": 100,
      "totalCount": 1,
      "totalPages": 1
    }
  }
}
```

### 6.3. Get Session by ID

- **Route**: `GET /session/:sessionId`
- **Description**: Retrieves details of a specific session.
- **Security**: Bearer Token

### 6.4. Revoke Session

- **Route**: `DELETE /session/:sessionId`
- **Description**: Revokes a specific session.
- **Security**: Bearer Token

### 6.5. Revoke All Other Sessions

- **Route**: `DELETE /session`
- **Description**: Revokes all active sessions except the current one.
- **Security**: Bearer Token

---

## 7. Admin (`/admin`)

### 7.1. Promote User to Admin

- **Route**: `POST /admin/users/promote`
- **Description**: Promotes a user to the ADMIN role.
- **Security**: Bearer Token (Admin role)

**Request Body**

```json
{
  "userId": "uuid-string"
}
```

### 7.2. Delete User

- **Route**: `DELETE /admin/users/:userId`
- **Description**: Deletes a user account and all associated data.
- **Security**: Bearer Token (Admin role)

**Request Body**: None

### 7.3. Revoke Session by ID (Admin)

- **Route**: `DELETE /admin/sessions/:sessionId`
- **Description**: Revokes any session by its ID.
- **Security**: Bearer Token (Admin role)

**Request Body**: None

### 7.4. Revoke All Sessions of a User (Admin)

- **Route**: `DELETE /admin/sessions/user/:userId`
- **Description**: Revokes all sessions for a specific user.
- **Security**: Bearer Token (Admin role)

**Request Body**: None

### 7.5. Register OIDC Client

- **Route**: `POST /admin/oidc/clients`
- **Description**: Registers a new OIDC client and returns the generated Client ID and Client Secret. Ensure you save the secret as it will not be shown again.
- **Security**: Bearer Token (Admin role)

**Request Body**

```json
{
  "clientName": "Client Name",
  "redirectUrls": ["https://example.com/callback"],
  "grantTypes": ["authorization_code", "refresh_token"],
  "scope": "openid profile email"
}
```

### 7.6. Fetch All Users

- **Route**: `GET /admin/users`
- **Description**: Retrieves a list of all users using cursor-based pagination.
- **Security**: Bearer Token (Admin role)

**Query Parameters**

- `cursor` (optional, string): The unique user ID used as the cursor for the next page.
- `limit` (optional, number): The maximum number of users to return (default: `100`, max: `100`).

**Response Headers**

- `X-Total-Count` (number): The total count of registered users in the database.
- `X-Page-Count` (number): The total number of pages available based on the limit.

**Response Example**

```json
{
  "success": true,
  "message": "Users retrieved successfully",
  "data": {
    "users": [
      {
        "id": "cm0...",
        "name": "John Doe",
        "email": "john@example.com",
        "role": "USER",
        "createdAt": "2026-08-01T12:00:00.000Z"
      }
    ],
    "pagination": {
      "cursor": null,
      "nextCursor": null,
      "hasMore": false,
      "limit": 100,
      "totalCount": 1,
      "totalPages": 1
    }
  }
}
```

### 7.7. Fetch A Specific User

- **Route**: `GET /admin/users/:userId`
- **Description**: Retrieves details of a specific user.
- **Security**: Bearer Token (Admin role)

**Request Body**: None

### 7.8. Fetch User Sessions

- **Route**: `GET /admin/sessions/user/:userId`
- **Description**: Retrieves all active sessions for a specific user using cursor-based pagination.
- **Security**: Bearer Token (Admin role)

**Query Parameters**

- `cursor` (optional, string): The unique session ID used as the cursor for the next page.
- `limit` (optional, number): The maximum number of sessions to return (default: `100`, max: `100`).

**Response Headers**

- `X-Total-Count` (number): The total count of active sessions matching the target user.
- `X-Page-Count` (number): The total number of pages available based on the limit.

**Response Example**

```json
{
  "success": true,
  "message": "User sessions retrieved successfully",
  "data": {
    "sessions": [
      {
        "id": "cm0...",
        "userId": "cm0...",
        "userAgent": "Mozilla/5.0 ...",
        "ipAddress": "127.0.0.1",
        "isRevoked": false,
        "createdAt": "2026-08-01T12:00:00.000Z",
        "expiresAt": "2026-08-15T12:00:00.000Z"
      }
    ],
    "pagination": {
      "cursor": null,
      "nextCursor": null,
      "hasMore": false,
      "limit": 100,
      "totalCount": 1,
      "totalPages": 1
    }
  }
}
```

### 7.9. List Audit Logs

- **Route**: `GET /admin/audit-logs`
- **Description**: Returns a paginated list of security audit logs. Supports filtering by `userId`, `action`, `entityType`, `entityId`, `status`, `startDate`, and `endDate`.
- **Security**: Admin Only (`Role.ADMIN`)

**Query Parameters**:

- `cursor` (string, optional): Pagination cursor ID.
- `limit` (number, optional): Page limit.
- `userId` (string, optional): Filter by actor user ID.
- `action` (string, optional): Filter by `AuditAction` enum.
- `entityType` (string, optional): Filter by resource type (e.g. `User`, `Session`, `OidcClient`).
- `entityId` (string, optional): Filter by target resource ID.
- `status` (string, optional): Filter by `SUCCESS` or `FAILURE`.
- `startDate` (string, optional): ISO start date timestamp.
- `endDate` (string, optional): ISO end date timestamp.

### 7.10. Get Audit Log Details

- **Route**: `GET /admin/audit-logs/:id`
- **Description**: Returns full audit log details for a single log entry. Sensitive metadata values are automatically redacted.
- **Security**: Admin Only (`Role.ADMIN`)

### 7.11. Webhooks & Outbound Events (`/admin/webhooks`)

#### 7.11.1. Create Webhook Subscription

- **Route**: `POST /admin/webhooks`
- **Description**: Creates a new webhook subscription for external platform integration. Generates a cryptographically secure signing secret (`whsec_...`).
- **Security**: Admin Only (`Role.ADMIN`)

#### 7.11.2. List Webhook Subscriptions

- **Route**: `GET /admin/webhooks`
- **Description**: Retrieves a paginated list of webhook subscriptions with optional `status` filtering. Signing secrets are redacted.
- **Security**: Admin Only (`Role.ADMIN`)

#### 7.11.3. Get Webhook Subscription Details

- **Route**: `GET /admin/webhooks/:id`
- **Description**: Retrieves details for a specific webhook subscription.
- **Security**: Admin Only (`Role.ADMIN`)

#### 7.11.4. Update Webhook Subscription

- **Route**: `PATCH /admin/webhooks/:id`
- **Description**: Updates subscription configuration (name, URL, description, subscribed events, or status). Validates target URLs against SSRF security policies.
- **Security**: Admin Only (`Role.ADMIN`)

#### 7.11.5. Delete Webhook Subscription

- **Route**: `DELETE /admin/webhooks/:id`
- **Description**: Permanently deletes a webhook subscription and its associated delivery records.
- **Security**: Admin Only (`Role.ADMIN`)

#### 7.11.6. Rotate Webhook Signing Secret

- **Route**: `POST /admin/webhooks/:id/rotate-secret`
- **Description**: Rotates the HMAC signing secret for a webhook endpoint while maintaining a 24-hour dual-signature grace period for zero-downtime rotation.
- **Security**: Admin Only (`Role.ADMIN`)

#### 7.11.7. Send Test Webhook Event

- **Route**: `POST /admin/webhooks/:id/test`
- **Description**: Dispatches a signed `webhook.test` event delivery attempt to verify receiver endpoint health.
- **Security**: Admin Only (`Role.ADMIN`)

#### 7.11.8. Fetch Webhook Delivery History

- **Route**: `GET /admin/webhooks/:id/deliveries`
- **Description**: Retrieves paginated delivery attempt records for a webhook subscription.
- **Security**: Admin Only (`Role.ADMIN`)

#### 7.11.9. Fetch Webhook Delivery Details

- **Route**: `GET /admin/webhooks/:id/deliveries/:deliveryId`
- **Description**: Retrieves detailed information for a specific delivery attempt including request payload, HTTP status, duration, error reason, and redacted response body.
- **Security**: Admin Only (`Role.ADMIN`)

---

## 8. OpenID Connect (OIDC) (`/oidc`)

The OIDC endpoints enable this application to act as an Identity Provider (IdP) for other applications.

### 8.1. Discovery Configuration

- **Route**: `GET /oidc/.well-known/openid-configuration`
- **Description**: Returns the OIDC Provider configuration and supported metadata.
- **Security**: Public

### 8.2. JWKS (Json Web Key Set)

- **Route**: `GET /oidc/jwks`
- **Description**: Returns the public keys used to verify tokens signed by this provider.
- **Security**: Public

### 8.3. Authorization

- **Route**: `GET /oidc/auth`
- **Description**: Starts the OIDC Authorization Code flow. Redirects to interaction endpoints if login/consent is needed.
- **Security**: Public (Requires Client ID, Redirect URI, etc.)

### 8.4. Token

- **Route**: `POST /oidc/token`
- **Description**: Exchanges an Authorization Code for Access, Refresh, and ID Tokens.
- **Security**: Basic Auth (Client ID & Secret) OR POST Body Credentials.

### 8.5. UserInfo

- **Route**: `GET /oidc/me`
- **Description**: Returns claims about the authenticated user.
- **Security**: Bearer Token (Access Token from OIDC flow)

### 8.6. Introspection

- **Route**: `POST /oidc/token/introspection`
- **Description**: Validates a token and returns its active state and meta-information.
- **Security**: Basic Auth (Client ID & Secret)

### 8.7. Revocation

- **Route**: `POST /oidc/token/revocation`
- **Description**: Revokes a given token.
- **Security**: Basic Auth (Client ID & Secret)

### 8.8. Get Interaction Details

- **Route**: `GET /oidc/interaction/:uid`
- **Description**: Get interaction details. **Note:** Checks for an existing Direct API session (`refreshToken` cookie) and automatically logs the user in if valid (Session Bridge).
- **Security**: Public

### 8.9. Submit Login Interaction

- **Route**: `POST /oidc/interaction/:uid/login`
- **Description**: Submit login credentials. Returns `{ mfaRequired: true, uid: "..." }` if MFA is enabled.
- **Security**: Public

### 8.10. Submit MFA Interaction

- **Route**: `POST /oidc/interaction/:uid/mfa`
- **Description**: Submit MFA code to finalize login (New).
- **Security**: Public

### 8.11. Confirm Consent

- **Route**: `POST /oidc/interaction/:uid/confirm`
- **Description**: Confirm consent.
- **Security**: Public

### 8.12. Abort Interaction

- **Route**: `GET /oidc/interaction/:uid/abort`
- **Description**: Abort interaction.
- **Security**: Public

### 8.13. Generate OIDC WebAuthn Options

- **Route**: `POST /oidc/interaction/:uid/webauthn/options`
- **Description**: Generates WebAuthn authentication options and random challenge bound to the OIDC interaction session.
- **Security**: Public

### 8.14. Submit OIDC WebAuthn Assertion

- **Route**: `POST /oidc/interaction/:uid/webauthn/verify`
- **Description**: Verifies passkey assertion, authenticates user, and completes OIDC login interaction prompt.
- **Security**: Public

### 8.15. Submit OIDC WebAuthn MFA Assertion

- **Route**: `POST /oidc/interaction/:uid/webauthn/mfa`
- **Description**: Verifies passkey assertion as a secondary factor during OIDC MFA interaction prompt.
- **Security**: Public (Requires `mfaLoginToken` cookie)

---

## 9. WebAuthn & Passkeys (`/webauthn`)

Phishing-resistant passwordless authentication and authenticator management conforming to the FIDO2 / WebAuthn standard.

### 9.1. Generate Registration Options

- **Route**: `POST /webauthn/register/options`
- **Description**: Generates cryptographic options and random challenge for registering a new passkey. Automatically excludes existing user credentials to prevent duplicate registrations.
- **Security**: Bearer Token (Rate-limited via `authRateLimiter`)

**Request Body**: None

### 9.2. Verify Registration Response

- **Route**: `POST /webauthn/register/verify`
- **Description**: Verifies authenticator attestation response, checks challenge from Redis, and persists the passkey credential in the database.
- **Security**: Bearer Token (Rate-limited via `authRateLimiter`)

**Request Body**

```json
{
  "name": "MacBook Touch ID",
  "response": {
    "id": "credential_id_here",
    "rawId": "raw_credential_id_here",
    "response": {
      "clientDataJSON": "base64url_string",
      "attestationObject": "base64url_string"
    },
    "type": "public-key",
    "clientExtensionResults": {}
  }
}
```

### 9.3. Generate Authentication Options

- **Route**: `POST /webauthn/authenticate/options`
- **Description**: Generates assertion options and random challenge for passwordless passkey login. Accepts optional `email` for user-identified login, or supports discoverable passkeys.
- **Security**: Public (Rate-limited via `authRateLimiter`)

**Request Body**

```json
{
  "email": "user@example.com"
}
```

### 9.4. Verify Authentication Assertion

- **Route**: `POST /webauthn/authenticate/verify`
- **Description**: Verifies passkey assertion, validates signature counter, establishes user session, sets authentication cookies, and issues JWT access tokens.
- **Security**: Public (Rate-limited via `authRateLimiter`)

**Request Body**

```json
{
  "response": {
    "id": "credential_id_here",
    "rawId": "raw_credential_id_here",
    "response": {
      "clientDataJSON": "base64url_string",
      "authenticatorData": "base64url_string",
      "signature": "base64url_string",
      "userHandle": "optional_user_handle"
    },
    "type": "public-key",
    "clientExtensionResults": {}
  }
}
```

### 9.5. Verify MFA Assertion via Passkey

- **Route**: `POST /webauthn/authenticate/verify-mfa`
- **Description**: Verifies passkey assertion as a secondary factor during an active MFA login challenge.
- **Security**: Public (Requires `mfaLoginToken` cookie, rate-limited via `authRateLimiter`)

**Request Body**

```json
{
  "response": {
    "id": "credential_id_here",
    "rawId": "raw_credential_id_here",
    "response": {
      "clientDataJSON": "base64url_string",
      "authenticatorData": "base64url_string",
      "signature": "base64url_string"
    },
    "type": "public-key",
    "clientExtensionResults": {}
  }
}
```

### 9.6. List Registered Authenticators

- **Route**: `GET /webauthn/authenticators`
- **Description**: Returns all passkey authenticators registered to the authenticated user with masked public key data.
- **Security**: Bearer Token

### 9.7. Update Authenticator Name

- **Route**: `PATCH /webauthn/authenticators/:id`
- **Description**: Updates the friendly label/name of a registered passkey.
- **Security**: Bearer Token

**Request Body**

```json
{
  "name": "Work Laptop Passkey"
}
```

### 9.8. Delete Authenticator

- **Route**: `DELETE /webauthn/authenticators/:id`
- **Description**: Deletes a registered passkey owned by the authenticated user.
- **Security**: Bearer Token
