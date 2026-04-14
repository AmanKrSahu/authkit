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
  "confirmPassword": "strongPassword123"
}
```

### 2.2. Login

- **Route**: `POST /auth/login`
- **Description**: Authenticates a user and returns access and refresh tokens.
- **Security**: Public

**Request Body**

```json
{
  "email": "john@example.com",
  "password": "strongPassword123"
}
```

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
  "email": "john@example.com",
  "password": "newStrongPassword123",
  "confirmPassword": "newStrongPassword123"
}
```

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

---

## 3. OAuth (`/oauth`)

### 3.1. Google Login

- **Route**: `GET /oauth/google`
- **Description**: Redirects the user to Google for authentication.
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
- **Security**: Public

**Request Body**

```json
{
  "email": "john@example.com",
  "uid": "optional_oidc_interaction_uid"
}
```

### 4.2. Verify Magic Link

- **Route**: `POST /magic-link/verify`
- **Description**: Verifies the magic link token and authenticates the user. If `uid` was provided during login, it resumes the OIDC flow.
- **Security**: Public

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
- **Security**: Bearer Token

**Request Body**

```json
{
  "code": "123456"
}
```

### 5.3. Verify Login (MFA)

- **Route**: `POST /mfa/verify-login`
- **Description**: Verifies the MFA code during the login flow.
- **Security**: MFA login token (cookie)

**Request Body**

```json
{
  "code": "123456"
}
```

### 5.4. Revoke MFA

- **Route**: `POST /mfa/revoke`
- **Description**: Disables MFA for the authenticated user.
- **Security**: Bearer Token

**Request Body**: None

---

## 6. User & Session (`/user`, `/session`)

### 6.1. Get Current User

- **Route**: `GET /user/me`
- **Description**: Retrieves the profile of the currently authenticated user.
- **Security**: Bearer Token

### 6.2. List Sessions

- **Route**: `GET /session`
- **Description**: Retrieves all active sessions for the current user.
- **Security**: Bearer Token

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

**Request Body**

```json
{
  "userId": "uuid-string"
}
```

### 7.3. Revoke Session by ID (Admin)

- **Route**: `DELETE /admin/sessions/:sessionId`
- **Description**: Revokes any session by its ID.
- **Security**: Bearer Token (Admin role)

**Request Body**

```json
{
  "sessionId": "uuid-string"
}
```

### 7.4. Revoke All Sessions of a User (Admin)

- **Route**: `DELETE /admin/sessions/user/:userId`
- **Description**: Revokes all sessions for a specific user.
- **Security**: Bearer Token (Admin role)

**Request Body**

```json
{
  "userId": "uuid-string"
}
```

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
