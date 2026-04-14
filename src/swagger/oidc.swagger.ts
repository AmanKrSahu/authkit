/**
 * @openapi
 * /oidc/interaction/{uid}:
 *   get:
 *     tags:
 *       - OIDC APIs
 *     summary: Get interaction details
 *     description: "Retrieves details of an OIDC interaction. If a valid Direct API session exists (via `refreshToken` cookie), this endpoint automatically logs the user in (Session Bridge)."
 *     security: []
 *     parameters:
 *       - in: path
 *         name: uid
 *         required: true
 *         schema:
 *           type: string
 *         description: Interaction UID
 *     responses:
 *       200:
 *         description: Interaction details retrieved successfully.
 *       400:
 *         description: Bad request - Invalid interaction.
 *       500:
 *         description: Internal server error.
 */

/**
 * @openapi
 * /oidc/interaction/{uid}/login:
 *   post:
 *     tags:
 *       - OIDC APIs
 *     summary: Submit login interaction
 *     description: "Submits user credentials for an OIDC login interaction. If MFA is enabled, it returns `mfaRequired: true`."
 *     security: []
 *     parameters:
 *       - in: path
 *         name: uid
 *         required: true
 *         schema:
 *           type: string
 *         description: Interaction UID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *               password:
 *                 type: string
 *                 format: password
 *     responses:
 *       200:
 *         description: Login successful or MFA required.
 *       400:
 *         description: Bad request - Invalid credentials.
 *       500:
 *         description: Internal server error.
 */

/**
 * @openapi
 * /oidc/interaction/{uid}/confirm:
 *   post:
 *     tags:
 *       - OIDC APIs
 *     summary: Confirm interaction
 *     description: Confirms an OIDC interaction (e.g., consent).
 *     security: []
 *     parameters:
 *       - in: path
 *         name: uid
 *         required: true
 *         schema:
 *           type: string
 *         description: Interaction UID
 *     responses:
 *       200:
 *         description: Interaction confirmed successfully.
 *       400:
 *         description: Bad request.
 *       500:
 *         description: Internal server error.
 */

/**
 * @openapi
 * /oidc/interaction/{uid}/abort:
 *   get:
 *     tags:
 *       - OIDC APIs
 *     summary: Abort interaction
 *     description: Aborts an OIDC interaction.
 *     security: []
 *     parameters:
 *       - in: path
 *         name: uid
 *         required: true
 *         schema:
 *           type: string
 *         description: Interaction UID
 *     responses:
 *       200:
 *         description: Interaction aborted successfully.
 *       400:
 *         description: Bad request.
 *       500:
 *         description: Internal server error.
 */

/**
 * @openapi
 * /oidc/interaction/{uid}/mfa:
 *   post:
 *     tags:
 *       - OIDC APIs
 *     summary: Submit MFA for OIDC interaction
 *     description: Verifies MFA code and completes the OIDC login.
 *     security: []
 *     parameters:
 *       - in: path
 *         name: uid
 *         required: true
 *         schema:
 *           type: string
 *         description: Interaction UID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - code
 *             properties:
 *               code:
 *                 type: string
 *                 description: OTP code
 *     responses:
 *       200:
 *         description: MFA verified and login successful.
 *       400:
 *         description: Invalid code.
 *       500:
 *         description: Internal server error.
 */

/**
 * @openapi
 * /oidc/.well-known/openid-configuration:
 *   get:
 *     tags:
 *       - OIDC Provider APIs
 *     summary: OIDC Discovery Configuration
 *     description: Returns the OIDC Provider configuration and supported metadata.
 *     security: []
 *     responses:
 *       200:
 *         description: Discovery configuration returned.
 *
 * /oidc/jwks:
 *   get:
 *     tags:
 *       - OIDC Provider APIs
 *     summary: JSON Web Key Set (JWKS)
 *     description: Returns the public keys used to verify tokens signed by this provider.
 *     security: []
 *     responses:
 *       200:
 *         description: JWKS returned.
 *
 * /oidc/auth:
 *   get:
 *     tags:
 *       - OIDC Provider APIs
 *     summary: OIDC Authorization Endpoint
 *     description: Starts the OIDC Authorization Code flow. Redirects to interaction endpoints if login/consent is needed.
 *     security: []
 *     parameters:
 *       - in: query
 *         name: client_id
 *         required: true
 *         schema:
 *           type: string
 *       - in: query
 *         name: response_type
 *         required: true
 *         schema:
 *           type: string
 *       - in: query
 *         name: scope
 *         required: true
 *         schema:
 *           type: string
 *       - in: query
 *         name: redirect_uri
 *         required: true
 *         schema:
 *           type: string
 *       - in: query
 *         name: state
 *         required: false
 *         schema:
 *           type: string
 *     responses:
 *       302:
 *         description: Redirects to login, consent or redirect_uri.
 *
 * /oidc/token:
 *   post:
 *     tags:
 *       - OIDC Provider APIs
 *     summary: OIDC Token Endpoint
 *     description: Exchanges an Authorization Code for Access, Refresh, and ID Tokens.
 *     security:
 *       - basicAuth: []
 *     requestBody:
 *       content:
 *         application/x-www-form-urlencoded:
 *           schema:
 *             type: object
 *             properties:
 *               grant_type:
 *                 type: string
 *               code:
 *                 type: string
 *               redirect_uri:
 *                 type: string
 *               code_verifier:
 *                 type: string
 *               refresh_token:
 *                 type: string
 *     responses:
 *       200:
 *         description: Tokens returned successfully.
 *
 * /oidc/me:
 *   get:
 *     tags:
 *       - OIDC Provider APIs
 *     summary: OIDC UserInfo Endpoint
 *     description: "Returns claims about the authenticated user."
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: UserInfo returned successfully.
 *
 * /oidc/token/introspection:
 *   post:
 *     tags:
 *       - OIDC Provider APIs
 *     summary: Token Introspection
 *     description: Validates a token and returns its active state and meta-information.
 *     security:
 *       - basicAuth: []
 *     requestBody:
 *       content:
 *         application/x-www-form-urlencoded:
 *           schema:
 *             type: object
 *             required:
 *               - token
 *             properties:
 *               token:
 *                 type: string
 *     responses:
 *       200:
 *         description: Token introspection results.
 *
 * /oidc/token/revocation:
 *   post:
 *     tags:
 *       - OIDC Provider APIs
 *     summary: Token Revocation
 *     description: Revokes a given token.
 *     security:
 *       - basicAuth: []
 *     requestBody:
 *       content:
 *         application/x-www-form-urlencoded:
 *           schema:
 *             type: object
 *             required:
 *               - token
 *             properties:
 *               token:
 *                 type: string
 *     responses:
 *       200:
 *         description: Token revoked successfully.
 */
