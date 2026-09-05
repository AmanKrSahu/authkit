/**
 * @openapi
 * /webauthn/register/options:
 *   post:
 *     tags:
 *       - WebAuthn & Passkeys
 *     summary: Generate WebAuthn registration options
 *     description: Generates cryptographic options and random challenge for registering a new passkey.
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Registration options generated successfully
 *       401:
 *         description: User not authenticated
 *       500:
 *         description: Internal server error
 */

/**
 * @openapi
 * /webauthn/register/verify:
 *   post:
 *     tags:
 *       - WebAuthn & Passkeys
 *     summary: Verify WebAuthn registration
 *     description: Verifies authenticator attestation response and persists the passkey credential.
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - response
 *             properties:
 *               name:
 *                 type: string
 *                 description: User-friendly label for the passkey
 *                 example: MacBook Touch ID
 *               response:
 *                 type: object
 *                 description: Registration response from navigator.credentials.create()
 *     responses:
 *       201:
 *         description: Passkey registered successfully
 *       400:
 *         description: Verification failed or credential already registered
 *       401:
 *         description: User not authenticated
 *       500:
 *         description: Internal server error
 */

/**
 * @openapi
 * /webauthn/authenticate/options:
 *   post:
 *     tags:
 *       - WebAuthn & Passkeys
 *     summary: Generate WebAuthn authentication options
 *     description: Generates assertion options and random challenge for passwordless passkey login.
 *     security: []
 *     requestBody:
 *       required: false
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 description: Optional user email for identified-user passkey login
 *                 example: user@example.com
 *     responses:
 *       200:
 *         description: Authentication options generated successfully
 *       500:
 *         description: Internal server error
 */

/**
 * @openapi
 * /webauthn/authenticate/verify:
 *   post:
 *     tags:
 *       - WebAuthn & Passkeys
 *     summary: Verify WebAuthn authentication
 *     description: Verifies passkey assertion, logs in user, creates session, and issues tokens.
 *     security: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - response
 *             properties:
 *               response:
 *                 type: object
 *                 description: Authentication response from navigator.credentials.get()
 *     responses:
 *       200:
 *         description: User signed in successfully via passkey
 *       400:
 *         description: Assertion verification failed or challenge expired
 *       404:
 *         description: Passkey credential not found
 *       500:
 *         description: Internal server error
 */

/**
 * @openapi
 * /webauthn/authenticate/verify-mfa:
 *   post:
 *     tags:
 *       - WebAuthn & Passkeys
 *     summary: Verify WebAuthn MFA factor
 *     description: Verifies passkey assertion as a secondary factor during MFA challenge.
 *     security: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - response
 *             properties:
 *               response:
 *                 type: object
 *                 description: Authentication response from navigator.credentials.get()
 *     responses:
 *       200:
 *         description: MFA verified successfully via passkey
 *       400:
 *         description: Assertion verification failed or challenge expired
 *       401:
 *         description: MFA session expired or invalid
 *       500:
 *         description: Internal server error
 */

/**
 * @openapi
 * /webauthn/authenticators:
 *   get:
 *     tags:
 *       - WebAuthn & Passkeys
 *     summary: List registered passkeys
 *     description: Returns all passkey authenticators registered to the authenticated user.
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of authenticators retrieved successfully
 *       401:
 *         description: User not authenticated
 *       500:
 *         description: Internal server error
 */

/**
 * @openapi
 * /webauthn/authenticators/{id}:
 *   delete:
 *     tags:
 *       - WebAuthn & Passkeys
 *     summary: Delete a registered passkey
 *     description: Deletes a passkey authenticator owned by the authenticated user.
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Authenticator ID
 *     responses:
 *       200:
 *         description: Passkey deleted successfully
 *       401:
 *         description: User not authenticated
 *       404:
 *         description: Authenticator not found
 *       500:
 *         description: Internal server error
 *   patch:
 *     tags:
 *       - WebAuthn & Passkeys
 *     summary: Update passkey name
 *     description: Updates the friendly name/label of a registered passkey.
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Authenticator ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - name
 *             properties:
 *               name:
 *                 type: string
 *                 example: My Security Key
 *     responses:
 *       200:
 *         description: Passkey name updated successfully
 *       401:
 *         description: User not authenticated
 *       404:
 *         description: Authenticator not found
 *       500:
 *         description: Internal server error
 */
