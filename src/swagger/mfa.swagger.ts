/**
 * @openapi
 * /mfa/setup:
 *   post:
 *     tags:
 *       - Multi-factor Authentication
 *     summary: Generate MFA setup
 *     description: Generates a QR code for setting up Multi-Factor Authentication.
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: MFA setup generated successfully
 *       401:
 *         description: User not authenticated
 *       500:
 *         description: Internal server error
 */

/**
 * @openapi
 * /mfa/verify-setup:
 *   post:
 *     tags:
 *       - Multi-factor Authentication
 *     summary: Verify MFA setup
 *     description: Verifies the MFA setup using a code and returns backup codes.
 *     security:
 *       - bearerAuth: []
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
 *     responses:
 *       200:
 *         description: MFA setup verified successfully
 *       400:
 *         description: Invalid code
 *       401:
 *         description: User not authenticated
 *       500:
 *         description: Internal server error
 */

/**
 * @openapi
 * /mfa/revoke:
 *   post:
 *     tags:
 *       - Multi-factor Authentication
 *     summary: Revoke MFA
 *     description: Revokes the MFA setup for the user.
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: MFA revoked successfully
 *       401:
 *         description: User not authenticated
 *       500:
 *         description: Internal server error
 */

/**
 * @openapi
 * /mfa/verify-login:
 *   post:
 *     tags:
 *       - Multi-factor Authentication
 *     summary: Verify MFA for login
 *     description: Verifies MFA code during login process.
 *     security: []
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
 *     responses:
 *       200:
 *         description: Login completed successfully
 *       401:
 *         description: Invalid code or token or User not authenticated
 *       403:
 *         description: MFA token expired
 *       500:
 *         description: Internal server error
 */
