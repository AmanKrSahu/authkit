/**
 * @openapi
 * /magic-link/login:
 *   post:
 *     tags:
 *       - Magic Link APIs
 *     summary: Login with Magic Link
 *     description: Sends a magic link to the user's email address. Optionally accepts an OIDC interaction UID.
 *     security: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *               uid:
 *                 type: string
 *                 description: Optional OIDC interaction UID
 *     responses:
 *       200:
 *         description: Magic link sent successfully
 *       400:
 *         description: Invalid input data
 *       500:
 *         description: Internal server error
 */

/**
 * @openapi
 * /magic-link/verify:
 *   post:
 *     tags:
 *       - Magic Link APIs
 *     summary: Verify Magic Link
 *     description: Verifies the magic link token and authenticates the user. Resumes OIDC flow if uid is present.
 *     security: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - token
 *             properties:
 *               token:
 *                 type: string
 *     responses:
 *       200:
 *         description: Login successful or MFA required.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 message:
 *                   type: string
 *                 mfaRequired:
 *                   type: boolean
 *                 uid:
 *                   type: string
 *                 data:
 *                   type: object
 *       400:
 *         description: Invalid or expired token
 *       404:
 *         description: User not found
 *       500:
 *         description: Internal server error
 */
