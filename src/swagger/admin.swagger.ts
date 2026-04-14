/**
 * @openapi
 * /admin/users/promote:
 *   post:
 *     tags:
 *       - Admin APIs
 *     summary: Promote a user to Admin
 *     description: Promotes an existing user to the ADMIN role.
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - userId
 *             properties:
 *               userId:
 *                 type: string
 *     responses:
 *       200:
 *         description: User promoted successfully
 *       400:
 *         description: Invalid input or user not found
 *       403:
 *         description: Forbidden (Non-admin access)
 *       500:
 *         description: Internal server error
 */

/**
 * @openapi
 * /admin/users/{userId}:
 *   delete:
 *     tags:
 *       - Admin APIs
 *     summary: Delete a user
 *     description: Deletes a user account and all associated data.
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - userId
 *             properties:
 *               userId:
 *                 type: string
 *     responses:
 *       200:
 *         description: User deleted successfully
 *       400:
 *         description: Invalid User ID
 *       403:
 *         description: Forbidden
 *       500:
 *         description: Internal server error
 */

/**
 * @openapi
 * /admin/sessions/{sessionId}:
 *   delete:
 *     tags:
 *       - Admin APIs
 *     summary: Revoke session by ID
 *     description: Revokes a specific session.
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - sessionId
 *             properties:
 *               sessionId:
 *                 type: string
 *     responses:
 *       200:
 *         description: Session revoked successfully
 *       400:
 *         description: Invalid Session ID
 *       403:
 *         description: Forbidden
 *       500:
 *         description: Internal server error
 */

/**
 * @openapi
 * /admin/sessions/user/{userId}:
 *   delete:
 *     tags:
 *       - Admin APIs
 *     summary: Revoke all sessions for a user
 *     description: Revokes all active sessions for a specific user.
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - userId
 *             properties:
 *               userId:
 *                 type: string
 *     responses:
 *       200:
 *         description: User sessions revoked successfully
 *       400:
 *         description: Invalid User ID
 *       403:
 *         description: Forbidden
 *       500:
 *         description: Internal server error
 */

/**
 * @openapi
 * /admin/oidc/clients:
 *   post:
 *     tags:
 *       - Admin APIs
 *     summary: Register an OIDC Client
 *     description: Registers a new OIDC client and returns the generated Client ID and Client Secret. Ensure you save the secret as it will not be shown again.
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - clientName
 *               - redirectUrls
 *             properties:
 *               clientName:
 *                 type: string
 *               redirectUrls:
 *                 type: array
 *                 items:
 *                   type: string
 *               grantTypes:
 *                 type: array
 *                 items:
 *                   type: string
 *                 default: ["authorization_code", "refresh_token"]
 *               scope:
 *                 type: string
 *                 default: "openid profile email"
 *     responses:
 *       201:
 *         description: Client registered successfully with auto-generated Client ID and Secret
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 message:
 *                   type: string
 *                 data:
 *                   type: object
 *                   properties:
 *                     client:
 *                       type: object
 *                       properties:
 *                         id:
 *                           type: string
 *                         clientId:
 *                           type: string
 *                         clientName:
 *                           type: string
 *                         clientSecret:
 *                           type: string
 *                         redirectUrls:
 *                           type: array
 *                           items:
 *                             type: string
 *                         grantTypes:
 *                           type: array
 *                           items:
 *                             type: string
 *                         scope:
 *                           type: string
 *       400:
 *         description: Invalid input
 *       500:
 *         description: Internal server error
 */
