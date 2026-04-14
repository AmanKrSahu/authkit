/**
 * @openapi
 * /session/:
 *   get:
 *     tags:
 *       - Session APIs
 *     summary: Get all active sessions
 *     description: Retrieves a list of all active sessions for the current user.
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Sessions retrieved successfully
 *       401:
 *         description: User not authenticated
 *       500:
 *         description: Internal server error
 */

/**
 * @openapi
 * /session/{sessionId}:
 *   get:
 *     tags:
 *       - Session APIs
 *     summary: Get session by ID
 *     description: Retrieves details of a specific session.
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: sessionId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Session retrieved successfully
 *       401:
 *         description: User not authenticated
 *       404:
 *         description: Session not found
 *       500:
 *         description: Internal server error
 */

/**
 * @openapi
 * /session/:
 *   delete:
 *     tags:
 *       - Session APIs
 *     summary: Revoke all other sessions
 *     description: Revokes all active sessions except the current one.
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: All other sessions revoked successfully
 *       401:
 *         description: User not authenticated
 *       500:
 *         description: Internal server error
 */

/**
 * @openapi
 * /session/{sessionId}:
 *   delete:
 *     tags:
 *       - Session APIs
 *     summary: Revoke session by ID
 *     description: Revokes a specific session.
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: sessionId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Session revoked successfully
 *       400:
 *         description: Cannot revoke current session
 *       401:
 *         description: User not authenticated
 *       404:
 *         description: Session not found
 *       500:
 *         description: Internal server error
 */
