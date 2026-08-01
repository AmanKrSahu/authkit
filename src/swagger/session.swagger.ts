/**
 * @openapi
 * /session/:
 *   get:
 *     tags:
 *       - Session APIs
 *     summary: Get all active sessions
 *     description: Retrieves all active sessions for the current user using cursor-based pagination.
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: cursor
 *         required: false
 *         schema:
 *           type: string
 *         description: The unique session ID used as a cursor for pagination.
 *       - in: query
 *         name: limit
 *         required: false
 *         schema:
 *           type: integer
 *           default: 100
 *           maximum: 100
 *         description: The maximum number of sessions to return.
 *     responses:
 *       200:
 *         description: Sessions retrieved successfully
 *         headers:
 *           X-Total-Count:
 *             schema:
 *               type: integer
 *             description: Total count of active sessions.
 *           X-Page-Count:
 *             schema:
 *               type: integer
 *             description: Total number of pages available based on the limit.
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
 *                     sessions:
 *                       type: array
 *                       items:
 *                         type: object
 *                     pagination:
 *                       type: object
 *                       properties:
 *                         cursor:
 *                           type: string
 *                           nullable: true
 *                         nextCursor:
 *                           type: string
 *                           nullable: true
 *                         hasMore:
 *                           type: boolean
 *                         limit:
 *                           type: integer
 *                         totalCount:
 *                           type: integer
 *                         totalPages:
 *                           type: integer
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
