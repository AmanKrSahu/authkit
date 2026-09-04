/**
 * @openapi
 * /admin/users:
 *   get:
 *     tags:
 *       - Admin APIs
 *     summary: Fetch all users
 *     description: Retrieves a list of all users using cursor-based pagination.
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: cursor
 *         required: false
 *         schema:
 *           type: string
 *         description: The unique user ID used as a cursor for pagination.
 *       - in: query
 *         name: limit
 *         required: false
 *         schema:
 *           type: integer
 *           default: 100
 *           maximum: 100
 *         description: The maximum number of users to return.
 *     responses:
 *       200:
 *         description: Users retrieved successfully
 *         headers:
 *           X-Total-Count:
 *             schema:
 *               type: integer
 *             description: Total count of users in the system.
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
 *                     users:
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
 *       403:
 *         description: Forbidden (Non-admin access)
 *       500:
 *         description: Internal server error
 */

/**
 * @openapi
 * /admin/users/{userId}:
 *   get:
 *     tags:
 *       - Admin APIs
 *     summary: Fetch a user by ID
 *     description: Retrieves details of a specific user.
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: userId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: User retrieved successfully
 *       400:
 *         description: Invalid User ID
 *       403:
 *         description: Forbidden
 *       404:
 *         description: User not found
 *       500:
 *         description: Internal server error
 */

/**
 * @openapi
 * /admin/sessions/user/{userId}:
 *   get:
 *     tags:
 *       - Admin APIs
 *     summary: Fetch all sessions of a user
 *     description: Retrieves all active sessions for a specific user using cursor-based pagination.
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: userId
 *         required: true
 *         schema:
 *           type: string
 *         description: The unique ID of the user.
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
 *         description: User sessions retrieved successfully
 *         headers:
 *           X-Total-Count:
 *             schema:
 *               type: integer
 *             description: Total count of active sessions for the user.
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
 *       400:
 *         description: Invalid User ID
 *       403:
 *         description: Forbidden
 *       404:
 *         description: User not found
 *       500:
 *         description: Internal server error
 */

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
 *     parameters:
 *       - in: path
 *         name: userId
 *         required: true
 *         schema:
 *           type: string
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
 *     parameters:
 *       - in: path
 *         name: userId
 *         required: true
 *         schema:
 *           type: string
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

/**
 * @openapi
 * /admin/audit-logs:
 *   get:
 *     tags:
 *       - Admin APIs
 *     summary: Fetch security audit logs
 *     description: Retrieves a paginated list of security audit logs with optional filters.
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: cursor
 *         required: false
 *         schema:
 *           type: string
 *         description: Cursor ID for pagination.
 *       - in: query
 *         name: limit
 *         required: false
 *         schema:
 *           type: integer
 *           default: 10
 *         description: Number of records to return.
 *       - in: query
 *         name: userId
 *         required: false
 *         schema:
 *           type: string
 *       - in: query
 *         name: action
 *         required: false
 *         schema:
 *           type: string
 *       - in: query
 *         name: entityType
 *         required: false
 *         schema:
 *           type: string
 *       - in: query
 *         name: entityId
 *         required: false
 *         schema:
 *           type: string
 *       - in: query
 *         name: status
 *         required: false
 *         schema:
 *           type: string
 *           enum: [SUCCESS, FAILURE]
 *       - in: query
 *         name: startDate
 *         required: false
 *         schema:
 *           type: string
 *           format: date-time
 *       - in: query
 *         name: endDate
 *         required: false
 *         schema:
 *           type: string
 *           format: date-time
 *     responses:
 *       200:
 *         description: Audit logs retrieved successfully
 *       403:
 *         description: Forbidden
 *       500:
 *         description: Internal server error
 */

/**
 * @openapi
 * /admin/audit-logs/{id}:
 *   get:
 *     tags:
 *       - Admin APIs
 *     summary: Fetch audit log details by ID
 *     description: Retrieves details of a specific security audit log entry.
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Audit log details retrieved successfully
 *       403:
 *         description: Forbidden
 *       404:
 *         description: Audit log entry not found
 *       500:
 *         description: Internal server error
 */
