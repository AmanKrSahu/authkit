/**
 * @openapi
 * /user/me:
 *   get:
 *     tags:
 *       - User APIs
 *     summary: Get current user
 *     description: Retrieves the profile of the currently authenticated user.
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User retrieved successfully
 *       401:
 *         description: User not authenticated
 *       404:
 *         description: User not found
 *       500:
 *         description: Internal server error
 */
