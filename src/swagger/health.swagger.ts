/**
 * @openapi
 * /:
 *   get:
 *     tags:
 *       - Health APIs
 *     summary: Check system status
 *     description: Returns a simple message indicating the server is running.
 *     security: []
 *     responses:
 *       200:
 *         description: Server started successfully
 *       500:
 *         description: Internal server error
 *       503:
 *         description: Service unavailable
 */

/**
 * @openapi
 * /health:
 *   get:
 *     tags:
 *       - Health APIs
 *     summary: Basic health check
 *     description: Checks the basic health of the application services.
 *     security: []
 *     responses:
 *       200:
 *         description: Server is healthy
 *       500:
 *         description: Internal server error
 *       503:
 *         description: Service unavailable
 */

/**
 * @openapi
 * /health/detailed:
 *   get:
 *     tags:
 *       - Health APIs
 *     summary: Detailed health check
 *     description: Provides a detailed health report including external dependencies.
 *     security: []
 *     responses:
 *       200:
 *         description: Detailed health check completed
 *       500:
 *         description: Internal server error
 *       503:
 *         description: Service unavailable
 */
