/**
 * @openapi
 * /oauth/google:
 *   get:
 *     tags:
 *       - OAuth APIs
 *     summary: Initiate Google OAuth
 *     description: Redirects the user to Google for authentication. In Swagger UI, this can be triggered via the "Authorize" button if googleOAuth is configured.
 *     security:
 *       - googleOAuth:
 *           - openid
 *           - profile
 *           - email
 *     responses:
 *       302:
 *         description: Redirect to Google Login
 */

/**
 * @openapi
 * /oauth/google/callback:
 *   get:
 *     tags:
 *       - OAuth APIs
 *     summary: Google OAuth callback
 *     description: Handles the callback from Google OAuth authentication.
 *     security: []
 *     parameters:
 *       - in: query
 *         name: code
 *         schema:
 *           type: string
 *         description: The authorization code returned by Google
 *       - in: query
 *         name: state
 *         schema:
 *           type: string
 *         description: The state parameter for CSRF protection
 *     responses:
 *       200:
 *         description: OAuth login successful, redirects to frontend
 *       401:
 *         description: Authentication failed
 *       500:
 *         description: Internal server error
 */
