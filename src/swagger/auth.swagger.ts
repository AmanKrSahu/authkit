/**
 * @openapi
 * /auth/register:
 *   post:
 *     tags:
 *       - Auth APIs
 *     summary: Register a new user
 *     description: Creates a new user account and sends a verification email.
 *     security: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - name
 *               - email
 *               - password
 *               - confirmPassword
 *             properties:
 *               name:
 *                 type: string
 *               email:
 *                 type: string
 *                 format: email
 *               password:
 *                 type: string
 *                 format: password
 *               confirmPassword:
 *                 type: string
 *                 format: password
 *               redirectUrl:
 *                 type: string
 *                 format: uri
 *     responses:
 *       201:
 *         description: User registered successfully
 *       400:
 *         description: Bad request - Invalid input data
 *       409:
 *         description: Conflict - Email already exists
 *       500:
 *         description: Internal server error
 */

/**
 * @openapi
 * /auth/verify-email:
 *   post:
 *     tags:
 *       - Auth APIs
 *     summary: Verify email address
 *     description: Verifies the user's email address using a code.
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
 *       201:
 *         description: Email verified successfully
 *       400:
 *         description: Invalid or missing token
 *       404:
 *         description: User not found or already verified
 *       500:
 *         description: Internal server error
 */

/**
 * @openapi
 * /auth/resend-verification:
 *   post:
 *     tags:
 *       - Auth APIs
 *     summary: Resend verification email
 *     description: Resends the verification email to the user's email address.
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
 *               redirectUrl:
 *                 type: string
 *                 format: uri
 *     responses:
 *       201:
 *         description: Verification email sent successfully
 *       400:
 *         description: Invalid email address
 *       404:
 *         description: User not found
 *       500:
 *         description: Internal server error
 */

/**
 * @openapi
 * /auth/login:
 *   post:
 *     tags:
 *       - Auth APIs
 *     summary: Login user
 *     description: Authenticates a user and returns access/refresh tokens.
 *     security: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *               password:
 *                 type: string
 *                 format: password
 *     responses:
 *       200:
 *         description: Login successful
 *       401:
 *         description: Invalid credentials
 *       403:
 *         description: Account not verified
 *       500:
 *         description: Internal server error
 */

/**
 * @openapi
 * /auth/logout:
 *   post:
 *     tags:
 *       - Auth APIs
 *     summary: Logout user
 *     description: Logs out the authenticated user and clears session.
 *     security:
 *       - bearerAuth: []
 *       - csrfAuth: []
 *     responses:
 *       200:
 *         description: Logged out successfully
 *       401:
 *         description: User not authenticated
 *       500:
 *         description: Internal server error
 */

/**
 * @openapi
 * /auth/refresh-token:
 *   post:
 *     tags:
 *       - Auth APIs
 *     summary: Refresh access token
 *     description: Generates a new access token using a refresh token.
 *     security:
 *       - csrfAuth: []
 *     responses:
 *       200:
 *         description: Token refreshed successfully
 *       401:
 *         description: Invalid or missing refresh token
 *       403:
 *         description: Refresh token expired or reused
 *       500:
 *         description: Internal server error
 */

/**
 * @openapi
 * /auth/forgot-password:
 *   post:
 *     tags:
 *       - Auth APIs
 *     summary: Forgot password
 *     description: Sends a password reset OTP to the user's email.
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
 *     responses:
 *       200:
 *         description: OTP sent successfully
 *       400:
 *         description: Invalid email or user not found
 *       429:
 *         description: Too many requests
 *       500:
 *         description: Internal server error
 */

/**
 * @openapi
 * /auth/verify-otp:
 *   post:
 *     tags:
 *       - Auth APIs
 *     summary: Verify OTP
 *     description: Verifies the OTP sent to the user's email.
 *     security: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - otp
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *               otp:
 *                 type: string
 *     responses:
 *       200:
 *         description: OTP verified successfully
 *       400:
 *         description: Invalid OTP or email
 *       410:
 *         description: OTP expired
 *       500:
 *         description: Internal server error
 */

/**
 * @openapi
 * /auth/reset-password:
 *   post:
 *     tags:
 *       - Auth APIs
 *     summary: Reset password
 *     description: Resets the user's password using the verified token.
 *     security:
 *       - csrfAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *               - confirmPassword
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *               password:
 *                 type: string
 *                 format: password
 *               confirmPassword:
 *                 type: string
 *                 format: password
 *     responses:
 *       200:
 *         description: Password reset successfully
 *       400:
 *         description: Passwords do not match or invalid input
 *       401:
 *         description: Invalid or expired reset token
 *       500:
 *         description: Internal server error
 */

/**
 * @openapi
 * /auth/change-password:
 *   post:
 *     tags:
 *       - Auth APIs
 *     summary: Change password
 *     description: Changes the user's password.
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - currentPassword
 *               - newPassword
 *             properties:
 *               currentPassword:
 *                 type: string
 *                 format: password
 *               newPassword:
 *                 type: string
 *                 format: password
 *     responses:
 *       200:
 *         description: Password changed successfully
 *       400:
 *         description: Invalid current password
 *       401:
 *         description: User not authenticated
 *       500:
 *         description: Internal server error
 */
