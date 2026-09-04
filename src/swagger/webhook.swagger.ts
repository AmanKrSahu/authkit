/**
 * @openapi
 * /admin/webhooks:
 *   post:
 *     tags:
 *       - Admin - Webhooks
 *     summary: Create a webhook subscription
 *     description: Creates a new event webhook subscription. Generates a cryptographically secure signing secret.
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - name
 *               - url
 *               - events
 *             properties:
 *               name:
 *                 type: string
 *                 example: Production Audit Webhook
 *               url:
 *                 type: string
 *                 example: https://api.example.com/webhooks
 *               description:
 *                 type: string
 *                 example: Subscribes to user lifecycle events
 *               events:
 *                 type: array
 *                 items:
 *                   type: string
 *                 example: ["user.created", "user.deleted"]
 *     responses:
 *       201:
 *         description: Webhook subscription created successfully
 *       400:
 *         description: Invalid payload or SSRF restricted URL
 *       403:
 *         description: Forbidden (Admin access required)
 *       500:
 *         description: Internal server error
 *
 *   get:
 *     tags:
 *       - Admin - Webhooks
 *     summary: List webhook subscriptions
 *     description: Retrieves a paginated list of webhook subscriptions.
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: cursor
 *         required: false
 *         schema:
 *           type: string
 *       - in: query
 *         name: limit
 *         required: false
 *         schema:
 *           type: integer
 *           default: 10
 *       - in: query
 *         name: status
 *         required: false
 *         schema:
 *           type: string
 *           enum: [ACTIVE, PAUSED, DISABLED]
 *     responses:
 *       200:
 *         description: Webhook subscriptions retrieved successfully
 *       403:
 *         description: Forbidden
 *       500:
 *         description: Internal server error
 */

/**
 * @openapi
 * /admin/webhooks/{id}:
 *   get:
 *     tags:
 *       - Admin - Webhooks
 *     summary: Fetch webhook subscription details
 *     description: Retrieves details of a specific webhook subscription.
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
 *         description: Webhook subscription retrieved successfully
 *       404:
 *         description: Webhook subscription not found
 *
 *   patch:
 *     tags:
 *       - Admin - Webhooks
 *     summary: Update a webhook subscription
 *     description: Updates configuration, URL, events, or status for a webhook subscription.
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *               url:
 *                 type: string
 *               description:
 *                 type: string
 *               events:
 *                 type: array
 *                 items:
 *                   type: string
 *               status:
 *                 type: string
 *                 enum: [ACTIVE, PAUSED, DISABLED]
 *     responses:
 *       200:
 *         description: Webhook subscription updated successfully
 *       400:
 *         description: Invalid input or SSRF restricted URL
 *       404:
 *         description: Webhook subscription not found
 *
 *   delete:
 *     tags:
 *       - Admin - Webhooks
 *     summary: Delete a webhook subscription
 *     description: Permanently deletes a webhook subscription and its delivery history.
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
 *         description: Webhook subscription deleted successfully
 *       404:
 *         description: Webhook subscription not found
 */

/**
 * @openapi
 * /admin/webhooks/{id}/rotate-secret:
 *   post:
 *     tags:
 *       - Admin - Webhooks
 *     summary: Rotate webhook signing secret
 *     description: Rotates the signing secret for a webhook endpoint with a 24-hour dual-signature grace window.
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
 *         description: Signing secret rotated successfully
 *       404:
 *         description: Webhook subscription not found
 */

/**
 * @openapi
 * /admin/webhooks/{id}/test:
 *   post:
 *     tags:
 *       - Admin - Webhooks
 *     summary: Dispatch a test webhook event
 *     description: Triggers a signed `webhook.test` event delivery attempt to verify receiver endpoint health.
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
 *         description: Test event dispatched successfully
 *       404:
 *         description: Webhook subscription not found
 */

/**
 * @openapi
 * /admin/webhooks/{id}/deliveries:
 *   get:
 *     tags:
 *       - Admin - Webhooks
 *     summary: Fetch delivery history
 *     description: Retrieves paginated delivery history records for a webhook subscription.
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *       - in: query
 *         name: cursor
 *         required: false
 *         schema:
 *           type: string
 *       - in: query
 *         name: limit
 *         required: false
 *         schema:
 *           type: integer
 *           default: 10
 *       - in: query
 *         name: status
 *         required: false
 *         schema:
 *           type: string
 *           enum: [PENDING, SUCCESS, FAILURE, RETRIES_EXCEEDED]
 *     responses:
 *       200:
 *         description: Delivery records retrieved successfully
 *       404:
 *         description: Webhook subscription not found
 */

/**
 * @openapi
 * /admin/webhooks/{id}/deliveries/{deliveryId}:
 *   get:
 *     tags:
 *       - Admin - Webhooks
 *     summary: Fetch delivery attempt details
 *     description: Retrieves detailed information for a specific delivery attempt.
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *       - in: path
 *         name: deliveryId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Delivery attempt details retrieved successfully
 *       404:
 *         description: Webhook delivery record not found
 */
