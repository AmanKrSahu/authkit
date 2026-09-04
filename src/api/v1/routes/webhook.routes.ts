import { authenticateJWT } from '@core/common/strategies/jwt.strategy';
import { Role } from '@prisma/client';
import { Router } from 'express';

import { WebhookController } from '../controllers/webhook.controller';
import { roleGuard } from '../middlewares/role.middleware';

const webhookController = new WebhookController();

const webhookRoutes = Router();

// Gate all webhook admin endpoints with JWT authentication and Role.ADMIN authorization
webhookRoutes.use(authenticateJWT);
webhookRoutes.use(roleGuard(Role.ADMIN));

webhookRoutes.post('/', webhookController.createSubscription);
webhookRoutes.get('/', webhookController.getSubscriptions);
webhookRoutes.get('/:id', webhookController.getSubscriptionById);
webhookRoutes.patch('/:id', webhookController.updateSubscription);
webhookRoutes.delete('/:id', webhookController.deleteSubscription);
webhookRoutes.post('/:id/rotate-secret', webhookController.rotateSecret);
webhookRoutes.post('/:id/test', webhookController.testWebhook);
webhookRoutes.get('/:id/deliveries', webhookController.getDeliveries);
webhookRoutes.get('/:id/deliveries/:deliveryId', webhookController.getDeliveryById);

export default webhookRoutes;
