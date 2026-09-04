import { Router } from 'express';

import { HealthController } from '../controllers/health.controller';

const healthController = new HealthController();

const healthRoutes = Router();

healthRoutes.get('/', healthController.initialise);
healthRoutes.get('/health', healthController.health);
healthRoutes.get('/health/detailed', healthController.detailedHealth);

export default healthRoutes;
