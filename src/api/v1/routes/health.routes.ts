import { Router } from 'express';

import { healthController } from '../modules/health.module';

const healthRoutes = Router();

healthRoutes.get('/', healthController.initialise);
healthRoutes.get('/health', healthController.health);
healthRoutes.get('/health/detailed', healthController.detailedHealth);

export default healthRoutes;
