import { HealthController } from '../controllers/health.controller';
import { HealthService } from '../services/health.service';

const healthService = new HealthService();
const healthController = new HealthController(healthService);

export { healthController, healthService };
