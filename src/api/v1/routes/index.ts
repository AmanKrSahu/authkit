import { authenticateJWT } from '@core/common/strategies/jwt.strategy';
import { Router } from 'express';

import authRoutes from './auth.routes';
import healthRoutes from './health.routes';
import sessionRoutes from './session.routes';
import userRoutes from './user.routes';

const router = Router();

router.use('/', healthRoutes);

router.use('/auth/', authRoutes);
router.use('/session/', authenticateJWT, sessionRoutes);

router.use('/user/', authenticateJWT, userRoutes);

export default router;
