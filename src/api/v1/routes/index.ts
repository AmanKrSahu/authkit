import { authenticateJWT } from '@core/common/strategies/jwt.strategy';
import { Router } from 'express';

import authRoutes from './auth.routes';
import healthRoutes from './health.routes';
import mfaRoutes from './mfa.routes';
import oauthRoutes from './oauth.route';
import sessionRoutes from './session.routes';
import userRoutes from './user.routes';

const router = Router();

router.use('/', healthRoutes);

router.use('/auth/', authRoutes);
router.use('/oauth/', oauthRoutes);

router.use('/mfa/', mfaRoutes);

router.use('/session/', authenticateJWT, sessionRoutes);

router.use('/user/', authenticateJWT, userRoutes);

export default router;
