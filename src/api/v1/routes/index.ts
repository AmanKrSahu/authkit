import { authenticateJWT } from '@core/common/strategies/jwt.strategy';
import { Role } from '@prisma/client';
import { Router } from 'express';

import { oidcRateLimiter } from '../middlewares/rate-limiter.middleware';
import { roleGuard } from '../middlewares/role.middleware';
import { oidcService } from '../modules/oidc.module';
import adminRoutes from './admin.routes';
import authRoutes from './auth.routes';
import healthRoutes from './health.routes';
import magicLinkRoutes from './magic-link.routes';
import mfaRoutes from './mfa.routes';
import oauthRoutes from './oauth.route';
import oidcRoutes from './oidc.routes';
import sessionRoutes from './session.routes';
import userRoutes from './user.routes';

const router = Router();

router.use('/', healthRoutes);

// 1. Custom UI Routes FIRST (Interactions, Login Page)
router.use('/oidc', oidcRateLimiter, oidcRoutes);

// 2. OIDC Engine SECOND (The "Catch-all" for standard OIDC endpoints)
router.use('/oidc', oidcService.getProvider().callback());

router.use('/auth/', authRoutes);
router.use('/oauth/', oauthRoutes);
router.use('/magic-link', magicLinkRoutes);

router.use('/mfa/', mfaRoutes);

router.use('/session/', authenticateJWT, sessionRoutes);

router.use('/user/', authenticateJWT, userRoutes);

router.use('/admin/', authenticateJWT, roleGuard(Role.ADMIN), adminRoutes);

export default router;
