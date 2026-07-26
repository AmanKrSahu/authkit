import { Router } from 'express';

import { authRateLimiter } from '../middlewares/rate-limiter.middleware';
import { magicLinkController } from '../modules/magic-link.module';

const magicLinkRoutes = Router();

magicLinkRoutes.post('/login', authRateLimiter, magicLinkController.login);
magicLinkRoutes.post('/verify', authRateLimiter, magicLinkController.verify);

export default magicLinkRoutes;
