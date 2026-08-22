import { Router } from 'express';

import { MagicLinkController } from '../controllers/magic-link.controller';
import { authRateLimiter } from '../middlewares/rate-limiter.middleware';

const magicLinkController = new MagicLinkController();

const magicLinkRoutes = Router();

magicLinkRoutes.post('/login', authRateLimiter, magicLinkController.login);
magicLinkRoutes.post('/verify', authRateLimiter, magicLinkController.verify);

export default magicLinkRoutes;
