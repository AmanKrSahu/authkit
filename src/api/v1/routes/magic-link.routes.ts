import { Router } from 'express';

import { magicLinkController } from '../modules/magic-link.module';

const magicLinkRoutes = Router();

magicLinkRoutes.post('/login', magicLinkController.login);
magicLinkRoutes.post('/verify', magicLinkController.verify);

export default magicLinkRoutes;
