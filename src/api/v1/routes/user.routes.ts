import { Router } from 'express';

import { userController } from '../modules/user.module';

const userRoutes = Router();

userRoutes.get('/me', userController.currentUser);

export default userRoutes;
