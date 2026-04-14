import { Router } from 'express';

import { adminController } from '../modules/admin.module';

const adminRoutes = Router();

adminRoutes.post('/users/promote', adminController.promoteUserToAdmin);
adminRoutes.delete('/users/:userId', adminController.deleteUser);

adminRoutes.delete('/sessions/user/:userId', adminController.revokeSessionsByUserId);
adminRoutes.delete('/sessions/:sessionId', adminController.revokeSessionById);

adminRoutes.post('/oidc/clients', adminController.registerOidcClient);

export default adminRoutes;
