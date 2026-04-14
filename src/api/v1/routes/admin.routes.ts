import { Router } from 'express';

import { adminController } from '../modules/admin.module';

const adminRoutes = Router();

adminRoutes.post('/users/promote', adminController.promoteUserToAdmin);
adminRoutes.get('/users', adminController.getAllUsers);
adminRoutes.get('/users/:userId', adminController.getUserById);
adminRoutes.delete('/users/:userId', adminController.deleteUser);

adminRoutes.get('/sessions/user/:userId', adminController.getUserSessions);
adminRoutes.delete('/sessions/user/:userId', adminController.revokeSessionsByUserId);
adminRoutes.delete('/sessions/:sessionId', adminController.revokeSessionById);

adminRoutes.post('/oidc/clients', adminController.registerOidcClient);

export default adminRoutes;
