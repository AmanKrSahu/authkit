import { Router } from 'express';

import { AdminController } from '../controllers/admin.controller';

const adminController = new AdminController();

const adminRoutes = Router();

adminRoutes.post('/users/promote', adminController.promoteUserToAdmin);
adminRoutes.get('/users', adminController.getAllUsers);
adminRoutes.get('/users/:userId', adminController.getUserById);
adminRoutes.delete('/users/:userId', adminController.deleteUser);

adminRoutes.get('/sessions/user/:userId', adminController.getUserSessions);
adminRoutes.delete('/sessions/user/:userId', adminController.revokeSessionsByUserId);
adminRoutes.delete('/sessions/:sessionId', adminController.revokeSessionById);

adminRoutes.post('/oidc/clients', adminController.registerOidcClient);

adminRoutes.get('/audit-logs', adminController.getAuditLogs);
adminRoutes.get('/audit-logs/:id', adminController.getAuditLogById);

export default adminRoutes;
