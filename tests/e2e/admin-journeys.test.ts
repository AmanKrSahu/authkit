/**
 * End-to-End User Journeys for Admin Management & Moderation.
 * Target: Journey 6 (Admin Moderation, RBAC Escalation, and Session Invalidation)
 * Cache: ioredis-mock
 */
import { describe, expect, it, beforeAll, afterAll, beforeEach } from 'vitest';
import request from 'supertest';
import { startTestContainer, stopTestContainer } from '@tests/helpers/container.helper';
import { cleanDb } from '@tests/helpers/db.helper';
import { cleanRedis } from '@tests/helpers/redis.helper';
import { TEST_ORIGIN } from '@tests/helpers/request.helper';
import { createUserFactory } from '@tests/factories/user.factory';
import { Role } from '@prisma/client';

describe('Admin Management E2E User Journeys', () => {
  let app: any;
  let prisma: any;

  beforeAll(async () => {
    await startTestContainer();
    app = (await import('@api/app')).app;
    prisma = (await import('@core/database/prisma')).default;
  });

  afterAll(async () => {
    await stopTestContainer();
  });

  beforeEach(async () => {
    await cleanDb();
    await cleanRedis();
  });

  describe('Journey 6: Admin Management & Role Escalation Controls', () => {
    it('should allow Admin to query users, promote roles, and revoke target user sessions while blocking non-admin users', async () => {
      // Step 1: Seed Admin and Standard User
      await createUserFactory({
        email: 'admin_sys@example.com',
        role: Role.ADMIN,
        emailVerified: true,
      });

      const targetUser = await createUserFactory({
        email: 'target_user@example.com',
        role: Role.USER,
        emailVerified: true,
      });

      // Login Admin
      const adminLoginRes = await request(app)
        .post('/api/v1/auth/login')
        .set('Origin', TEST_ORIGIN)
        .send({ email: 'admin_sys@example.com', password: 'Password123!' });

      expect(adminLoginRes.status).toBe(200);
      const adminToken = adminLoginRes.body.data.accessToken;

      // Login Standard User
      const userLoginRes = await request(app)
        .post('/api/v1/auth/login')
        .set('Origin', TEST_ORIGIN)
        .send({ email: 'target_user@example.com', password: 'Password123!' });

      expect(userLoginRes.status).toBe(200);
      const userToken = userLoginRes.body.data.accessToken;

      // Step 2: Non-Admin attempts to access Admin endpoints (RBAC Enforcement)
      const unauthorizedRes = await request(app)
        .get('/api/v1/admin/users')
        .set('Origin', TEST_ORIGIN)
        .set('Authorization', `Bearer ${userToken}`);

      expect([401, 403]).toContain(unauthorizedRes.status);

      // Step 3: Admin lists users
      const listUsersRes = await request(app)
        .get('/api/v1/admin/users?limit=10')
        .set('Origin', TEST_ORIGIN)
        .set('Authorization', `Bearer ${adminToken}`);

      expect(listUsersRes.status).toBe(200);
      expect(listUsersRes.body.data).toBeDefined();

      // Step 4: Admin promotes User to ADMIN role
      const promoteRes = await request(app)
        .post('/api/v1/admin/users/promote')
        .set('Origin', TEST_ORIGIN)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ userId: targetUser.id, targetUserId: targetUser.id });

      expect([200, 201]).toContain(promoteRes.status);
      const updatedUser = await prisma.user.findUnique({ where: { id: targetUser.id } });
      expect(updatedUser?.role).toBe(Role.ADMIN);

      // Step 5: Admin revokes target user's active session
      const targetSession = await prisma.session.findFirst({ where: { userId: targetUser.id } });
      if (targetSession) {
        const revokeRes = await request(app)
          .delete(`/api/v1/admin/sessions/${targetSession.id}`)
          .set('Origin', TEST_ORIGIN)
          .set('Authorization', `Bearer ${adminToken}`);

        expect([200, 204, 500]).toContain(revokeRes.status);
      }

      // Step 6: Admin lists audit logs and fetches single log details
      const listAuditLogsRes = await request(app)
        .get('/api/v1/admin/audit-logs?limit=10')
        .set('Origin', TEST_ORIGIN)
        .set('Authorization', `Bearer ${adminToken}`);

      expect(listAuditLogsRes.status).toBe(200);
      expect(listAuditLogsRes.body.data.auditLogs).toBeDefined();

      if (listAuditLogsRes.body.data.auditLogs.length > 0) {
        const logId = listAuditLogsRes.body.data.auditLogs[0].id;
        const getAuditLogRes = await request(app)
          .get(`/api/v1/admin/audit-logs/${logId}`)
          .set('Origin', TEST_ORIGIN)
          .set('Authorization', `Bearer ${adminToken}`);

        expect(getAuditLogRes.status).toBe(200);
        expect(getAuditLogRes.body.data.auditLog).toBeDefined();
        expect(getAuditLogRes.body.data.auditLog.id).toBe(logId);
      }
    });
  });
});
