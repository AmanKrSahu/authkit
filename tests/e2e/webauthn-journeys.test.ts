import { Role } from '@prisma/client';
import request from 'supertest';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { createUserFactory } from '@tests/factories/user.factory';
import { startTestContainer, stopTestContainer } from '@tests/helpers/container.helper';
import { cleanDb } from '@tests/helpers/db.helper';
import { cleanRedis } from '@tests/helpers/redis.helper';
import { TEST_ORIGIN } from '@tests/helpers/request.helper';
import { MockEmailService } from '@tests/mocks/resend';

vi.mock('@core/mailers/resend', () => ({
  EmailService: MockEmailService,
}));

describe('WebAuthn & Passkeys End-to-End User Journeys', () => {
  let app: any;
  let userToken: string;
  let user: any;

  beforeAll(async () => {
    await startTestContainer();
    app = (await import('@api/app')).app;
    return async () => {
      await stopTestContainer();
    };
  });

  beforeEach(async () => {
    await cleanDb();
    await cleanRedis();

    user = await createUserFactory({
      email: 'passkey_journey@example.com',
      password: 'Password123!',
      role: Role.USER,
      emailVerified: true,
    });

    const loginRes = await request(app).post('/api/v1/auth/login').set('Origin', TEST_ORIGIN).send({
      email: 'passkey_journey@example.com',
      password: 'Password123!',
    });

    userToken = loginRes.body.data.accessToken;
  });

  it('should complete registration options request, list authenticators, and manage labels', async () => {
    // 1. Generate registration options
    const regOptionsRes = await request(app)
      .post('/api/v1/webauthn/register/options')
      .set('Origin', TEST_ORIGIN)
      .set('Authorization', `Bearer ${userToken}`);

    expect(regOptionsRes.status).toBe(200);
    expect(regOptionsRes.body.data.options.challenge).toBeDefined();

    // 2. Direct database seed of a verified authenticator to simulate completed client ceremony
    const prismaClient = (await import('@core/database/prisma')).default;
    const authenticator = await prismaClient.authenticator.create({
      data: {
        userId: user.id,
        credentialId: 'e2e_passkey_cred_1',
        credentialPublicKey: Buffer.from([1, 2, 3, 4, 5]),
        counter: BigInt(0),
        transports: ['internal'],
        name: 'MacBook TouchID',
        deviceType: 'multiDevice',
        backedUp: true,
      },
    });

    // 3. List authenticators
    const listRes = await request(app)
      .get('/api/v1/webauthn/authenticators')
      .set('Origin', TEST_ORIGIN)
      .set('Authorization', `Bearer ${userToken}`);

    expect(listRes.status).toBe(200);
    expect(listRes.body.data.authenticators).toHaveLength(1);
    expect(listRes.body.data.authenticators[0].name).toBe('MacBook TouchID');

    // 4. Update authenticator label
    const patchRes = await request(app)
      .patch(`/api/v1/webauthn/authenticators/${authenticator.id}`)
      .set('Origin', TEST_ORIGIN)
      .set('Authorization', `Bearer ${userToken}`)
      .send({ name: 'Work Laptop Passkey' });

    expect(patchRes.status).toBe(200);
    expect(patchRes.body.data.authenticator.name).toBe('Work Laptop Passkey');

    // 5. Delete authenticator
    const delRes = await request(app)
      .delete(`/api/v1/webauthn/authenticators/${authenticator.id}`)
      .set('Origin', TEST_ORIGIN)
      .set('Authorization', `Bearer ${userToken}`);

    expect(delRes.status).toBe(200);

    const listAfterDel = await request(app)
      .get('/api/v1/webauthn/authenticators')
      .set('Origin', TEST_ORIGIN)
      .set('Authorization', `Bearer ${userToken}`);

    expect(listAfterDel.body.data.authenticators).toHaveLength(0);
  });
});
