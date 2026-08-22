/**
 * In-memory PrismaClient mock implementation for unit, integration, and E2E testing.
 * Exports createInMemoryPrismaClient for stateful in-memory integration/E2E test runs,
 * and prismaMock DeepMockProxy for isolated unit test mocking.
 */
import type { PrismaClient } from '@prisma/client';
import { mockDeep, mockReset, type DeepMockProxy } from 'vitest-mock-extended';
import { beforeEach } from 'vitest';

export const createInMemoryPrismaClient = (): PrismaClient => {
  const store: Record<string, Map<string, any>> = {
    user: new Map(),
    session: new Map(),
    account: new Map(),
    oidcClient: new Map(),
    auditLog: new Map(),
  };

  const getModelStore = (modelName: string) => {
    if (!store[modelName]) store[modelName] = new Map();
    return store[modelName];
  };

  const attachRelations = (modelName: string, record: any, _include?: any) => {
    if (!record) return null;
    const copy = { ...record };
    if (modelName === 'user') {
      const userAccs = [...getModelStore('account').values()].filter(a => a.userId === record.id);
      copy.accounts = userAccs;
    }
    if (modelName === 'session') {
      const userRec = getModelStore('user').get(record.userId);
      if (userRec) {
        copy.user = {
          id: userRec.id,
          email: userRec.email,
          role: userRec.role,
          name: userRec.name,
          enable2FA: userRec.enable2FA ?? false,
        };
      }
    }
    return copy;
  };

  const createModelMock = (modelName: string) => ({
    create: async ({ data, include }: any) => {
      const mStore = getModelStore(modelName);
      const id = data.id || `mock_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
      const { accounts, ...restData } = data;
      const record = { id, createdAt: new Date(), updatedAt: new Date(), ...restData };
      mStore.set(id, record);

      if (accounts?.create) {
        const accData = Array.isArray(accounts.create) ? accounts.create : [accounts.create];
        for (const acc of accData) {
          const accId = acc.id || `acc_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
          const accRecord = {
            id: accId,
            userId: id,
            createdAt: new Date(),
            updatedAt: new Date(),
            ...acc,
          };
          getModelStore('account').set(accId, accRecord);
        }
      }

      return attachRelations(modelName, record, include);
    },
    findUnique: async ({ where, include }: any) => {
      const mStore = getModelStore(modelName);
      for (const item of mStore.values()) {
        if (where.id && item.id === where.id) return attachRelations(modelName, item, include);
        if (where.email && item.email === where.email)
          return attachRelations(modelName, item, include);
        if (where.clientId && item.clientId === where.clientId)
          return attachRelations(modelName, item, include);
        if (where.sessionToken && item.sessionToken === where.sessionToken)
          return attachRelations(modelName, item, include);
      }
      return null;
    },
    findFirst: async ({ where, include }: any) => {
      const mStore = getModelStore(modelName);
      if (!where) {
        const first = mStore.values().next().value || null;
        return attachRelations(modelName, first, include);
      }
      for (const item of mStore.values()) {
        let match = true;
        for (const [k, v] of Object.entries(where)) {
          if (item[k] !== v) {
            match = false;
            break;
          }
        }
        if (match) return attachRelations(modelName, item, include);
      }
      return null;
    },
    findMany: async (args?: any) => {
      const mStore = getModelStore(modelName);
      let list = [...mStore.values()];
      if (args?.where) {
        list = list.filter(item => {
          for (const [k, v] of Object.entries(args.where)) {
            if (v === undefined) continue;
            if (k === 'createdAt' && typeof v === 'object' && v !== null) {
              const itemTime = new Date(item.createdAt).getTime();
              const { gte, lte } = v as any;
              if (gte && itemTime < new Date(gte).getTime()) return false;
              if (lte && itemTime > new Date(lte).getTime()) return false;
              continue;
            }
            if (item[k] !== v) return false;
          }
          return true;
        });
      }
      return list.map(item => attachRelations(modelName, item, args?.include));
    },
    update: async ({ where, data, include }: any) => {
      const mStore = getModelStore(modelName);
      let targetRecord: any = null;
      for (const item of mStore.values()) {
        if (where.id && item.id === where.id) {
          targetRecord = item;
          break;
        }
        if (where.email && item.email === where.email) {
          targetRecord = item;
          break;
        }
      }
      if (!targetRecord) return null;

      const { accounts, ...restData } = data;
      Object.assign(targetRecord, restData, { updatedAt: new Date() });

      if (accounts?.create) {
        const accData = Array.isArray(accounts.create) ? accounts.create : [accounts.create];
        for (const acc of accData) {
          const accId = acc.id || `acc_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
          const accRecord = {
            id: accId,
            userId: targetRecord.id,
            createdAt: new Date(),
            updatedAt: new Date(),
            ...acc,
          };
          getModelStore('account').set(accId, accRecord);
        }
      }

      return attachRelations(modelName, targetRecord, include);
    },
    updateMany: async (args?: any) => {
      const mStore = getModelStore(modelName);
      let count = 0;
      for (const item of mStore.values()) {
        let match = true;
        if (args?.where) {
          for (const [k, v] of Object.entries(args.where)) {
            if (item[k] !== v) {
              match = false;
              break;
            }
          }
        }
        if (match) {
          Object.assign(item, args?.data, { updatedAt: new Date() });
          count++;
        }
      }
      return { count };
    },
    delete: async ({ where }: any) => {
      const mStore = getModelStore(modelName);
      let targetRecord: any = null;
      for (const item of mStore.values()) {
        if (where.id && item.id === where.id) {
          targetRecord = item;
          break;
        }
        if (where.email && item.email === where.email) {
          targetRecord = item;
          break;
        }
      }
      if (targetRecord) mStore.delete(targetRecord.id);
      return targetRecord;
    },
    deleteMany: async (args?: any) => {
      const mStore = getModelStore(modelName);
      if (!args?.where || Object.keys(args.where).length === 0) {
        const count = mStore.size;
        mStore.clear();
        return { count };
      }
      let count = 0;
      for (const [id, item] of mStore.entries()) {
        let match = true;
        for (const [k, v] of Object.entries(args.where)) {
          if (item[k] !== v) {
            match = false;
            break;
          }
        }
        if (match) {
          mStore.delete(id);
          count++;
        }
      }
      return { count };
    },
    count: async (args?: any) => {
      const mStore = getModelStore(modelName);
      let list = [...mStore.values()];
      if (args?.where) {
        list = list.filter(item => {
          for (const [k, v] of Object.entries(args.where)) {
            if (v === undefined) continue;
            if (k === 'createdAt' && typeof v === 'object' && v !== null) {
              const itemTime = new Date(item.createdAt).getTime();
              const { gte, lte } = v as any;
              if (gte && itemTime < new Date(gte).getTime()) return false;
              if (lte && itemTime > new Date(lte).getTime()) return false;
              continue;
            }
            if (item[k] !== v) return false;
          }
          return true;
        });
      }
      return list.length;
    },
  });

  const mockClient = {
    user: createModelMock('user'),
    session: createModelMock('session'),
    account: createModelMock('account'),
    oidcClient: createModelMock('oidcClient'),
    auditLog: createModelMock('auditLog'),
    $transaction: async (cb: any) => {
      if (typeof cb === 'function') {
        return await cb(mockClient);
      }
      if (Array.isArray(cb)) {
        return await Promise.all(cb);
      }
      return null;
    },
    $executeRawUnsafe: async () => 0,
    $connect: async () => {},
    $disconnect: async () => {},
  };

  return mockClient as unknown as PrismaClient;
};

export const prismaMock: DeepMockProxy<PrismaClient> = mockDeep<PrismaClient>();

beforeEach(() => {
  mockReset(prismaMock);
});
