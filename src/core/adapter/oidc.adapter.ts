import redisClient from '@core/database/redis';
import type { Adapter, AdapterPayload } from 'oidc-provider';

const grantable = new Set([
  'AccessToken',
  'AuthorizationCode',
  'RefreshToken',
  'DeviceCode',
  'BackchannelAuthenticationRequest',
  'Grant',
]);

export class RedisAdapter implements Adapter {
  private readonly name: string;

  constructor(name: string) {
    this.name = name;
  }

  public async upsert(id: string, payload: AdapterPayload, expiresIn: number): Promise<void> {
    const key = this.key(id);
    const store = grantable.has(this.name) ? { ...payload, grantId: payload.grantId } : payload;

    const multi = redisClient.multi();
    multi.set(key, JSON.stringify(store));

    if (expiresIn) {
      multi.expire(key, expiresIn);
    }

    if (payload.grantId) {
      const grantKey = grantKeyFor(payload.grantId);

      multi.rpush(grantKey, key);

      const ttl = await redisClient.ttl(grantKey);

      if (ttl < expiresIn) {
        multi.expire(grantKey, expiresIn);
      }
    }

    if (payload.userCode) {
      const userCodeKey = userCodeKeyFor(payload.userCode);

      multi.set(userCodeKey, id);
      multi.expire(userCodeKey, expiresIn);
    }

    if (payload.uid) {
      const uidKey = uidKeyFor(payload.uid);

      multi.set(uidKey, id);
      multi.expire(uidKey, expiresIn);
    }

    await multi.exec();
  }

  public async find(id: string): Promise<AdapterPayload | undefined> {
    const data = await redisClient.get(this.key(id));
    return data ? JSON.parse(data) : undefined;
  }

  public async findByUserCode(userCode: string): Promise<AdapterPayload | undefined> {
    const id = await redisClient.get(userCodeKeyFor(userCode));
    return id ? this.find(id) : undefined;
  }

  public async findByUid(uid: string): Promise<AdapterPayload | undefined> {
    const id = await redisClient.get(uidKeyFor(uid));
    return id ? this.find(id) : undefined;
  }

  public async destroy(id: string): Promise<void> {
    const key = this.key(id);
    await redisClient.del(key);
  }

  public async revokeByGrantId(grantId: string): Promise<void> {
    const grantKey = grantKeyFor(grantId);
    const grantIdList = await redisClient.lrange(grantKey, 0, -1);
    const tokenKeys = grantIdList.map(token => token);

    if (tokenKeys.length > 0) {
      await redisClient.del(...tokenKeys);
    }

    await redisClient.del(grantKey);
  }

  public async consume(id: string): Promise<void> {
    const key = this.key(id);
    const data = await redisClient.get(key);
    if (data) {
      const payload = JSON.parse(data);
      payload.consumed = Math.floor(Date.now() / 1000);
      await redisClient.set(key, JSON.stringify(payload), 'KEEPTTL');
    }
  }

  public key(id: string): string {
    return `oidc:${this.name}:${id}`;
  }
}

function grantKeyFor(id: string) {
  return `oidc:grant:${id}`;
}

function userCodeKeyFor(userCode: string) {
  return `oidc:userCode:${userCode}`;
}

function uidKeyFor(uid: string) {
  return `oidc:uid:${uid}`;
}

export default RedisAdapter;
