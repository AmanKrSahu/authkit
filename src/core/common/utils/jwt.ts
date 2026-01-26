import { config } from '@core/config/app.config';
import type { SignOptions, VerifyOptions } from 'jsonwebtoken';
import jwt from 'jsonwebtoken';

export type AccessTPayload = {
  userId: string;
  sessionId: string;
};

export type RefreshTPayload = {
  sessionId: string;
};

export type ResetTPayload = {
  email: string;
  purpose: 'PASSWORD_RESET';
};

export type MFATPayload = {
  userId: string;
  purpose: 'MFA_LOGIN';
};

const defaults: SignOptions & VerifyOptions = {
  audience: 'user',
};

type SignOptsAndSecret = SignOptions & {
  secret: string;
};

export const accessTokenSignOptions: SignOptsAndSecret = {
  secret: config.JWT.SECRET,
  expiresIn: config.JWT.EXPIRES_IN as SignOptions['expiresIn'],
};

export const refreshTokenSignOptions: SignOptsAndSecret = {
  secret: config.JWT.REFRESH_SECRET,
  expiresIn: config.JWT.REFRESH_EXPIRES_IN as SignOptions['expiresIn'],
};

export const resetTokenSignOptions: SignOptsAndSecret = {
  secret: config.JWT.RESET_SECRET,
  expiresIn: config.JWT.RESET_EXPIRES_IN as SignOptions['expiresIn'],
};

export const mfaTokenSignOptions: SignOptsAndSecret = {
  secret: config.JWT.MFA_LOGIN_SECRET,
  expiresIn: config.JWT.MFA_LOGIN_EXPIRES_IN as SignOptions['expiresIn'],
};

export const signJwtToken = (
  payload: AccessTPayload | RefreshTPayload | ResetTPayload | MFATPayload,
  options?: SignOptsAndSecret
) => {
  const { secret, ...opts } = options ?? accessTokenSignOptions;
  return jwt.sign(payload, secret, {
    ...defaults,
    ...opts,
  });
};

export const verifyJwtToken = <TPayload extends object = AccessTPayload>(
  token: string,
  options?: VerifyOptions & { secret: string }
) => {
  try {
    const { secret = config.JWT.SECRET, ...opts } = options ?? {};
    const payload = jwt.verify(token, secret, {
      ...defaults,
      ...opts,
    }) as unknown as TPayload;
    return { payload };
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  } catch (error: any) {
    return {
      error: error.message,
    };
  }
};
