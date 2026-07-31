import { config } from '@core/config/app.config';
import bcrypt from 'bcrypt';

export const hashPassword = async (
  password: string,
  saltRounds: number = config.BCRYPT_SALT_ROUNDS
) => await bcrypt.hash(password, saltRounds);

export const comparePassword = async (password: string, hashedValue: string) =>
  await bcrypt.compare(password, hashedValue);
