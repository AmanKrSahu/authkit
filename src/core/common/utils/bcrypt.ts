import bcrypt from 'bcrypt';

export const hashPassword = async (password: string, saltRounds: number = 10) =>
  await bcrypt.hash(password, saltRounds);

export const comparePassword = async (password: string, hashedValue: string) =>
  await bcrypt.compare(password, hashedValue);
