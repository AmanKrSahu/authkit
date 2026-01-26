export interface GenerateMFASetupData {
  userId: string;
}

export interface VerifyMFASetupData {
  userId: string;
  code: string;
}

export interface RevokeMFAData {
  userId: string;
}

export interface VerifyMFAForLoginData {
  code: string;
  userAgent: string;
  ipAddress: string;
  mfaLoginToken: string;
}
