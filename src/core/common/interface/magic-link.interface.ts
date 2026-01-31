export interface MagicLinkLoginData {
  email: string;
}

export interface MagicLinkVerifyData {
  token: string;
  ipAddress: string;
  userAgent: string;
}
