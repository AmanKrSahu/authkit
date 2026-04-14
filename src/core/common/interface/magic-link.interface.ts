export interface MagicLinkLoginData {
  email: string;
  uid?: string;
}

export interface MagicLinkVerifyData {
  token: string;
  ipAddress: string;
  userAgent: string;
}
