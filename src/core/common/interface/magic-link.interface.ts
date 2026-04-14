export interface MagicLinkLoginData {
  email: string;
  uid?: string;
  redirectUrl?: string;
}

export interface MagicLinkVerifyData {
  token: string;
  ipAddress: string;
  userAgent: string;
}
