export interface RegisterData {
  name: string;
  email: string;
  password: string;
  confirmPassword: string;
}

export interface VerifyEmailData {
  token: string;
}

export interface ResendVerificationData {
  email: string;
}

export interface LoginData {
  email: string;
  password: string;
  ipAddress: string;
  userAgent: string;
}

export interface LogoutData {
  sessionId: string;
}

export interface refreshAccessTokenData {
  refreshToken: string;
}

export interface ForgotPasswordData {
  email: string;
  ipAddress: string;
}

export interface VerifyOtpData {
  otp: string;
  email: string;
}

export interface ResetPasswordData {
  email: string;
  password: string;
  confirmPassword: string;
  resetToken: string;
}

export interface ChangePasswordData {
  userId: string;
  currentPassword: string;
  newPassword: string;
}

export interface GoogleProfile {
  id: string;
  displayName: string;
  name?: {
    givenName: string;
    familyName: string;
  };
  emails?: {
    value: string;
  }[];
  photos?: {
    value: string;
  }[];
}

export interface LoginWithGoogleData {
  profile: GoogleProfile;
  ipAddress: string;
  userAgent: string;
}
