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
