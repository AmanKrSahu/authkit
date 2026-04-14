export interface PromoteUserToAdminData {
  userId: string;
}

export interface DeleteUserData {
  userId: string;
}

export interface RevokeSessionByIdData {
  sessionId: string;
}

export interface RevokeSessionsByUserIdData {
  userId: string;
}

export interface CreateOidcClientData {
  clientName: string;
  redirectUrls: string[];
  grantTypes?: string[];
  scope?: string;
}

export interface GetUserByIdData {
  userId: string;
}

export interface GetUserSessionsData {
  userId: string;
}
