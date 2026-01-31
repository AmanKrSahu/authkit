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
