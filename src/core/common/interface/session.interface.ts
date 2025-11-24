export interface SessionData {
  userId: string;
}

export interface SessionByIdData {
  userId: string;
  sessionId: string;
}

export interface RevokeSessionData {
  userId: string;
  currentSessionId?: string;
}

export interface RevokeSessionByIdData {
  userId: string;
  sessionId?: string;
}
