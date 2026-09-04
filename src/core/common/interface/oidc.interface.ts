export interface ConsentDetail {
  scopes?: {
    new: string[];
    accepted?: string[];
    rejected?: string[];
  };
  missingOIDCScope?: string[];
}
