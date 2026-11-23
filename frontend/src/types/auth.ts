/**
 * Multi-User RBAC & Authentication Types for ForensicOps AI.
 */

export type UserRole = "lead_investigator" | "soc_analyst" | "auditor";

export interface User {
  id: string;
  username: string;
  badge_id: string;
  role: UserRole;
  full_name?: string;
  is_active: boolean;
  created_at: string;
}

export interface UserCreatePayload {
  username: string;
  badge_id: string;
  role: UserRole;
  password: string;
  full_name?: string;
}

export interface UserSetupPayload {
  username: string;
  badge_id: string;
  password: string;
  full_name?: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  user: User;
}

export interface AuthStatus {
  initialized: boolean;
  active_users_count: number;
}
