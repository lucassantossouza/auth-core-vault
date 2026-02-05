import { PolicyEnforcementMode, RoleMatch, RoleMerge } from '../constants';
import { TokenValidation } from '../constants/token-validation.const';

/** Shared options for auth/resource/role guards (cookie key, policy mode, token validation, role merge/match). */
export interface AuthVaultLibraryOptions {
  cookieKey?: string;
  policyEnforcement?: PolicyEnforcementMode;
  tokenValidation?: TokenValidation;
  roleMerge?: RoleMerge;
  roleMatch?: RoleMatch;
}
