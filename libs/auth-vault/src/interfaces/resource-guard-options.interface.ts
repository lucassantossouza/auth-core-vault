import { PolicyEnforcementMode } from '../constants';

/** ResourceGuard options. Provide when registering the guard or via module. */
export interface IResourceGuardOptions {
  policyEnforcementMode?: PolicyEnforcementMode;
  /** Cookie key for token (defaults to AuthGuard cookie key if not set). */
  cookieKey?: string;
}
