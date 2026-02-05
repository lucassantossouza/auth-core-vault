import { PolicyEnforcementMode } from '../constants';

/** Enforcer options for a route/controller (e.g. @EnforcerOptions). Overrides ResourceGuard policy mode. */
export interface IEnforcerOptions {
  policyEnforcementMode?: PolicyEnforcementMode;
  [key: string]: unknown;
}
