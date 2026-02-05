import { RoleMatch, RoleMerge } from '../constants';

/** RoleGuard options. Provide when registering the guard or via module. */
export interface IRoleGuardOptions {
  cookieKey?: string;
  /** Role merge: ALL (class + method) or OVERRIDE (method overrides). Default OVERRIDE. */
  roleMerge?: RoleMerge;
  /** Match mode: user needs ANY (at least one) or ALL roles. Default ANY. */
  roleMatch?: RoleMatch;
}
