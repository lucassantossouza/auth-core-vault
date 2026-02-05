import { SetMetadata } from '@nestjs/common';
import { RoleMatch } from '../constants';

/** Metadata key for role matching mode (ANY = at least one, ALL = all). */
export const META_ROLE_MATCHING_MODE = 'auth:roleMatchingMode';

/**
 * Sets matching mode for @Roles: ANY (at least one) or ALL (all roles required).
 * @param mode - RoleMatch.ANY or RoleMatch.ALL
 * @example
 * @Get()
 * @Roles('admin', 'manager')
 * @RoleMatchMode(RoleMatch.ALL)
 * getResource() { ... }
 */
export const RoleMatchMode = (mode: RoleMatch) =>
  SetMetadata(META_ROLE_MATCHING_MODE, mode);
