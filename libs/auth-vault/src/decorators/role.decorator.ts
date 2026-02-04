import { SetMetadata } from '@nestjs/common';

/** Metadata key for required roles (RoleGuard). */
export const META_ROLES = 'auth:roles';

/**
 * Required roles for the route. User must have at least one (RoleMatch.ANY) or all (RoleMatch.ALL), per @RoleMatchMode or RoleGuard options.
 * @param roles - Role names (e.g. 'admin', 'manager').
 * @example
 * @Get()
 * @Roles('admin', 'manager')
 * getResource() { ... }
 */
export const Roles = (...roles: string[]) => SetMetadata(META_ROLES, roles);
