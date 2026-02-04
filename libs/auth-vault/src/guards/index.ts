/**
 * Guards: AuthGuard (JWT validation), ResourceGuard (resource + scopes), RoleGuard (roles).
 * Use with @UseGuards(); apply AuthGuard first, then ResourceGuard or RoleGuard as needed.
 */
export * from './auth.guard';
export * from './resource.guard';
export * from './role.guard';
