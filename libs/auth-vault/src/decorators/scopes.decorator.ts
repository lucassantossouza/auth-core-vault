import { SetMetadata } from '@nestjs/common';

export const META_SCOPES = 'scopes';

/**
 * Required scopes to access the resource. User must have at least one (from resource_access or realm_access). Use with @Resource().
 * @param scopes - Scope names (e.g. 'read', 'write').
 * @example
 * @Resource('my-api')
 * @Scopes('read', 'write')
 * @Get() getData() { ... }
 */
export const Scopes = (...scopes: string[]) => SetMetadata(META_SCOPES, scopes);
