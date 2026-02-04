import { SetMetadata } from '@nestjs/common';

/** Metadata key for the protected resource (ResourceGuard). */
export const META_RESOURCE = 'resource';

/**
 * Sets the resource protected by ResourceGuard. Use with @Scopes() on the handler or class.
 * @param resource - Resource name (e.g. Keycloak client or API resource).
 * @example
 * @Resource('my-api')
 * @Scopes('read')
 * @Get() getData() { ... }
 */
export const Resource = (resource: string) =>
  SetMetadata(META_RESOURCE, resource);
