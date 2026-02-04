import { SetMetadata } from '@nestjs/common';
import { ConditionalScopeFn } from '../types/conditional-scope-fn.type';

export const META_CONDITIONAL_SCOPES = 'conditional-scopes';

/**
 * Sets the function that resolves conditional scopes for ResourceGuard. Receives (request, accessToken) and returns additional scopes.
 * @param resolver - (request, accessToken) => string[]
 * @example
 * @Resource('my-api')
 * @Scopes('read')
 * @ConditionalScopes((req, token) => (req.query?.expand ? ['detail'] : []))
 * @Get() getData() { ... }
 */
export const ConditionalScopes = (resolver: ConditionalScopeFn) =>
  SetMetadata(META_CONDITIONAL_SCOPES, resolver);
