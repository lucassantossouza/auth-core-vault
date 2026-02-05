import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { extractRequest } from '../utils';
import { IAuthRequest } from '../interfaces';

/**
 * Gets the Bearer access token from the execution context. Exported for tests and programmatic use.
 */
export function getAccessTokenFromContext(
  ctx: ExecutionContext,
): string | undefined {
  const [request] = extractRequest<IAuthRequest, unknown>(ctx);
  return request?.accessToken;
}

/**
 * Parameter decorator: injects the Bearer access token from the request.
 * @returns JWT string or undefined if not authenticated.
 * @example
 * @Get() getToken(@AccessToken() accessToken: string | undefined) { return accessToken; }
 */
export const AccessToken = createParamDecorator(
  (data: unknown, ctx: ExecutionContext): string | undefined =>
    getAccessTokenFromContext(ctx),
);
