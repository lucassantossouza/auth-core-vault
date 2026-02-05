import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { extractRequest } from '../utils';
import { IAuthRequest } from '../interfaces';
import { ValidateResponseDto } from '../dto';

export type AuthUserType = ValidateResponseDto | undefined;

/**
 * Gets the authenticated user from the execution context. Exported for tests and programmatic use.
 */
export function getAuthUserFromContext(ctx: ExecutionContext): AuthUserType {
  const [request] = extractRequest<IAuthRequest, unknown>(ctx);
  return request?.user;
}

/**
 * Parameter decorator: injects the authenticated user (ValidateResponseDto) from the request.
 * @returns User from token validation or undefined.
 * @example
 * @Get() getProfile(@AuthUser() user: AuthUserType) { return user; }
 */
export const AuthUser = createParamDecorator(
  (data: unknown, ctx: ExecutionContext): AuthUserType =>
    getAuthUserFromContext(ctx),
);
