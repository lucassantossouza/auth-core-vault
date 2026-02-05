import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { extractRequest } from '../utils';

/**
 * Gets resolved scopes (explicit + conditional) from the execution context. Exported for tests and programmatic use.
 */
export function getResolvedScopesFromContext(
  ctx: ExecutionContext,
): string[] | undefined {
  const [request] = extractRequest<Request & { scopes?: string[] }>(ctx);
  return request?.scopes;
}

/**
 * Parameter decorator: injects scopes resolved by ResourceGuard (explicit + conditional).
 * @returns Resolved scopes or undefined.
 * @example
 * @Get() getData(@ResolvedScopes() scopes: string[] | undefined) { return scopes ?? []; }
 */
export const ResolvedScopes = createParamDecorator(
  (data: unknown, ctx: ExecutionContext): string[] | undefined =>
    getResolvedScopesFromContext(ctx),
);
