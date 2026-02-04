import { ContextType, ExecutionContext } from '@nestjs/common';
import { GqlExecutionContext } from '@nestjs/graphql';

type GqlContextType = Extract<ContextType, 'graphql'>;

export const extractRequest = <TReq = any, TRes = any>(
  context: ExecutionContext,
): [TReq, TRes] => {
  // verifico se a requisição é do tipo http ou graphql
  if (context.getType() === 'http') {
    // Request HTTP
    const httpContext = context.switchToHttp();

    return [httpContext.getRequest(), httpContext.getResponse()];
  }
  if (context.getType<GqlContextType>() === 'graphql') {
    // Request GraphQL
    const gqlContext = GqlExecutionContext.create(context).getContext<{
      req: any;
      res: any;
    }>();

    return [gqlContext.req as TReq, gqlContext.res as TRes];
  }

  return [undefined as TReq, undefined as TRes];
};

export const attachCookieToHeader = (
  request: {
    cookies?: Record<string, string>;
    headers?: Record<string, string>;
  },
  cookieKey: string,
) => {
  // Attach cookie as authorization header
  if (request && request?.cookies && request?.cookies?.[cookieKey])
    request.headers!.authorization = `Bearer ${request.cookies?.[cookieKey]}`;

  return request;
};

export const extractRequestAndAttachCookie = <TReq = any, TRes = any>(
  context: ExecutionContext,
  cookieKey: string,
): [TReq, TRes] => {
  const [tmpRequest, response] = extractRequest<TReq, TRes>(context);
  const request = attachCookieToHeader(
    tmpRequest as unknown as {
      cookies?: Record<string, string>;
      headers?: Record<string, string>;
    },
    cookieKey,
  );

  return [request as TReq, response];
};

export function parseToken<TDecodedToken = Record<string, unknown>>(
  token: string,
  throwOnError?: false,
): TDecodedToken | object;
export function parseToken<TDecodedToken = Record<string, unknown>>(
  token: string,
  throwOnError?: true,
): TDecodedToken;
export function parseToken<TDecodedToken = Record<string, unknown>>(
  token: string,
  throwOnError?: boolean,
) {
  const parts = (token ?? '').split('.');

  try {
    return JSON.parse(
      Buffer.from(parts[1], 'base64').toString(),
    ) as TDecodedToken;
  } catch (error) {
    if (throwOnError) throw error;
    return {};
  }
}
