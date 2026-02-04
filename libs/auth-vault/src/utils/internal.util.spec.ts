import { ExecutionContext } from '@nestjs/common';
import { GqlExecutionContext } from '@nestjs/graphql';
import {
  extractRequest,
  attachCookieToHeader,
  extractRequestAndAttachCookie,
  parseToken,
} from './internal.util';

jest.mock('@nestjs/graphql', () => ({
  GqlExecutionContext: {
    create: jest.fn(),
  },
}));

describe('internal.util', () => {
  describe('extractRequest', () => {
    it('retorna [request, response] para contexto http', () => {
      const req = { url: '/' };
      const res = { statusCode: 200 };
      const context = {
        getType: () => 'http',
        switchToHttp: () => ({ getRequest: () => req, getResponse: () => res }),
      } as unknown as ExecutionContext;

      const [r, s] = extractRequest(context);

      expect(r).toBe(req);
      expect(s).toBe(res);
    });

    it('retorna [req, res] do contexto graphql', () => {
      const req = { query: '{}' };
      const res = {};
      const gqlContext = { req, res };
      (GqlExecutionContext.create as jest.Mock).mockReturnValue({
        getContext: () => gqlContext,
      });
      const context = {
        getType: () => 'graphql',
      } as unknown as ExecutionContext;

      const [r, s] = extractRequest(context);

      expect((GqlExecutionContext.create as jest.Mock).mock.calls[0][0]).toBe(
        context,
      );
      expect(r).toBe(req);
      expect(s).toBe(res);
    });

    it('retorna [undefined, undefined] para tipo não http/graphql', () => {
      const context = {
        getType: () => 'rpc',
      } as unknown as ExecutionContext;

      const [r, s] = extractRequest(context);

      expect(r).toBeUndefined();
      expect(s).toBeUndefined();
    });
  });

  describe('attachCookieToHeader', () => {
    it('define authorization no header quando cookie existe', () => {
      const request = {
        cookies: { access_token: 'my-jwt' },
        headers: {} as Record<string, string>,
      };

      const result = attachCookieToHeader(request, 'access_token');

      expect(result).toBe(request);
      expect(request.headers.authorization).toBe('Bearer my-jwt');
    });

    it('não altera headers quando cookie não existe', () => {
      const request = {
        cookies: {},
        headers: {} as Record<string, string>,
      };

      attachCookieToHeader(request, 'access_token');

      expect(request.headers.authorization).toBeUndefined();
    });

    it('não quebra quando request ou cookies são undefined', () => {
      expect(
        attachCookieToHeader(
          undefined as unknown as {
            cookies?: Record<string, string>;
            headers?: Record<string, string>;
          },
          'x',
        ),
      ).toBeUndefined();
      const req = { headers: {} as Record<string, string> };
      expect(
        attachCookieToHeader(
          req as unknown as {
            cookies?: Record<string, string>;
            headers?: Record<string, string>;
          },
          'x',
        ),
      ).toEqual(req);
    });
  });

  describe('extractRequestAndAttachCookie', () => {
    it('extrai request, anexa cookie e retorna [request, response]', () => {
      const req = {
        cookies: { token: 'jwt' },
        headers: {} as Record<string, string>,
      };
      const res = {};
      const context = {
        getType: () => 'http',
        switchToHttp: () => ({ getRequest: () => req, getResponse: () => res }),
      } as unknown as ExecutionContext;

      const [r, s] = extractRequestAndAttachCookie(context, 'token');

      expect(r).toBe(req);
      expect(s).toBe(res);
      expect((r as typeof req).headers.authorization).toBe('Bearer jwt');
    });
  });

  describe('parseToken', () => {
    it('decodifica JWT válido e retorna payload', () => {
      const payload = { sub: 'user-1', exp: 999 };
      const encoded = Buffer.from(JSON.stringify(payload)).toString('base64');
      const token = `header.${encoded}.sig`;

      const result = parseToken(token);

      expect(result).toEqual(payload);
    });

    it('retorna {} quando token é inválido e throwOnError é false', () => {
      const result = parseToken('not-a-valid-jwt', false);

      expect(result).toEqual({});
    });

    it('retorna {} quando token é inválido e throwOnError é omitido', () => {
      const result = parseToken('x.y.z');

      expect(result).toEqual({});
    });

    it('lança quando token é inválido e throwOnError é true', () => {
      expect(() => parseToken('invalid', true)).toThrow();
    });

    it('trata token null/undefined como string vazia', () => {
      expect(parseToken(undefined as unknown as string)).toEqual({});
      expect(parseToken(null as unknown as string)).toEqual({});
    });
  });
});
