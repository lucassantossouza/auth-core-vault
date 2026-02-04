import {
  Public,
  META_PUBLIC,
  Resource,
  META_RESOURCE,
  Roles,
  META_ROLES,
  Scopes,
  META_SCOPES,
  AccessToken,
  AuthUser,
  ResolvedScopes,
  ConditionalScopes,
  META_CONDITIONAL_SCOPES,
  EnforcerOptions,
  RoleMatchMode,
  META_ROLE_MATCHING_MODE,
} from './index';
import { getAccessTokenFromContext } from './access-token.decorator';
import { getAuthUserFromContext } from './auth-user.decorator';
import { getResolvedScopesFromContext } from './resolved-scopes.decorator';
import { extractRequest } from '../utils';
import { RoleMatch } from '../constants';
import type { ExecutionContext } from '@nestjs/common';

const ROUTE_ARGS_METADATA = '__routeArguments__';

describe('decorators', () => {
  const createHttpContext = (request: Record<string, unknown>) =>
    ({
      getType: () => 'http',
      getClass: () => class {},
      getHandler: () => function handler() {},
      switchToHttp: () => ({
        getRequest: () => request,
        getResponse: () => ({}),
      }),
    }) as unknown as ExecutionContext;

  describe('Public', () => {
    it('retorna decorator e usa META_PUBLIC', () => {
      const dec = Public();
      expect(dec).toBeDefined();
      expect(META_PUBLIC).toBe('public');
    });
  });

  describe('Resource', () => {
    it('retorna decorator com META_RESOURCE e recurso', () => {
      const dec = Resource('my-api');
      expect(dec).toBeDefined();
      expect(META_RESOURCE).toBe('resource');
    });
  });

  describe('Roles', () => {
    it('retorna decorator com META_ROLES e roles', () => {
      const dec = Roles('admin', 'user');
      expect(dec).toBeDefined();
      expect(META_ROLES).toBe('auth:roles');
    });
  });

  describe('Scopes', () => {
    it('retorna decorator com META_SCOPES e scopes', () => {
      const dec = Scopes('read', 'write');
      expect(dec).toBeDefined();
      expect(META_SCOPES).toBe('scopes');
    });
  });

  describe('ConditionalScopes', () => {
    it('retorna decorator com META_CONDITIONAL_SCOPES', () => {
      const fn = (): string[] => [];
      const dec = ConditionalScopes(fn);
      expect(dec).toBeDefined();
      expect(META_CONDITIONAL_SCOPES).toBe('conditional-scopes');
    });
  });

  describe('EnforcerOptions', () => {
    it('retorna decorator com opções', () => {
      const dec = EnforcerOptions({
        policyEnforcementMode:
          'ENFORCING' as unknown as import('../interfaces').IEnforcerOptions['policyEnforcementMode'],
      });
      expect(dec).toBeDefined();
    });
  });

  describe('RoleMatchMode', () => {
    it('retorna decorator com META_ROLE_MATCHING_MODE e modo', () => {
      const dec = RoleMatchMode(RoleMatch.ALL);
      expect(dec).toBeDefined();
      expect(META_ROLE_MATCHING_MODE).toBe('auth:roleMatchingMode');
    });
  });

  describe('AccessToken (param decorator)', () => {
    it('retorna função decorator', () => {
      const decorator = AccessToken();
      expect(typeof decorator).toBe('function');
    });

    it('extractRequest retorna request com accessToken', () => {
      const ctx = createHttpContext({ accessToken: 'bearer-token' });
      const [request] = extractRequest(ctx);
      expect((request as { accessToken?: string })?.accessToken).toBe(
        'bearer-token',
      );
    });

    it('getAccessTokenFromContext retorna accessToken do contexto', () => {
      const ctx = createHttpContext({ accessToken: 'my-jwt' });
      expect(getAccessTokenFromContext(ctx)).toBe('my-jwt');
    });

    it('callback do decorator é executado ao resolver param (cobertura linha 30)', () => {
      class TestController {
        getToken(@AccessToken() token: string | undefined) {
          return token;
        }
      }
      const args = Reflect.getMetadata(
        ROUTE_ARGS_METADATA,
        TestController,
        'getToken',
      );
      const entry = Object.values(args ?? {}).find(
        (v: unknown) =>
          typeof v === 'object' &&
          v !== null &&
          'factory' in v &&
          typeof (v as { factory: unknown }).factory === 'function',
      ) as
        | { factory: (data: unknown, ctx: ExecutionContext) => unknown }
        | undefined;
      expect(entry?.factory).toBeDefined();
      const ctx = createHttpContext({ accessToken: 'from-callback' });
      expect(entry!.factory(undefined, ctx)).toBe('from-callback');
    });
  });

  describe('AuthUser (param decorator)', () => {
    it('retorna função decorator', () => {
      expect(typeof AuthUser()).toBe('function');
    });

    it('request com user é extraído corretamente', () => {
      const user = { sub: 'id' };
      const ctx = createHttpContext({ user });
      const [request] = extractRequest(ctx);
      expect((request as { user?: unknown })?.user).toBe(user);
    });

    it('getAuthUserFromContext retorna user do contexto', () => {
      const user = { sub: 'id' };
      const ctx = createHttpContext({ user });
      expect(getAuthUserFromContext(ctx)).toBe(user);
    });

    it('callback do decorator é executado ao resolver param (cobertura linha 31)', () => {
      class TestController {
        getProfile(@AuthUser() user: unknown) {
          return user;
        }
      }
      const args = Reflect.getMetadata(
        ROUTE_ARGS_METADATA,
        TestController,
        'getProfile',
      );
      const entry = Object.values(args ?? {}).find(
        (v: unknown) =>
          typeof v === 'object' &&
          v !== null &&
          'factory' in v &&
          typeof (v as { factory: unknown }).factory === 'function',
      ) as
        | { factory: (data: unknown, ctx: ExecutionContext) => unknown }
        | undefined;
      expect(entry?.factory).toBeDefined();
      const user = { sub: 'id' };
      const ctx = createHttpContext({ user });
      expect(entry!.factory(undefined, ctx)).toBe(user);
    });
  });

  describe('ResolvedScopes (param decorator)', () => {
    it('retorna função decorator', () => {
      expect(typeof ResolvedScopes()).toBe('function');
    });

    it('extractRequest retorna request com scopes', () => {
      const ctx = createHttpContext({ scopes: ['read', 'write'] });
      const [request] = extractRequest<Request & { scopes?: string[] }>(ctx);
      expect(request?.scopes).toEqual(['read', 'write']);
    });

    it('getResolvedScopesFromContext retorna scopes do contexto', () => {
      const ctx = createHttpContext({ scopes: ['read', 'write'] });
      expect(getResolvedScopesFromContext(ctx)).toEqual(['read', 'write']);
    });

    it('callback do decorator é executado ao resolver param (cobertura linha 29)', () => {
      class TestController {
        getScopes(@ResolvedScopes() scopes: string[] | undefined) {
          return scopes;
        }
      }
      const args = Reflect.getMetadata(
        ROUTE_ARGS_METADATA,
        TestController,
        'getScopes',
      );
      const entry = Object.values(args ?? {}).find(
        (v: unknown) =>
          typeof v === 'object' &&
          v !== null &&
          'factory' in v &&
          typeof (v as { factory: unknown }).factory === 'function',
      ) as
        | { factory: (data: unknown, ctx: ExecutionContext) => unknown }
        | undefined;
      expect(entry?.factory).toBeDefined();
      const ctx = createHttpContext({ scopes: ['read'] });
      expect(entry!.factory(undefined, ctx)).toEqual(['read']);
    });
  });
});
