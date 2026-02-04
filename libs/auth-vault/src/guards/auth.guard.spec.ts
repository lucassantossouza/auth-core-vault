import { ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import { Reflector } from '@nestjs/core';
import { AUTH_GUARD_OPTIONS } from '../constants/auth-guard.const';
import { AUTH_VAULT_LOGGER_FACTORY } from '../constants/auth-vault-logger-factory.const';
import { AUTH_VAULT_SERVICE } from '../tokens';
import { AuthGuard } from './auth.guard';
import type { IAuthVaultService, IAuthVaultLogger } from '../interfaces';

const mockLogger: IAuthVaultLogger = {
  verbose: jest.fn(),
  log: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
};

function createHttpContext(
  overrides: {
    headers?: Record<string, string>;
    user?: unknown;
    accessToken?: string;
  } = {},
) {
  const request: Record<string, unknown> = {
    headers: overrides.headers ?? {},
    ...overrides,
  };
  return {
    getType: () => 'http',
    getClass: () => ({}),
    getHandler: () => ({}),
    switchToHttp: () => ({
      getRequest: () => request,
      getResponse: () => ({}),
    }),
  } as unknown as ExecutionContext;
}

describe('AuthGuard', () => {
  let guard: AuthGuard;
  let authVaultService: jest.Mocked<IAuthVaultService>;
  const reflectorMock = { getAllAndOverride: jest.fn() };

  beforeEach(async () => {
    authVaultService = {
      validate: jest.fn(),
    } as unknown as jest.Mocked<IAuthVaultService>;

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthGuard,
        { provide: AUTH_VAULT_SERVICE, useValue: authVaultService },
        { provide: Reflector, useValue: reflectorMock },
        { provide: AUTH_VAULT_LOGGER_FACTORY, useValue: () => mockLogger },
        { provide: AUTH_GUARD_OPTIONS, useValue: {} },
      ],
    }).compile();

    guard = module.get<AuthGuard>(AuthGuard);
  });

  it('deve ser definido', () => {
    expect(guard).toBeDefined();
  });

  it('usa cookieKey das options quando fornecido (branch options?.cookieKey)', async () => {
    const moduleWithCookieKey = await Test.createTestingModule({
      providers: [
        AuthGuard,
        { provide: AUTH_VAULT_SERVICE, useValue: authVaultService },
        { provide: Reflector, useValue: reflectorMock },
        { provide: AUTH_VAULT_LOGGER_FACTORY, useValue: () => mockLogger },
        {
          provide: AUTH_GUARD_OPTIONS,
          useValue: { cookieKey: 'custom-cookie' },
        },
      ],
    }).compile();
    const guardWithOpts = moduleWithCookieKey.get<AuthGuard>(AuthGuard);
    reflectorMock.getAllAndOverride.mockReturnValue(true);
    const context = createHttpContext({ headers: {} });
    await expect(guardWithOpts.canActivate(context)).resolves.toBe(true);
  });

  it('usa AUTH_GUARD_COOKIE_DEFAULT quando options não é fornecido', async () => {
    const moduleWithoutOptions = await Test.createTestingModule({
      providers: [
        AuthGuard,
        { provide: AUTH_VAULT_SERVICE, useValue: authVaultService },
        { provide: Reflector, useValue: reflectorMock },
        { provide: AUTH_VAULT_LOGGER_FACTORY, useValue: () => mockLogger },
      ],
    }).compile();
    const guardNoOpts = moduleWithoutOptions.get<AuthGuard>(AuthGuard);
    reflectorMock.getAllAndOverride.mockReturnValue(true);
    const context = createHttpContext({ headers: {} });
    await expect(guardNoOpts.canActivate(context)).resolves.toBe(true);
  });

  describe('rota pública', () => {
    beforeEach(() => {
      reflectorMock.getAllAndOverride.mockReturnValue(true);
    });

    it('permite acesso sem token', async () => {
      const context = createHttpContext({ headers: {} });
      await expect(guard.canActivate(context)).resolves.toBe(true);
      expect(jest.mocked(authVaultService).validate.mock.calls).toHaveLength(0);
    });

    it('permite acesso com token inválido (rota pública)', async () => {
      (authVaultService.validate as jest.Mock).mockResolvedValue({
        success: false,
      });
      const context = createHttpContext({
        headers: { authorization: 'Bearer invalid-jwt' },
      });
      await expect(guard.canActivate(context)).resolves.toBe(true);
    });
  });

  describe('rota protegida', () => {
    beforeEach(() => {
      reflectorMock.getAllAndOverride.mockReturnValue(false);
    });

    it('retorna true quando não é contexto http (request null) (branch 61)', async () => {
      const context = {
        getType: () => 'rpc',
        getClass: () => ({}),
        getHandler: () => ({}),
        switchToHttp: () => ({
          getRequest: () => null,
          getResponse: () => ({}),
        }),
      } as unknown as ExecutionContext;
      await expect(guard.canActivate(context)).resolves.toBe(true);
    });

    it('extractJwtFromHeader com headers undefined não entra no if (branch 116)', async () => {
      const context = createHttpContext({});
      const req = context.switchToHttp().getRequest();
      req.headers = undefined;
      await expect(guard.canActivate(context)).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('lança UnauthorizedException quando não há token', async () => {
      const context = createHttpContext({ headers: {} });
      await expect(guard.canActivate(context)).rejects.toThrow(
        UnauthorizedException,
      );
      expect(jest.mocked(authVaultService).validate.mock.calls).toHaveLength(0);
    });

    it('lança UnauthorizedException quando não há header Authorization', async () => {
      const context = createHttpContext({ headers: { other: 'x' } });
      await expect(guard.canActivate(context)).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('lança UnauthorizedException quando Authorization não é Bearer', async () => {
      const context = createHttpContext({
        headers: { authorization: 'Basic dXNlcjpwYXNz' },
      });
      await expect(guard.canActivate(context)).rejects.toThrow(
        UnauthorizedException,
      );
      expect(jest.mocked(authVaultService).validate.mock.calls).toHaveLength(0);
    });

    it('lança quando headers não têm authorization (cobre extractJwtFromHeader)', async () => {
      const context = createHttpContext({
        headers: { 'content-type': 'application/json' },
      });
      await expect(guard.canActivate(context)).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('lança quando Authorization é "Bearer " sem token (auth[1] undefined)', async () => {
      const context = createHttpContext({
        headers: { authorization: 'Bearer ' },
      });
      await expect(guard.canActivate(context)).rejects.toThrow(
        UnauthorizedException,
      );
      expect(jest.mocked(authVaultService).validate.mock.calls).toHaveLength(0);
    });

    it('retorna true e preenche request.user quando token é válido', async () => {
      const user = { sub: 'id', preferred_username: 'user' };
      (authVaultService.validate as jest.Mock).mockResolvedValue({
        success: true,
        data: user,
      });
      const request = {
        headers: {
          authorization:
            'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJpZCJ9.x',
        },
      };
      const context = createHttpContext({
        headers: request.headers as Record<string, string>,
      });
      const req = context.switchToHttp().getRequest();
      (req as Record<string, unknown>).headers = request.headers;

      const result = await guard.canActivate(context);

      expect(result).toBe(true);
      expect(req.user).toEqual(user);
      expect(req.accessToken).toBe(
        'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJpZCJ9.x'.split(
          ' ',
        )[1],
      );
      expect(jest.mocked(authVaultService).validate.mock.calls).toHaveLength(1);
      expect(jest.mocked(authVaultService).validate.mock.calls[0][0]).toEqual({
        token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJpZCJ9.x',
      });
    });

    it('lança UnauthorizedException quando token é inválido', async () => {
      (authVaultService.validate as jest.Mock).mockResolvedValue({
        success: false,
      });
      const context = createHttpContext({
        headers: { authorization: 'Bearer any-token' },
      });

      await expect(guard.canActivate(context)).rejects.toThrow(
        UnauthorizedException,
      );
    });
  });
});
