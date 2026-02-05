import { Test, TestingModule } from '@nestjs/testing';
import { of, throwError } from 'rxjs';
import { HttpService } from '@nestjs/axios';
import { KeycloakStrategy } from './keycloak.strategy';
import { AUTH_STRATEGY_CONFIG } from '../../tokens';
import { AUTH_VAULT_LOGGER_FACTORY } from '../../constants/auth-vault-logger-factory.const';
import type { ConfigForStrategy } from '../../types/strategy-config-dto.types';
import type { IAuthVaultLogger } from '../../interfaces';
import type { ValidateResponseDto } from '../../dto';

const mockLogger: IAuthVaultLogger = {
  verbose: jest.fn(),
  log: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
};

const validConfig: ConfigForStrategy<'keycloak'> = {
  name: 'keycloak',
  clientId: 'client',
  clientSecret: 'secret',
  realm: 'realm',
  url: 'https://auth.example.com',
};

describe('KeycloakStrategy', () => {
  let strategy: KeycloakStrategy;
  let httpService: { request: jest.Mock };

  beforeEach(async () => {
    httpService = {
      request: jest.fn().mockReturnValue(
        of({
          data: {},
          status: 200,
          statusText: 'OK',
          headers: {},
          config: {},
        }),
      ),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        KeycloakStrategy,
        { provide: AUTH_STRATEGY_CONFIG, useValue: validConfig },
        { provide: HttpService, useValue: httpService },
        { provide: AUTH_VAULT_LOGGER_FACTORY, useValue: () => mockLogger },
      ],
    }).compile();

    strategy = module.get<KeycloakStrategy>(KeycloakStrategy);
  });

  it('deve ser definido', () => {
    expect(strategy).toBeDefined();
    expect(strategy.name).toBe('keycloak');
  });

  describe('login', () => {
    it('retorna success true e data quando request retorna tokens', async () => {
      httpService.request.mockReturnValue(
        of({
          data: {
            access_token: 'at',
            expires_in: 300,
            refresh_token: 'rt',
            refresh_token_expires_in: 3600,
            scope: 'openid',
            session_state: 'ss',
            token_type: 'Bearer',
          },
          status: 200,
          statusText: 'OK',
          headers: {},
          config: {},
        }),
      );

      const result = await strategy.login({
        username: 'u',
        password: 'p',
      });

      expect(result.success).toBe(true);
      expect(result.data).toMatchObject({
        accessToken: 'at',
        expiresIn: 300,
        refreshToken: 'rt',
        tokenType: 'Bearer',
      });
      expect(httpService.request).toHaveBeenCalled();
    });

    it('retorna success false quando request falha', async () => {
      httpService.request.mockReturnValue(
        throwError(() => ({
          response: {
            status: 401,
            data: {
              error: 'invalid_grant',
              error_description: 'Invalid credentials',
            },
          },
        })),
      );

      const result = await strategy.login({
        username: 'u',
        password: 'p',
      });

      expect(result.success).toBe(false);
      expect(result.data).toMatchObject({
        error: 'invalid_grant',
        details: 'Invalid credentials',
      });
    });

    it('retorna success false quando request falha com status fora do whitelist (ex: 404)', async () => {
      httpService.request.mockReturnValue(
        throwError(() => ({
          response: { status: 404, data: {} },
          message: 'Not Found',
        })),
      );

      const result = await strategy.login({
        username: 'u',
        password: 'p',
      });

      expect(result.success).toBe(false);
    });
  });

  const minimalUser = (
    overrides: Partial<ValidateResponseDto> = {},
  ): ValidateResponseDto => ({
    sub: 'id',
    exp: 0,
    iat: 0,
    jti: 'test',
    ...overrides,
  });

  describe('getRolesForResource', () => {
    it('agrega roles de realm_access, resource_access e roles', () => {
      const user = minimalUser({
        realm_access: { roles: ['realm-a', 'realm-b'] },
        resource_access: {
          'my-app': { roles: ['app-1'] },
        },
        roles: ['top-role'],
      });

      const result = strategy.getRolesForResource(user, 'my-app');

      expect(result).toEqual(
        expect.arrayContaining(['realm-a', 'realm-b', 'app-1', 'top-role']),
      );
      expect(result).toHaveLength(4);
    });

    it('retorna array vazio quando user não tem roles', () => {
      expect(strategy.getRolesForResource(minimalUser(), 'x')).toEqual([]);
    });
  });

  describe('getRoles', () => {
    it('agrega todas as roles de realm_access e resource_access', () => {
      const user = minimalUser({
        realm_access: { roles: ['r1'] },
        resource_access: {
          app1: { roles: ['a1'] },
          app2: { roles: ['a2'] },
        },
        roles: ['direct'],
      });

      const result = strategy.getRoles(user);

      expect(result).toEqual(
        expect.arrayContaining(['r1', 'a1', 'a2', 'direct']),
      );
      expect(result).toHaveLength(4);
    });

    it('retorna array vazio quando user não tem roles', () => {
      expect(strategy.getRoles(minimalUser())).toEqual([]);
    });
  });

  describe('validate', () => {
    it('retorna success true quando token é ativo', async () => {
      const body = {
        active: true,
        sub: 'user-1',
        realm_access: { roles: ['user'] },
      };
      httpService.request.mockReturnValue(
        of({
          data: body,
          status: 200,
          statusText: 'OK',
          headers: {},
          config: {},
        }),
      );

      const result = await strategy.validate({ token: 'jwt' });

      expect(result.success).toBe(true);
      expect(result.data).toEqual(body);
    });

    it('retorna success false quando token não é ativo', async () => {
      httpService.request.mockReturnValue(
        of({
          data: { active: false },
          status: 200,
          statusText: 'OK',
          headers: {},
          config: {},
        }),
      );

      const result = await strategy.validate({ token: 'jwt' });

      expect(result.success).toBe(false);
      expect(
        (result as { success: false; statusCode?: number }).statusCode,
      ).toBe(401);
    });
  });

  describe('getUserInfo', () => {
    it('retorna success false quando request falha', async () => {
      httpService.request.mockReturnValue(
        throwError(() => ({
          response: {
            status: 401,
            data: { error: 'invalid_token' },
          },
        })),
      );

      const result = await strategy.getUserInfo({ token: 'jwt' });

      expect(result.success).toBe(false);
      expect(result.statusCode).toBe(401);
      expect(result.data).toMatchObject({ error: 'invalid_token' });
    });

    it('retorna success true e data quando request ok', async () => {
      httpService.request.mockReturnValue(
        of({
          data: { sub: 'user-1', preferred_username: 'u1' },
          status: 200,
          statusText: 'OK',
          headers: {},
          config: {},
        }),
      );

      const result = await strategy.getUserInfo({ token: 'jwt' });

      expect(result.success).toBe(true);
      expect(result.data).toMatchObject({
        sub: 'user-1',
        preferred_username: 'u1',
      });
    });
  });

  describe('refreshToken', () => {
    it('retorna success false quando request falha', async () => {
      httpService.request.mockReturnValue(
        throwError(() => ({
          response: {
            status: 401,
            data: {
              error: 'invalid_grant',
              error_description: 'Token expired',
            },
          },
        })),
      );

      const result = await strategy.refreshToken({ refreshToken: 'old-rt' });

      expect(result.success).toBe(false);
      expect(result.data).toMatchObject({
        error: 'invalid_grant',
        details: 'Token expired',
      });
    });

    it('retorna success true quando request retorna novos tokens', async () => {
      httpService.request.mockReturnValue(
        of({
          data: {
            access_token: 'new-at',
            refresh_token: 'new-rt',
            expires_in: 300,
            refresh_token_expires_in: 3600,
            scope: 'openid',
            session_state: 'ss',
            token_type: 'Bearer',
          },
          status: 200,
          statusText: 'OK',
          headers: {},
          config: {},
        }),
      );

      const result = await strategy.refreshToken({ refreshToken: 'old-rt' });

      expect(result.success).toBe(true);
      expect(result.data).toMatchObject({
        accessToken: 'new-at',
        refreshToken: 'new-rt',
      });
    });
  });

  describe('logout', () => {
    it('retorna success true quando revoke retorna sem error', async () => {
      httpService.request.mockReturnValue(
        of({
          data: {},
          status: 200,
          statusText: 'OK',
          headers: {},
          config: {},
        }),
      );

      const result = await strategy.logout({
        refreshToken: 'rt',
        accessToken: 'at',
      });

      expect(result.success).toBe(true);
    });

    it('lança e depois retorna success false quando revoke retorna 200 com data.error', async () => {
      httpService.request.mockReturnValue(
        of({
          data: { error: 'revocation_failed', error_description: 'Failed' },
          status: 200,
          statusText: 'OK',
          headers: {},
          config: {},
        }),
      );

      const result = await strategy.logout({
        refreshToken: 'rt',
        accessToken: 'at',
      });

      expect(result.success).toBe(false);
      expect(result.data).toMatchObject({
        error: 'revocation_failed',
        details: 'Failed',
      });
    });
  });
});
