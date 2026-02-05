import 'reflect-metadata';
import { of, throwError, defer } from 'rxjs';
import { AuthStrategyBase } from './auth-strategy.abstract';

jest.mock('class-transformer', () => {
  const actual =
    jest.requireActual<typeof import('class-transformer')>('class-transformer');
  return {
    ...actual,
    plainToInstance: jest.fn((...args: unknown[]) =>
      (actual.plainToInstance as (...a: unknown[]) => unknown)(...args),
    ),
  };
});
import { plainToInstance } from 'class-transformer';
import type { ConfigForStrategy } from '../types';
import type { IAuthVaultLogger } from '../interfaces';
import type {
  LoginApiResponse,
  LogoutApiResponse,
  RefreshTokenApiResponse,
  UserInfoApiResponse,
  ValidateApiResponse,
} from '../types';
import { AUTH_METHOD_HEADER } from '../constants/auth-method-header.const';
import { AUTH_MESSAGES } from '../constants/auth-messages.const';
import type { HttpService } from '@nestjs/axios';

const mockLogger: IAuthVaultLogger = {
  verbose: jest.fn(),
  log: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
};

const createLogger = () => mockLogger;

/** Strategy de teste que expõe buildAuthHeader e implementa métodos abstratos. */
class TestKeycloakStrategy extends AuthStrategyBase<'keycloak'> {
  public exposeBuildAuthHeader(...args: unknown[]): string {
    return (
      this as unknown as AuthStrategyBase<'keycloak'> & {
        buildAuthHeader(...a: unknown[]): string;
      }
    ).buildAuthHeader(...args);
  }

  async login(): Promise<LoginApiResponse> {
    await Promise.resolve();
    return {
      success: false,
      data: {
        error: 'unknown',
        message: AUTH_MESSAGES.COMMON_DEFAULT_ERROR,
      },
    };
  }
  async logout(): Promise<LogoutApiResponse> {
    await Promise.resolve();
    return {
      success: false,
      data: { error: 'unknown', message: 'Error' },
    };
  }
  async refreshToken(): Promise<RefreshTokenApiResponse> {
    await Promise.resolve();
    return {
      success: false,
      data: { error: 'unknown', message: 'Error' },
    };
  }
  async getUserInfo(): Promise<UserInfoApiResponse> {
    await Promise.resolve();
    return {
      success: false,
      statusCode: 500,
      data: {
        error: 'unknown',
        message: AUTH_MESSAGES.COMMON_DEFAULT_ERROR,
      },
    };
  }
  async validate(): Promise<ValidateApiResponse> {
    await Promise.resolve();
    return { success: false, data: {} };
  }
  getRolesForResource(): string[] {
    return [];
  }
  getRoles(): string[] {
    return [];
  }

  /** Expõe request() para testar erro quando httpService está ausente. */
  public async exposeRequest(
    url: string,
    method: 'GET' | 'POST' = 'GET',
  ): Promise<unknown> {
    return this.request(url, method);
  }
}

describe('AuthStrategyBase', () => {
  const validConfig: ConfigForStrategy<'keycloak'> = {
    name: 'keycloak',
    clientId: 'client',
    clientSecret: 'secret',
    realm: 'realm',
    url: 'https://auth.example.com',
  };

  describe('constructor', () => {
    it('inicializa com config válida', () => {
      const strategy = new TestKeycloakStrategy(validConfig, createLogger);
      expect(strategy.name).toBe('keycloak');
      const config = (
        strategy as unknown as { config: ConfigForStrategy<'keycloak'> }
      ).config;
      expect(config).toMatchObject({
        clientId: validConfig.clientId,
        clientSecret: validConfig.clientSecret,
        realm: validConfig.realm,
        url: validConfig.url,
      });
    });

    it('lança quando config é null', () => {
      expect(
        () =>
          new TestKeycloakStrategy(
            null as unknown as ConfigForStrategy<'keycloak'>,
            createLogger,
          ),
      ).toThrow();
    });

    it('lança quando config é undefined', () => {
      expect(
        () =>
          new TestKeycloakStrategy(
            undefined as unknown as ConfigForStrategy<'keycloak'>,
            createLogger,
          ),
      ).toThrow();
    });

    it('lança quando config falha na validação (campos obrigatórios)', () => {
      expect(
        () =>
          new TestKeycloakStrategy(
            { name: 'keycloak' } as ConfigForStrategy<'keycloak'>,
            createLogger,
          ),
      ).toThrow(/Invalid keycloak config/);
    });

    it('lança quando validateSync retorna erro sem constraints (branch 102)', () => {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const classValidator = require('class-validator') as {
        validateSync: (
          object: unknown,
          options?: unknown,
        ) => import('class-validator').ValidationError[];
      };
      const spy = jest
        .spyOn(classValidator, 'validateSync')
        .mockReturnValueOnce([
          { property: 'url', constraints: undefined },
        ] as unknown as import('class-validator').ValidationError[]);
      expect(() => new TestKeycloakStrategy(validConfig, createLogger)).toThrow(
        /Invalid keycloak config/,
      );
      spy.mockRestore();
    });

    it('lança quando url é inválida', () => {
      expect(
        () =>
          new TestKeycloakStrategy(
            {
              ...validConfig,
              url: 'not-a-url',
            },
            createLogger,
          ),
      ).toThrow(/Invalid keycloak config/);
    });

    it('lança quando plainToInstance não retorna instância do DTO', () => {
      (plainToInstance as jest.Mock).mockReturnValueOnce(null);
      expect(() => new TestKeycloakStrategy(validConfig, createLogger)).toThrow(
        /Failed to transform config/,
      );
    });
  });

  describe('buildAuthHeader', () => {
    let strategy: TestKeycloakStrategy;

    beforeEach(() => {
      strategy = new TestKeycloakStrategy(validConfig, createLogger);
    });

    it('retorna header Bearer quando recebe token', () => {
      const header = strategy.exposeBuildAuthHeader('my-jwt');
      expect(header).toBe(`${AUTH_METHOD_HEADER.BEARER} my-jwt`);
    });

    it('retorna header Basic quando recebe (undefined, identifier, secret)', () => {
      const header = strategy.exposeBuildAuthHeader(
        undefined as unknown as string,
        'user',
        'pass',
      );
      expect(header).toMatch(/^Basic /);
      const decoded = Buffer.from(
        header.replace(/^Basic /, ''),
        'base64',
      ).toString();
      expect(decoded).toBe('user:pass');
    });

    it('lança quando token é vazio (argumentos inválidos)', () => {
      expect(() => strategy.exposeBuildAuthHeader('')).toThrow(
        /Error building auth header/,
      );
    });
  });

  describe('request (sem httpService)', () => {
    it('lança quando httpService não foi injetado', async () => {
      const strategy = new TestKeycloakStrategy(validConfig, createLogger);
      await expect(
        strategy.exposeRequest('https://example.com', 'GET'),
      ).rejects.toThrow(/does not support http requests/);
    });
  });

  describe('request com retry (delay branch)', () => {
    it('executa delay e retenta em erro 500', async () => {
      let attempt = 0;
      const mockRequest = jest.fn().mockReturnValue(
        defer(() => {
          attempt++;
          if (attempt === 1) {
            return throwError(() => ({
              response: { status: 500 },
              message: 'Server Error',
            }));
          }
          return of({
            data: {},
            status: 200,
            statusText: 'OK',
            headers: {},
            config: {} as import('axios').InternalAxiosRequestConfig,
          });
        }),
      );
      const httpService = { request: mockRequest } as unknown as HttpService;
      const strategy = new TestKeycloakStrategy(
        validConfig,
        createLogger,
        httpService,
      );

      const result = await strategy.exposeRequest('https://example.com', 'GET');
      expect(result).toBeDefined();
      expect(mockRequest).toHaveBeenCalledTimes(1);
    }, 8000);
  });
});
