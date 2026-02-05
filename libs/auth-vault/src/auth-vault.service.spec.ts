import { Test, TestingModule } from '@nestjs/testing';
import {
  BadRequestException,
  ForbiddenException,
  UnauthorizedException,
} from '@nestjs/common';
import { AUTH_STRATEGIES_TOKEN } from './tokens/auth-strategies.token';
import { AUTH_VAULT_OPTIONS } from './tokens';
import { AUTH_VAULT_LOGGER_FACTORY } from './constants/auth-vault-logger-factory.const';
import { AuthVaultService } from './auth-vault.service';
import type {
  IAuthStrategy,
  IAuthVaultLogger,
  IAuthVaultModuleOptions,
} from './interfaces';
import type { ValidateResponseDto } from './dto';

const mockLogger: IAuthVaultLogger = {
  verbose: jest.fn(),
  log: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
};

const createMockStrategy = (
  name: string,
  overrides?: Partial<IAuthStrategy>,
): IAuthStrategy =>
  ({
    name,
    login: jest.fn(),
    logout: jest.fn(),
    refreshToken: jest.fn(),
    getUserInfo: jest.fn(),
    validate: jest.fn(),
    getRolesForResource: jest.fn(),
    getRoles: jest.fn(),
    ...overrides,
  }) as IAuthStrategy;

describe('AuthVaultService', () => {
  const strategyName = 'keycloak';
  let mockStrategy: IAuthStrategy;
  let service: AuthVaultService;

  beforeEach(async () => {
    mockStrategy = createMockStrategy(strategyName);

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthVaultService,
        {
          provide: AUTH_STRATEGIES_TOKEN,
          useValue: [mockStrategy],
        },
        {
          provide: AUTH_VAULT_OPTIONS,
          useValue: {
            strategyConfig: { name: strategyName },
          } as IAuthVaultModuleOptions,
        },
        {
          provide: AUTH_VAULT_LOGGER_FACTORY,
          useValue: () => mockLogger,
        },
      ],
    }).compile();

    service = module.get<AuthVaultService>(AuthVaultService);
  });

  it('deve ser definido', () => {
    expect(service).toBeDefined();
  });

  describe('login', () => {
    it('retorna data quando strategy retorna success true', async () => {
      const data = { access_token: 'token', expires_in: 300 };
      (mockStrategy.login as jest.Mock).mockResolvedValue({
        success: true,
        data,
      });

      const result = await service.login({ username: 'u', password: 'p' });

      expect(result).toEqual(data);
      expect(mockStrategy.login).toHaveBeenCalledWith({
        username: 'u',
        password: 'p',
      });
    });

    it('lança UnauthorizedException quando strategy retorna success false', async () => {
      (mockStrategy.login as jest.Mock).mockResolvedValue({
        success: false,
        data: { error: 'invalid' },
      });

      await expect(
        service.login({ username: 'u', password: 'p' }),
      ).rejects.toThrow(UnauthorizedException);
    });
  });

  describe('logout', () => {
    it('retorna data quando strategy retorna success true', async () => {
      const data = { message: 'ok' };
      (mockStrategy.logout as jest.Mock).mockResolvedValue({
        success: true,
        data,
      });

      const result = await service.logout({ refreshToken: 't' });

      expect(result).toEqual(data);
    });

    it('lança BadRequestException quando strategy retorna success false', async () => {
      (mockStrategy.logout as jest.Mock).mockResolvedValue({
        success: false,
        data: {},
      });

      await expect(service.logout({ refreshToken: 't' })).rejects.toThrow(
        BadRequestException,
      );
    });
  });

  describe('refreshToken', () => {
    it('retorna data quando strategy retorna success true', async () => {
      const data = { access_token: 'new', expires_in: 300 };
      (mockStrategy.refreshToken as jest.Mock).mockResolvedValue({
        success: true,
        data,
      });

      const result = await service.refreshToken({ refreshToken: 'rt' });

      expect(result).toEqual(data);
    });

    it('lança UnauthorizedException quando strategy retorna success false', async () => {
      (mockStrategy.refreshToken as jest.Mock).mockResolvedValue({
        success: false,
        data: {},
      });

      await expect(
        service.refreshToken({ refreshToken: 'rt' }),
      ).rejects.toThrow(UnauthorizedException);
    });
  });

  describe('validate', () => {
    it('retorna o resultado da strategy', async () => {
      const response = {
        success: true,
        data: { sub: 'id' } as ValidateResponseDto,
      };
      (mockStrategy.validate as jest.Mock).mockResolvedValue(response);

      const result = await service.validate({ token: 'jwt' });

      expect(result).toEqual(response);
      expect(mockStrategy.validate).toHaveBeenCalledWith({ token: 'jwt' });
    });
  });

  describe('getUserInfo', () => {
    it('retorna data quando success true', async () => {
      const data = { sub: 'id', preferred_username: 'user' };
      (mockStrategy.getUserInfo as jest.Mock).mockResolvedValue({
        success: true,
        data,
      });

      const result = await service.getUserInfo({ token: 'jwt' });

      expect(result).toEqual(data);
    });

    it('lança UnauthorizedException quando statusCode 401', async () => {
      (mockStrategy.getUserInfo as jest.Mock).mockResolvedValue({
        success: false,
        data: {},
        statusCode: 401,
      });

      await expect(service.getUserInfo({ token: 'jwt' })).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('lança ForbiddenException quando statusCode 403', async () => {
      (mockStrategy.getUserInfo as jest.Mock).mockResolvedValue({
        success: false,
        data: {},
        statusCode: 403,
      });

      await expect(service.getUserInfo({ token: 'jwt' })).rejects.toThrow(
        ForbiddenException,
      );
    });

    it('lança BadRequestException em outros erros', async () => {
      (mockStrategy.getUserInfo as jest.Mock).mockResolvedValue({
        success: false,
        data: {},
      });

      await expect(service.getUserInfo({ token: 'jwt' })).rejects.toThrow(
        BadRequestException,
      );
    });
  });

  describe('getRolesForResource', () => {
    it('retorna array retornado pela strategy', async () => {
      (mockStrategy.getRolesForResource as jest.Mock).mockResolvedValue([
        'role1',
        'role2',
      ]);

      const user = { sub: 'id' } as ValidateResponseDto;
      const result = await service.getRolesForResource(user, 'resource');

      expect(result).toEqual(['role1', 'role2']);
      expect(mockStrategy.getRolesForResource).toHaveBeenCalledWith(
        user,
        'resource',
      );
    });

    it('retorna array vazio quando strategy retorna não-array', async () => {
      (mockStrategy.getRolesForResource as jest.Mock).mockResolvedValue(null);

      const result = await service.getRolesForResource(
        { sub: 'id' } as ValidateResponseDto,
        'r',
      );

      expect(result).toEqual([]);
    });
  });

  describe('getRoles', () => {
    it('retorna array retornado pela strategy', async () => {
      (mockStrategy.getRoles as jest.Mock).mockResolvedValue(['admin', 'user']);

      const user = { sub: 'id' } as ValidateResponseDto;
      const result = await service.getRoles(user);

      expect(result).toEqual(['admin', 'user']);
      expect(mockStrategy.getRoles).toHaveBeenCalledWith(user);
    });

    it('retorna array vazio quando strategy retorna não-array', async () => {
      (mockStrategy.getRoles as jest.Mock).mockResolvedValue(undefined);

      const result = await service.getRoles({
        sub: 'id',
      } as ValidateResponseDto);

      expect(result).toEqual([]);
    });
  });
});

describe('AuthVaultService (constructor)', () => {
  it('lança quando strategyConfig.name está ausente', async () => {
    const mockStrategy = createMockStrategy('keycloak');

    await expect(
      Test.createTestingModule({
        providers: [
          AuthVaultService,
          { provide: AUTH_STRATEGIES_TOKEN, useValue: [mockStrategy] },
          {
            provide: AUTH_VAULT_OPTIONS,
            useValue: {} as IAuthVaultModuleOptions,
          },
          { provide: AUTH_VAULT_LOGGER_FACTORY, useValue: () => mockLogger },
        ],
      }).compile(),
    ).rejects.toThrow('Strategy name is required');
  });

  it('lança quando strategy com o nome não existe na lista', async () => {
    const mockStrategy = createMockStrategy('other');

    await expect(
      Test.createTestingModule({
        providers: [
          AuthVaultService,
          { provide: AUTH_STRATEGIES_TOKEN, useValue: [mockStrategy] },
          {
            provide: AUTH_VAULT_OPTIONS,
            useValue: {
              strategyConfig: { name: 'keycloak' },
            } as IAuthVaultModuleOptions,
          },
          { provide: AUTH_VAULT_LOGGER_FACTORY, useValue: () => mockLogger },
        ],
      }).compile(),
    ).rejects.toThrow('Strategy keycloak not found');
  });
});
