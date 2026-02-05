import { ExecutionContext, ForbiddenException } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import { Reflector } from '@nestjs/core';
import { ROLE_GUARD_OPTIONS } from '../constants/role-guard.const';
import { AUTH_VAULT_LOGGER_FACTORY } from '../constants/auth-vault-logger-factory.const';
import { AUTH_VAULT_SERVICE } from '../tokens';
import { RoleMatch, RoleMerge } from '../constants';
import { RoleGuard } from './role.guard';
import type { IAuthVaultService, IAuthVaultLogger } from '../interfaces';
import { META_ROLES, META_ROLE_MATCHING_MODE } from '../decorators';

const mockLogger: IAuthVaultLogger = {
  verbose: jest.fn(),
  log: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
};

function createHttpContext(
  overrides: { user?: unknown; accessToken?: string } = {},
) {
  const request: Record<string, unknown> = {
    headers: {},
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

describe('RoleGuard', () => {
  let guard: RoleGuard;
  let authVaultService: jest.Mocked<IAuthVaultService>;
  const reflectorMock = {
    getAllAndOverride: jest.fn(),
    getAllAndMerge: jest.fn(),
  };

  beforeEach(async () => {
    authVaultService = {
      getRoles: jest.fn(),
    } as unknown as jest.Mocked<IAuthVaultService>;

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        RoleGuard,
        { provide: Reflector, useValue: reflectorMock },
        { provide: AUTH_VAULT_SERVICE, useValue: authVaultService },
        { provide: AUTH_VAULT_LOGGER_FACTORY, useValue: () => mockLogger },
        { provide: ROLE_GUARD_OPTIONS, useValue: {} },
      ],
    }).compile();

    guard = module.get<RoleGuard>(RoleGuard);
  });

  it('deve ser definido', () => {
    expect(guard).toBeDefined();
  });

  it('permite acesso quando não há request (não é http)', async () => {
    const context = {
      getType: () => 'rpc',
      getClass: () => ({}),
      getHandler: () => ({}),
      switchToHttp: () => ({ getRequest: () => null, getResponse: () => ({}) }),
    } as unknown as ExecutionContext;
    await expect(guard.canActivate(context)).resolves.toBe(true);
  });

  it('usa RoleMatch.ANY quando options não é fornecido (branch 37)', async () => {
    const moduleNoOpts = await Test.createTestingModule({
      providers: [
        RoleGuard,
        { provide: Reflector, useValue: reflectorMock },
        { provide: AUTH_VAULT_SERVICE, useValue: authVaultService },
        { provide: AUTH_VAULT_LOGGER_FACTORY, useValue: () => mockLogger },
      ],
    }).compile();
    const guardNoOpts = moduleNoOpts.get<RoleGuard>(RoleGuard);
    reflectorMock.getAllAndOverride.mockImplementation((key: string) => {
      if (key === META_ROLES) return ['user'];
      if (key === META_ROLE_MATCHING_MODE) return undefined;
      return undefined;
    });
    reflectorMock.getAllAndMerge.mockReturnValue([]);
    (authVaultService.getRoles as jest.Mock).mockResolvedValue(['user']);
    const result = await guardNoOpts.canActivate(
      createHttpContext({ user: { sub: 'id' }, accessToken: 't' }),
    );
    expect(result).toBe(true);
  });

  it('permite acesso quando não há roles exigidas (@Roles vazio ou ausente)', async () => {
    reflectorMock.getAllAndOverride.mockReturnValue([]);
    reflectorMock.getAllAndMerge.mockReturnValue([]);
    const context = createHttpContext({ user: {}, accessToken: 't' });

    await expect(guard.canActivate(context)).resolves.toBe(true);
    expect(jest.mocked(authVaultService).getRoles.mock.calls).toHaveLength(0);
  });

  it('permite acesso quando RoleMerge.OVERRIDE e getAllAndOverride retorna undefined', async () => {
    reflectorMock.getAllAndOverride.mockReturnValue(undefined);
    reflectorMock.getAllAndMerge.mockReturnValue(undefined);
    const context = createHttpContext({
      user: { sub: 'id' },
      accessToken: 't',
    });
    await expect(guard.canActivate(context)).resolves.toBe(true);
    expect(jest.mocked(authVaultService).getRoles.mock.calls).toHaveLength(0);
  });

  it('lança ForbiddenException quando não há accessToken no request', async () => {
    reflectorMock.getAllAndOverride.mockReturnValue(['admin']);
    reflectorMock.getAllAndMerge.mockReturnValue([]);
    const context = createHttpContext({ user: {} });

    await expect(guard.canActivate(context)).rejects.toThrow(
      ForbiddenException,
    );
  });

  it('lança ForbiddenException quando não há user no request', async () => {
    reflectorMock.getAllAndOverride.mockReturnValue(['admin']);
    reflectorMock.getAllAndMerge.mockReturnValue([]);
    const context = createHttpContext({ accessToken: 't' });

    await expect(guard.canActivate(context)).rejects.toThrow(
      ForbiddenException,
    );
  });

  describe('RoleMatch.ANY (pelo menos uma role)', () => {
    beforeEach(() => {
      reflectorMock.getAllAndOverride.mockImplementation((key: string) => {
        if (key === META_ROLES) return ['admin', 'user'];
        if (key === META_ROLE_MATCHING_MODE) return RoleMatch.ANY;
        return undefined;
      });
      reflectorMock.getAllAndMerge.mockReturnValue([]);
    });

    it('permite acesso quando usuário tem pelo menos uma das roles', async () => {
      (authVaultService.getRoles as jest.Mock).mockResolvedValue([
        'user',
        'other',
      ]);
      const context = createHttpContext({
        user: { sub: 'id' },
        accessToken: 't',
      });

      const result = await guard.canActivate(context);

      expect(result).toBe(true);
      expect(jest.mocked(authVaultService).getRoles.mock.calls).toHaveLength(1);
    });

    it('lança ForbiddenException quando usuário não tem nenhuma das roles', async () => {
      (authVaultService.getRoles as jest.Mock).mockResolvedValue(['guest']);

      await expect(
        guard.canActivate(
          createHttpContext({ user: { sub: 'id' }, accessToken: 't' }),
        ),
      ).rejects.toThrow(ForbiddenException);
    });
  });

  describe('RoleMatch.ALL (todas as roles)', () => {
    beforeEach(() => {
      reflectorMock.getAllAndOverride.mockImplementation((key: string) => {
        if (key === META_ROLES) return ['admin', 'user'];
        if (key === META_ROLE_MATCHING_MODE) return RoleMatch.ALL;
        return undefined;
      });
      reflectorMock.getAllAndMerge.mockReturnValue([]);
    });

    it('usa roleMatch das options quando reflector não define modo (branch 37)', async () => {
      const moduleWithOpts = await Test.createTestingModule({
        providers: [
          RoleGuard,
          { provide: Reflector, useValue: reflectorMock },
          { provide: AUTH_VAULT_SERVICE, useValue: authVaultService },
          { provide: AUTH_VAULT_LOGGER_FACTORY, useValue: () => mockLogger },
          {
            provide: ROLE_GUARD_OPTIONS,
            useValue: { roleMatch: RoleMatch.ALL },
          },
        ],
      }).compile();
      const guardWithOpts = moduleWithOpts.get<RoleGuard>(RoleGuard);
      reflectorMock.getAllAndOverride.mockImplementation((key: string) => {
        if (key === META_ROLES) return ['admin', 'user'];
        if (key === META_ROLE_MATCHING_MODE) return undefined;
        return undefined;
      });
      (authVaultService.getRoles as jest.Mock).mockResolvedValue([
        'admin',
        'user',
      ]);
      const result = await guardWithOpts.canActivate(
        createHttpContext({ user: { sub: 'id' }, accessToken: 't' }),
      );
      expect(result).toBe(true);
    });

    it('permite acesso quando usuário tem todas as roles', async () => {
      (authVaultService.getRoles as jest.Mock).mockResolvedValue([
        'admin',
        'user',
      ]);

      const result = await guard.canActivate(
        createHttpContext({ user: { sub: 'id' }, accessToken: 't' }),
      );

      expect(result).toBe(true);
    });

    it('lança ForbiddenException quando usuário não tem todas as roles', async () => {
      (authVaultService.getRoles as jest.Mock).mockResolvedValue(['admin']);

      await expect(
        guard.canActivate(
          createHttpContext({ user: { sub: 'id' }, accessToken: 't' }),
        ),
      ).rejects.toThrow(ForbiddenException);
    });
  });

  describe('RoleMerge.ALL (classe + método)', () => {
    beforeEach(async () => {
      const module: TestingModule = await Test.createTestingModule({
        providers: [
          RoleGuard,
          { provide: Reflector, useValue: reflectorMock },
          { provide: AUTH_VAULT_SERVICE, useValue: authVaultService },
          { provide: AUTH_VAULT_LOGGER_FACTORY, useValue: () => mockLogger },
          {
            provide: ROLE_GUARD_OPTIONS,
            useValue: { roleMerge: RoleMerge.ALL },
          },
        ],
      }).compile();
      guard = module.get<RoleGuard>(RoleGuard);
    });

    it('permite acesso quando getAllAndMerge retorna undefined (requiredRoles vazio)', async () => {
      reflectorMock.getAllAndMerge.mockReturnValue(undefined);
      reflectorMock.getAllAndOverride.mockReturnValue(undefined);
      const context = createHttpContext({
        user: { sub: 'id' },
        accessToken: 't',
      });
      await expect(guard.canActivate(context)).resolves.toBe(true);
      expect(jest.mocked(authVaultService).getRoles.mock.calls).toHaveLength(0);
    });

    it('obtém roles via getAllAndMerge e permite quando usuário tem a role', async () => {
      reflectorMock.getAllAndOverride.mockReturnValue([]);
      reflectorMock.getAllAndMerge.mockReturnValue(['admin']);
      (authVaultService.getRoles as jest.Mock).mockResolvedValue(['admin']);

      const result = await guard.canActivate(
        createHttpContext({ user: { sub: 'id' }, accessToken: 't' }),
      );

      expect(result).toBe(true);
      expect(jest.mocked(authVaultService).getRoles.mock.calls).toHaveLength(1);
    });
  });

  it('lança Error quando roleMerge é inválido', async () => {
    const invalidMerge = 'invalid' as unknown as RoleMerge;
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        RoleGuard,
        { provide: Reflector, useValue: reflectorMock },
        { provide: AUTH_VAULT_SERVICE, useValue: authVaultService },
        { provide: AUTH_VAULT_LOGGER_FACTORY, useValue: () => mockLogger },
        { provide: ROLE_GUARD_OPTIONS, useValue: { roleMerge: invalidMerge } },
      ],
    }).compile();
    const guardWithInvalidOptions = module.get<RoleGuard>(RoleGuard);

    reflectorMock.getAllAndOverride.mockReturnValue(['admin']);
    reflectorMock.getAllAndMerge.mockReturnValue([]);

    await expect(
      guardWithInvalidOptions.canActivate(
        createHttpContext({ user: { sub: 'id' }, accessToken: 't' }),
      ),
    ).rejects.toThrow('Invalid role merge mode');
  });
});
