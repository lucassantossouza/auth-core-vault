import { ExecutionContext, ForbiddenException } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import { Reflector } from '@nestjs/core';
import type { IEnforcerOptions } from '../interfaces';
import { RESOURCE_GUARD_OPTIONS } from '../constants/resource-guard.const';
import { AUTH_VAULT_LOGGER_FACTORY } from '../constants/auth-vault-logger-factory.const';
import { AUTH_VAULT_SERVICE } from '../tokens';
import { PolicyEnforcementMode } from '../constants';
import { ResourceGuard } from './resource.guard';
import type { IAuthVaultService, IAuthVaultLogger } from '../interfaces';
import {
  META_PUBLIC,
  META_RESOURCE,
  META_SCOPES,
  META_CONDITIONAL_SCOPES,
} from '../decorators';

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

describe('ResourceGuard', () => {
  let guard: ResourceGuard;
  let authVaultService: jest.Mocked<IAuthVaultService>;
  const reflectorMock = {
    get: jest.fn(),
    getAllAndOverride: jest.fn(),
  };

  beforeEach(async () => {
    authVaultService = {
      getRolesForResource: jest.fn(),
    } as unknown as jest.Mocked<IAuthVaultService>;

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ResourceGuard,
        { provide: Reflector, useValue: reflectorMock },
        { provide: AUTH_VAULT_SERVICE, useValue: authVaultService },
        { provide: AUTH_VAULT_LOGGER_FACTORY, useValue: () => mockLogger },
        { provide: RESOURCE_GUARD_OPTIONS, useValue: {} },
      ],
    }).compile();

    guard = module.get<ResourceGuard>(ResourceGuard);
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

  describe('sem @Resource (controller sem recurso)', () => {
    beforeEach(() => {
      reflectorMock.get.mockReturnValue(undefined);
      reflectorMock.getAllAndOverride.mockImplementation((key: string) => {
        if (key === META_PUBLIC) return false;
        return undefined;
      });
    });

    it('permite acesso quando política é PERMISSIVE', async () => {
      reflectorMock.getAllAndOverride.mockImplementation((key: string) => {
        if (key === 'enforcer-options') return undefined;
        if (key === META_PUBLIC) return false;
        return undefined;
      });
      const context = createHttpContext();
      await expect(guard.canActivate(context)).resolves.toBe(true);
    });

    it('usa policyEnforcementMode de enforcerOpts quando definido (branch 52)', async () => {
      reflectorMock.get.mockReturnValue(undefined);
      reflectorMock.getAllAndOverride.mockImplementation((key: string) => {
        if (key === 'enforcer-options')
          return {
            policyEnforcementMode: PolicyEnforcementMode.ENFORCING,
          } as IEnforcerOptions;
        if (key === META_PUBLIC) return false;
        return undefined;
      });
      const context = createHttpContext();
      await expect(guard.canActivate(context)).rejects.toThrow(
        ForbiddenException,
      );
    });

    it('usa policyEnforcementMode das options quando enforcerOpts é indefinido (branch 52)', async () => {
      const moduleWithOpts = await Test.createTestingModule({
        providers: [
          ResourceGuard,
          { provide: Reflector, useValue: reflectorMock },
          { provide: AUTH_VAULT_SERVICE, useValue: authVaultService },
          { provide: AUTH_VAULT_LOGGER_FACTORY, useValue: () => mockLogger },
          {
            provide: RESOURCE_GUARD_OPTIONS,
            useValue: {
              policyEnforcementMode: PolicyEnforcementMode.ENFORCING,
            },
          },
        ],
      }).compile();
      const guardWithOpts = moduleWithOpts.get<ResourceGuard>(ResourceGuard);
      reflectorMock.get.mockReturnValue(undefined);
      reflectorMock.getAllAndOverride.mockImplementation((key: string) => {
        if (key === 'enforcer-options') return undefined;
        if (key === META_PUBLIC) return false;
        return undefined;
      });
      const context = createHttpContext();
      await expect(guardWithOpts.canActivate(context)).rejects.toThrow(
        ForbiddenException,
      );
    });

    it('permite acesso quando não há user mas rota é pública', async () => {
      reflectorMock.get.mockReturnValue(undefined);
      reflectorMock.getAllAndOverride.mockImplementation((key: string) => {
        if (key === 'enforcer-options') return undefined;
        if (key === META_PUBLIC) return true;
        return undefined;
      });
      const context = createHttpContext({ accessToken: 't' });
      await expect(guard.canActivate(context)).resolves.toBe(true);
    });

    it('lança ForbiddenException quando política é ENFORCING', async () => {
      reflectorMock.getAllAndOverride.mockImplementation((key: string) => {
        if (key === 'enforcer-options')
          return {
            policyEnforcementMode: PolicyEnforcementMode.ENFORCING,
          } as IEnforcerOptions;
        if (key === META_PUBLIC) return false;
        return undefined;
      });
      const context = createHttpContext();
      await expect(guard.canActivate(context)).rejects.toThrow(
        ForbiddenException,
      );
    });
  });

  describe('com @Resource e @Scopes', () => {
    const resource = 'my-resource';
    const scopes = ['scope1'];
    const user = { sub: 'id', preferred_username: 'user' };

    beforeEach(() => {
      reflectorMock.get.mockImplementation((key: string) => {
        if (key === META_RESOURCE) return resource;
        if (key === META_SCOPES) return scopes;
        if (key === 'conditional-scopes') return undefined;
        return undefined;
      });
      reflectorMock.getAllAndOverride.mockImplementation((key: string) => {
        if (key === 'enforcer-options') return undefined;
        if (key === META_PUBLIC) return false;
        return undefined;
      });
    });

    it('permite acesso quando usuário tem role do escopo', async () => {
      (authVaultService.getRolesForResource as jest.Mock).mockResolvedValue([
        'scope1',
      ]);
      const context = createHttpContext({ user, accessToken: 'token' });

      const result = await guard.canActivate(context);

      expect(result).toBe(true);
      expect(
        jest.mocked(authVaultService).getRolesForResource.mock.calls,
      ).toHaveLength(1);
      expect(
        jest.mocked(authVaultService).getRolesForResource.mock.calls[0],
      ).toEqual([user, resource]);
    });

    it('lança ForbiddenException quando usuário não tem role do escopo', async () => {
      (authVaultService.getRolesForResource as jest.Mock).mockResolvedValue([
        'other',
      ]);

      await expect(
        guard.canActivate(createHttpContext({ user, accessToken: 'token' })),
      ).rejects.toThrow(ForbiddenException);
    });

    it('lança ForbiddenException quando request não tem user', async () => {
      await expect(
        guard.canActivate(createHttpContext({ accessToken: 'token' })),
      ).rejects.toThrow(ForbiddenException);
    });

    it('chama conditionalScopes quando definido (branch 130-131)', async () => {
      const conditionalFn = jest.fn().mockReturnValue(['extra-scope']);
      reflectorMock.get.mockImplementation((key: string) => {
        if (key === META_RESOURCE) return resource;
        if (key === META_SCOPES) return [];
        if (key === META_CONDITIONAL_SCOPES) return conditionalFn;
        return undefined;
      });
      (authVaultService.getRolesForResource as jest.Mock).mockResolvedValue([
        'extra-scope',
      ]);
      const context = createHttpContext({ user, accessToken: 'token' });
      await expect(guard.canActivate(context)).resolves.toBe(true);
      expect(conditionalFn).toHaveBeenCalledWith(
        expect.objectContaining({ user, accessToken: 'token' }),
        'token',
      );
    });

    it('passa segundo argumento "" quando request.accessToken é undefined (branch request.accessToken ?? "")', async () => {
      const conditionalFn = jest.fn().mockReturnValue(['extra-scope']);
      reflectorMock.get.mockImplementation((key: string) => {
        if (key === META_RESOURCE) return resource;
        if (key === META_SCOPES) return [];
        if (key === META_CONDITIONAL_SCOPES) return conditionalFn;
        return undefined;
      });
      (authVaultService.getRolesForResource as jest.Mock).mockResolvedValue([
        'extra-scope',
      ]);
      const context = createHttpContext({ user });
      await expect(guard.canActivate(context)).resolves.toBe(true);
      expect(conditionalFn).toHaveBeenCalledWith(expect.anything(), '');
    });

    it('permite acesso quando há recurso mas escopos vazios e política PERMISSIVE', async () => {
      reflectorMock.get.mockImplementation((key: string) => {
        if (key === META_RESOURCE) return resource;
        if (key === META_SCOPES) return [];
        if (key === 'conditional-scopes') return undefined;
        return undefined;
      });
      reflectorMock.getAllAndOverride.mockImplementation((key: string) => {
        if (key === 'enforcer-options') return undefined;
        if (key === META_PUBLIC) return false;
        return undefined;
      });
      const context = createHttpContext({ user, accessToken: 'token' });
      await expect(guard.canActivate(context)).resolves.toBe(true);
    });

    it('lança ForbiddenException quando há recurso mas escopos vazios e política ENFORCING', async () => {
      reflectorMock.get.mockImplementation((key: string) => {
        if (key === META_RESOURCE) return resource;
        if (key === META_SCOPES) return [];
        if (key === 'conditional-scopes') return undefined;
        return undefined;
      });
      reflectorMock.getAllAndOverride.mockImplementation((key: string) => {
        if (key === 'enforcer-options')
          return {
            policyEnforcementMode: PolicyEnforcementMode.ENFORCING,
          } as IEnforcerOptions;
        if (key === META_PUBLIC) return false;
        return undefined;
      });
      const context = createHttpContext({ user, accessToken: 'token' });
      await expect(guard.canActivate(context)).rejects.toThrow(
        ForbiddenException,
      );
    });
  });
});
