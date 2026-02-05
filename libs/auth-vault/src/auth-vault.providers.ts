import { Provider } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { APP_GUARD, Reflector } from '@nestjs/core';
import {
  AUTH_GUARD_COOKIE_DEFAULT,
  AUTH_GUARD_OPTIONS,
  AuthGuardOptions,
} from './constants/auth-guard.const';
import {
  AUTH_VAULT_OPTIONS,
  AUTH_STRATEGY_CONFIG,
  AUTH_STRATEGIES_TOKEN,
  AUTH_VAULT_SERVICE,
} from './tokens';
import {
  AUTH_STRATEGIES_REGISTRY,
  AuthStrategyName,
} from './strategies/strategies.registry';
import {
  PolicyEnforcementMode,
  RESOURCE_GUARD_OPTIONS,
  ROLE_GUARD_OPTIONS,
  RoleMerge,
  RoleMatch,
} from './constants';
import { AUTH_VAULT_LOGGER_FACTORY } from './constants/auth-vault-logger-factory.const';
import { ConfigForStrategy } from './types';
import {
  AuthVaultLibraryOptions,
  IAuthVaultModuleOptions,
  IAuthStrategy,
  IAuthVaultLogger,
  IAuthVaultService,
  IResourceGuardOptions,
  IRoleGuardOptions,
} from './interfaces';
import { AuthVaultFeatureAsyncOptions } from './types/auth-vault-feature-options.type';
import { AuthVaultLogger } from './logger/auth-vault.logger';
import { AuthVaultService } from './auth-vault.service';
import { AuthGuard, ResourceGuard, RoleGuard } from './guards';

/** Token interno só para encadear providers do forFeature (strategy instance). */
const FEATURE_STRATEGY_INSTANCE = Symbol('AuthVaultFeatureStrategyInstance');

const strategies = Object.values(AUTH_STRATEGIES_REGISTRY);

function buildGuardOptionsFromLibrary(
  options?: Pick<IAuthVaultModuleOptions, keyof AuthVaultLibraryOptions>,
) {
  const cookieKey = options?.cookieKey ?? AUTH_GUARD_COOKIE_DEFAULT;
  return {
    authGuard: {
      cookieKey,
      tokenValidation: options?.tokenValidation,
    },
    resourceGuard: {
      cookieKey,
      policyEnforcementMode:
        options?.policyEnforcement ?? PolicyEnforcementMode.PERMISSIVE,
    },
    roleGuard: {
      cookieKey,
      roleMerge: options?.roleMerge ?? RoleMerge.OVERRIDE,
      roleMatch: options?.roleMatch ?? RoleMatch.ANY,
    },
  };
}

/** Providers idênticos em forRoot e forRootAsync (não dependem de ter opts na mão). */
export function buildCoreProviders(): Provider[] {
  return [
    {
      provide: AUTH_STRATEGIES_TOKEN,
      useFactory: (...injectedStrategies: IAuthStrategy[]): IAuthStrategy[] =>
        injectedStrategies,
      inject: [...strategies],
    },
    {
      provide: AUTH_VAULT_LOGGER_FACTORY,
      useFactory: (opts: IAuthVaultModuleOptions) => (context: string) =>
        new AuthVaultLogger(opts?.logLevels, context),
      inject: [AUTH_VAULT_OPTIONS],
    },
    {
      provide: AUTH_VAULT_SERVICE,
      useExisting: AuthVaultService,
    },
    AuthVaultService,
    ...strategies,
    {
      provide: APP_GUARD,
      useClass: AuthGuard,
    },
    {
      provide: APP_GUARD,
      useClass: ResourceGuard,
    },
    {
      provide: APP_GUARD,
      useClass: RoleGuard,
    },
  ];
}

/** Providers que dependem de options em modo síncrono (forRoot). */
export function buildOptionsProvidersSync(
  options: IAuthVaultModuleOptions,
): Provider[] {
  const guardOptions = buildGuardOptionsFromLibrary(options);
  return [
    {
      provide: AUTH_STRATEGY_CONFIG,
      useValue: options.strategyConfig,
    },
    {
      provide: AUTH_GUARD_OPTIONS,
      useValue: guardOptions.authGuard,
    },
    {
      provide: RESOURCE_GUARD_OPTIONS,
      useValue: guardOptions.resourceGuard,
    },
    {
      provide: ROLE_GUARD_OPTIONS,
      useValue: guardOptions.roleGuard,
    },
  ];
}

/** Providers que dependem de options em runtime via AUTH_VAULT_OPTIONS (forRootAsync). */
export function buildOptionsProvidersAsync(): Provider[] {
  return [
    {
      provide: AUTH_STRATEGY_CONFIG,
      useFactory: (opts: IAuthVaultModuleOptions) => opts.strategyConfig,
      inject: [AUTH_VAULT_OPTIONS],
    },
    {
      provide: AUTH_GUARD_OPTIONS,
      useFactory: (opts: IAuthVaultModuleOptions) =>
        buildGuardOptionsFromLibrary(opts).authGuard,
      inject: [AUTH_VAULT_OPTIONS],
    },
    {
      provide: RESOURCE_GUARD_OPTIONS,
      useFactory: (opts: IAuthVaultModuleOptions) =>
        buildGuardOptionsFromLibrary(opts).resourceGuard,
      inject: [AUTH_VAULT_OPTIONS],
    },
    {
      provide: ROLE_GUARD_OPTIONS,
      useFactory: (opts: IAuthVaultModuleOptions) =>
        buildGuardOptionsFromLibrary(opts).roleGuard,
      inject: [AUTH_VAULT_OPTIONS],
    },
  ];
}

export function buildProviders(options: IAuthVaultModuleOptions): Provider[] {
  const strategyName = options.strategyConfig?.name;
  if (!strategyName) throw new Error('Strategy name is required');

  return [...buildCoreProviders(), ...buildOptionsProvidersSync(options)];
}

/** Providers para forFeature (sync). Isolamento pelo módulo que importa; usa os mesmos tokens do forRoot. */
export function buildFeatureProviders(
  options: IAuthVaultModuleOptions,
): Provider[] {
  const strategyName = options.strategyConfig?.name;
  if (!strategyName) throw new Error('Strategy name is required');

  const guardOptions = buildGuardOptionsFromLibrary(options);
  const StrategyClass =
    AUTH_STRATEGIES_REGISTRY[
      strategyName as keyof typeof AUTH_STRATEGIES_REGISTRY
    ];
  if (!StrategyClass) throw new Error(`Strategy ${strategyName} not found`);

  return [
    { provide: AUTH_VAULT_OPTIONS, useValue: options },
    { provide: AUTH_STRATEGY_CONFIG, useValue: options.strategyConfig },
    { provide: AUTH_GUARD_OPTIONS, useValue: guardOptions.authGuard },
    { provide: RESOURCE_GUARD_OPTIONS, useValue: guardOptions.resourceGuard },
    { provide: ROLE_GUARD_OPTIONS, useValue: guardOptions.roleGuard },
    {
      provide: AUTH_VAULT_LOGGER_FACTORY,
      useFactory: (opts: IAuthVaultModuleOptions) => (context: string) =>
        new AuthVaultLogger(opts?.logLevels, context),
      inject: [AUTH_VAULT_OPTIONS],
    },
    {
      provide: FEATURE_STRATEGY_INSTANCE,
      useFactory: (
        config: IAuthVaultModuleOptions['strategyConfig'],
        httpService: HttpService,
        createLogger: (context: string) => IAuthVaultLogger,
      ) =>
        new StrategyClass(
          config as ConfigForStrategy<AuthStrategyName>,
          httpService,
          createLogger,
        ),
      inject: [AUTH_STRATEGY_CONFIG, HttpService, AUTH_VAULT_LOGGER_FACTORY],
    },
    {
      provide: AUTH_STRATEGIES_TOKEN,
      useFactory: (instance: IAuthStrategy) => [instance],
      inject: [FEATURE_STRATEGY_INSTANCE],
    },
    {
      provide: AuthVaultService,
      useFactory: (
        strategies: IAuthStrategy[],
        opts: IAuthVaultModuleOptions,
        createLogger: (context: string) => IAuthVaultLogger,
      ) => new AuthVaultService(strategies, opts, createLogger),
      inject: [
        AUTH_STRATEGIES_TOKEN,
        AUTH_VAULT_OPTIONS,
        AUTH_VAULT_LOGGER_FACTORY,
      ],
    },
    {
      provide: AUTH_VAULT_SERVICE,
      useExisting: AuthVaultService,
    },
    {
      provide: APP_GUARD,
      useFactory: (
        svc: IAuthVaultService,
        reflector: Reflector,
        createLogger: (context: string) => IAuthVaultLogger,
        guardOpts: AuthGuardOptions,
      ) => new AuthGuard(svc, reflector, createLogger, guardOpts),
      inject: [
        AUTH_VAULT_SERVICE,
        Reflector,
        AUTH_VAULT_LOGGER_FACTORY,
        AUTH_GUARD_OPTIONS,
      ],
    },
    {
      provide: APP_GUARD,
      useFactory: (
        reflector: Reflector,
        svc: IAuthVaultService,
        createLogger: (context: string) => IAuthVaultLogger,
        guardOpts: IRoleGuardOptions,
      ) => new RoleGuard(reflector, svc, createLogger, guardOpts),
      inject: [
        Reflector,
        AUTH_VAULT_SERVICE,
        AUTH_VAULT_LOGGER_FACTORY,
        ROLE_GUARD_OPTIONS,
      ],
    },
    {
      provide: APP_GUARD,
      useFactory: (
        reflector: Reflector,
        svc: IAuthVaultService,
        createLogger: (context: string) => IAuthVaultLogger,
        guardOpts: IResourceGuardOptions,
      ) => new ResourceGuard(reflector, svc, createLogger, guardOpts),
      inject: [
        Reflector,
        AUTH_VAULT_SERVICE,
        AUTH_VAULT_LOGGER_FACTORY,
        RESOURCE_GUARD_OPTIONS,
      ],
    },
  ];
}

/** Providers para forFeatureAsync. Mesmos tokens do forRoot; isolamento pelo módulo que importa. */
export function buildFeatureProvidersAsync(
  asyncOptions: AuthVaultFeatureAsyncOptions,
): Provider[] {
  const asyncProvider: Provider = {
    provide: AUTH_VAULT_OPTIONS,
    useFactory: asyncOptions.useFactory,
    inject: asyncOptions.inject ?? [],
  };

  return [
    asyncProvider,
    {
      provide: AUTH_STRATEGY_CONFIG,
      useFactory: (opts: IAuthVaultModuleOptions) => opts.strategyConfig,
      inject: [AUTH_VAULT_OPTIONS],
    },
    {
      provide: AUTH_GUARD_OPTIONS,
      useFactory: (opts: IAuthVaultModuleOptions) =>
        buildGuardOptionsFromLibrary(opts).authGuard,
      inject: [AUTH_VAULT_OPTIONS],
    },
    {
      provide: RESOURCE_GUARD_OPTIONS,
      useFactory: (opts: IAuthVaultModuleOptions) =>
        buildGuardOptionsFromLibrary(opts).resourceGuard,
      inject: [AUTH_VAULT_OPTIONS],
    },
    {
      provide: ROLE_GUARD_OPTIONS,
      useFactory: (opts: IAuthVaultModuleOptions) =>
        buildGuardOptionsFromLibrary(opts).roleGuard,
      inject: [AUTH_VAULT_OPTIONS],
    },
    {
      provide: AUTH_VAULT_LOGGER_FACTORY,
      useFactory: (opts: IAuthVaultModuleOptions) => (context: string) =>
        new AuthVaultLogger(opts?.logLevels, context),
      inject: [AUTH_VAULT_OPTIONS],
    },
    {
      provide: FEATURE_STRATEGY_INSTANCE,
      useFactory: (
        config: IAuthVaultModuleOptions['strategyConfig'],
        httpService: HttpService,
        createLogger: (context: string) => IAuthVaultLogger,
      ) => {
        const strategyName = config?.name;
        const StrategyClass = strategyName
          ? AUTH_STRATEGIES_REGISTRY[
              strategyName as keyof typeof AUTH_STRATEGIES_REGISTRY
            ]
          : null;
        if (!StrategyClass)
          throw new Error(`Strategy ${strategyName} not found`);
        return new StrategyClass(
          config as ConfigForStrategy<AuthStrategyName>,
          httpService,
          createLogger,
        );
      },
      inject: [AUTH_STRATEGY_CONFIG, HttpService, AUTH_VAULT_LOGGER_FACTORY],
    },
    {
      provide: AUTH_STRATEGIES_TOKEN,
      useFactory: (instance: IAuthStrategy) => [instance],
      inject: [FEATURE_STRATEGY_INSTANCE],
    },
    {
      provide: AuthVaultService,
      useFactory: (
        strategies: IAuthStrategy[],
        opts: IAuthVaultModuleOptions,
        createLogger: (context: string) => IAuthVaultLogger,
      ) => new AuthVaultService(strategies, opts, createLogger),
      inject: [
        AUTH_STRATEGIES_TOKEN,
        AUTH_VAULT_OPTIONS,
        AUTH_VAULT_LOGGER_FACTORY,
      ],
    },
    {
      provide: AUTH_VAULT_SERVICE,
      useExisting: AuthVaultService,
    },
    {
      provide: APP_GUARD,
      useFactory: (
        svc: IAuthVaultService,
        reflector: Reflector,
        createLogger: (context: string) => IAuthVaultLogger,
        guardOpts: AuthGuardOptions,
      ) => new AuthGuard(svc, reflector, createLogger, guardOpts),
      inject: [
        AUTH_VAULT_SERVICE,
        Reflector,
        AUTH_VAULT_LOGGER_FACTORY,
        AUTH_GUARD_OPTIONS,
      ],
    },
    {
      provide: APP_GUARD,
      useFactory: (
        reflector: Reflector,
        svc: IAuthVaultService,
        createLogger: (context: string) => IAuthVaultLogger,
        guardOpts: IRoleGuardOptions,
      ) => new RoleGuard(reflector, svc, createLogger, guardOpts),
      inject: [
        Reflector,
        AUTH_VAULT_SERVICE,
        AUTH_VAULT_LOGGER_FACTORY,
        ROLE_GUARD_OPTIONS,
      ],
    },
    {
      provide: APP_GUARD,
      useFactory: (
        reflector: Reflector,
        svc: IAuthVaultService,
        createLogger: (context: string) => IAuthVaultLogger,
        guardOpts: IResourceGuardOptions,
      ) => new ResourceGuard(reflector, svc, createLogger, guardOpts),
      inject: [
        Reflector,
        AUTH_VAULT_SERVICE,
        AUTH_VAULT_LOGGER_FACTORY,
        RESOURCE_GUARD_OPTIONS,
      ],
    },
  ];
}
