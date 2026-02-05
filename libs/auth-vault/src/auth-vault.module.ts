import { DynamicModule, Module, Provider } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { AUTH_VAULT_OPTIONS, AUTH_VAULT_SERVICE } from './tokens';
import { AuthVaultModuleAsyncOptions, AuthVaultOptionsFactory } from './types';
import { IAuthVaultModuleOptions } from './interfaces';
import { AuthVaultFeatureAsyncOptions } from './types/auth-vault-feature-options.type';
import { AuthVaultService } from './auth-vault.service';
import { defaultHttpOptions } from './constants';
import {
  buildProviders,
  buildCoreProviders,
  buildOptionsProvidersAsync,
  buildFeatureProviders,
  buildFeatureProvidersAsync,
} from './auth-vault.providers';

const rootImports = [HttpModule.register(defaultHttpOptions)];

/**
 * NestJS module for Auth Vault: token validation, login/logout/refresh, and guards.
 * Register with forRoot/forRootAsync (app root) or forFeature/forFeatureAsync (scoped).
 *
 * @example
 * ```ts
 * // app.module.ts
 * AuthVaultModule.forRoot({
 *   strategyConfig: { name: 'keycloak', ...keycloakConfig },
 *   isGlobal: true,
 * })
 * ```
 */
@Module({})
export class AuthVaultModule {
  /**
   * Registers Auth Vault at app root with synchronous options.
   * @param options - strategyConfig, optional guard options (authGuard, resourceGuard, roleGuard), http, logLevels, isGlobal
   */
  static forRoot(options: IAuthVaultModuleOptions): DynamicModule {
    const opts = { ...options };
    const providers: Provider[] = [
      { provide: AUTH_VAULT_OPTIONS, useValue: opts },
      ...buildProviders(opts),
    ];
    const httpOptions = { ...defaultHttpOptions, ...opts.http };

    return {
      module: AuthVaultModule,
      global: options.isGlobal ?? false,
      imports: [...rootImports, HttpModule.register(httpOptions)],
      providers,
      exports: [AuthVaultService, AUTH_VAULT_SERVICE],
      controllers: [],
    };
  }

  /**
   * Registers Auth Vault at app root with async options (e.g. useFactory + ConfigService).
   * @param options - useFactory, useClass, or useExisting; optional imports, inject, isGlobal
   * @example
   * ```ts
   * AuthVaultModule.forRootAsync({
   *   imports: [ConfigModule],
   *   inject: [ConfigService],
   *   useFactory: (config: ConfigService) => ({ strategyConfig: { name: 'keycloak', ...config.get('keycloak') } }),
   *   isGlobal: true,
   * })
   * ```
   */
  static forRootAsync(options: AuthVaultModuleAsyncOptions): DynamicModule {
    const asyncProvider = AuthVaultModule.createAsyncOptionsProvider(options);
    const providers: Provider[] = [
      asyncProvider,
      ...buildCoreProviders(),
      ...buildOptionsProvidersAsync(),
    ];

    return {
      module: AuthVaultModule,
      global: options.isGlobal ?? false,
      imports: rootImports,
      providers,
      exports: [AuthVaultService, AUTH_VAULT_SERVICE],
      controllers: [],
    };
  }

  /**
   * Registers Auth Vault for the importing module only (synchronous config).
   * Use AUTH_VAULT_SERVICE or inject AuthVaultService in controllers.
   */
  static forFeature(options: IAuthVaultModuleOptions): DynamicModule {
    const providers = buildFeatureProviders(options);
    return {
      module: AuthVaultModule,
      global: false,
      imports: [HttpModule.register(defaultHttpOptions)],
      providers,
      exports: [AuthVaultService, AUTH_VAULT_SERVICE],
      controllers: [],
    };
  }

  /**
   * Registers Auth Vault for the importing module only (async config).
   */
  static forFeatureAsync(
    asyncOptions: AuthVaultFeatureAsyncOptions,
  ): DynamicModule {
    const providers = buildFeatureProvidersAsync(asyncOptions);
    return {
      module: AuthVaultModule,
      global: false,
      imports: [HttpModule.register(defaultHttpOptions)],
      providers,
      exports: [AuthVaultService, AUTH_VAULT_SERVICE],
      controllers: [],
    };
  }

  private static createAsyncOptionsProvider(
    options: AuthVaultModuleAsyncOptions,
  ): Provider {
    return buildAsyncOptionsProvider(options);
  }
}

/**
 * Builds the async options provider (useFactory / useClass / useExisting).
 * @internal Exported for tests
 */
export function buildAsyncOptionsProvider(
  options: AuthVaultModuleAsyncOptions,
): Provider {
  if (options.useFactory) {
    return {
      provide: AUTH_VAULT_OPTIONS,
      useFactory: options.useFactory,
      inject: options.inject || [],
    };
  }

  const useClass = options.useClass ?? options.useExisting;
  if (!useClass)
    throw new Error(
      'AuthVaultModuleAsyncOptions must provide useFactory, useClass or useExisting',
    );

  return {
    provide: AUTH_VAULT_OPTIONS,
    useFactory: async (
      factory: AuthVaultOptionsFactory,
    ): Promise<IAuthVaultModuleOptions> =>
      await factory.createAuthVaultOptions(),
    inject: [useClass],
  };
}
