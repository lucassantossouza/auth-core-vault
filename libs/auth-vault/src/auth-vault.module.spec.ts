import { Test, TestingModule } from '@nestjs/testing';
import { HttpModule } from '@nestjs/axios';
import {
  AuthVaultModule,
  buildAsyncOptionsProvider,
} from './auth-vault.module';
import { AuthVaultService } from './auth-vault.service';
import { AUTH_VAULT_SERVICE } from './tokens';
import type { IAuthVaultModuleOptions } from './interfaces';
import type {
  AuthVaultOptionsFactory,
  AuthVaultModuleAsyncOptions,
} from './types';

const validKeycloakConfig: IAuthVaultModuleOptions['strategyConfig'] = {
  name: 'keycloak',
  clientId: 'test',
  clientSecret: 'secret',
  realm: 'realm',
  url: 'https://auth.example.com',
};

class TestOptionsFactory implements AuthVaultOptionsFactory {
  createAuthVaultOptions(): Promise<IAuthVaultModuleOptions> {
    return Promise.resolve({
      strategyConfig: validKeycloakConfig,
    });
  }
}

describe('AuthVaultModule', () => {
  describe('forRoot', () => {
    it('compila e exporta AuthVaultService', async () => {
      const module: TestingModule = await Test.createTestingModule({
        imports: [
          HttpModule,
          AuthVaultModule.forRoot({
            strategyConfig:
              validKeycloakConfig as IAuthVaultModuleOptions['strategyConfig'],
          }),
        ],
      }).compile();

      const service = module.get(AuthVaultService);
      expect(service).toBeDefined();
      expect(module.get(AUTH_VAULT_SERVICE)).toBe(service);
    });

    it('aceita isGlobal', () => {
      const dynamic = AuthVaultModule.forRoot({
        strategyConfig:
          validKeycloakConfig as IAuthVaultModuleOptions['strategyConfig'],
        isGlobal: true,
      });
      expect(dynamic.global).toBe(true);
    });

    it('lança quando strategyConfig ou name está ausente', () => {
      expect(() =>
        AuthVaultModule.forRoot({} as IAuthVaultModuleOptions),
      ).toThrow(/Strategy name is required/);
    });
  });

  describe('forFeature', () => {
    it('retorna DynamicModule com providers', () => {
      const dynamic = AuthVaultModule.forFeature({
        strategyConfig:
          validKeycloakConfig as IAuthVaultModuleOptions['strategyConfig'],
      });
      expect(dynamic.module).toBe(AuthVaultModule);
      expect(dynamic.global).toBe(false);
      expect(dynamic.providers?.length).toBeGreaterThan(0);
    });

    it('compila e exporta AuthVaultService', async () => {
      const module: TestingModule = await Test.createTestingModule({
        imports: [
          HttpModule,
          AuthVaultModule.forFeature({
            strategyConfig:
              validKeycloakConfig as IAuthVaultModuleOptions['strategyConfig'],
          }),
        ],
      }).compile();

      expect(module.get(AuthVaultService)).toBeDefined();
    });
  });

  describe('forRootAsync', () => {
    it('compila com useFactory', async () => {
      const module: TestingModule = await Test.createTestingModule({
        imports: [
          HttpModule,
          AuthVaultModule.forRootAsync({
            isGlobal: false,
            useFactory: () => ({
              strategyConfig: validKeycloakConfig,
            }),
            inject: [],
          }),
        ],
      }).compile();

      expect(module.get(AuthVaultService)).toBeDefined();
    });

    it('retorna dynamic com isGlobal false quando isGlobal não informado (branch 57)', () => {
      const dynamic = AuthVaultModule.forRootAsync({
        useFactory: () => ({ strategyConfig: validKeycloakConfig }),
        inject: [],
      });
      expect(dynamic.global).toBe(false);
    });

    it('retorna dynamic com isGlobal true quando informado (branch 57)', () => {
      const dynamic = AuthVaultModule.forRootAsync({
        isGlobal: true,
        useFactory: () => ({ strategyConfig: validKeycloakConfig }),
        inject: [],
      });
      expect(dynamic.global).toBe(true);
    });

    it('lança quando não fornece useFactory, useClass nem useExisting', () => {
      expect(() =>
        AuthVaultModule.forRootAsync({
          isGlobal: false,
          inject: [],
        } as unknown as AuthVaultModuleAsyncOptions),
      ).toThrow(/useFactory|useClass|useExisting/);
    });

    it('retorna DynamicModule com useClass (cobre createAsyncOptionsProvider useClass)', () => {
      const dynamic = AuthVaultModule.forRootAsync({
        isGlobal: false,
        useClass: TestOptionsFactory,
      });
      expect(dynamic.module).toBe(AuthVaultModule);
      expect(dynamic.providers?.length).toBeGreaterThan(0);
      const providerWithInject = dynamic.providers?.find(
        (p) =>
          typeof p === 'object' &&
          p !== null &&
          'inject' in p &&
          Array.isArray((p as unknown as Record<string, unknown>).inject),
      ) as { inject: unknown[] } | undefined;
      expect(providerWithInject?.inject).toEqual([TestOptionsFactory]);
    });

    it('buildAsyncOptionsProvider com useFactory e inject vazio/undefined (branch 116)', () => {
      const provider = buildAsyncOptionsProvider({
        isGlobal: false,
        useFactory: () => ({ strategyConfig: validKeycloakConfig }),
      });
      expect((provider as unknown as { inject: unknown[] }).inject).toEqual([]);
    });

    it('buildAsyncOptionsProvider com useFactory e inject preenchido (branch 116)', () => {
      const token = Symbol('injectToken');
      const provider = buildAsyncOptionsProvider({
        isGlobal: false,
        useFactory: () => ({ strategyConfig: validKeycloakConfig }),
        inject: [token],
      });
      expect(provider).toBeDefined();
      const p = provider as unknown as { inject: unknown[] };
      expect(p.inject).toEqual([token]);
    });

    it('buildAsyncOptionsProvider com useExisting retorna provider com inject', () => {
      const provider = buildAsyncOptionsProvider({
        isGlobal: false,
        useExisting: TestOptionsFactory,
      });
      expect((provider as unknown as { inject: unknown[] }).inject).toEqual([
        TestOptionsFactory,
      ]);
    });

    it('buildAsyncOptionsProvider com useClass retorna provider com inject e useFactory (linhas 120 e 131)', async () => {
      const provider = buildAsyncOptionsProvider({
        isGlobal: false,
        useClass: TestOptionsFactory,
      });
      expect(provider).toBeDefined();
      expect(
        typeof provider === 'object' &&
          provider !== null &&
          'inject' in provider &&
          Array.isArray((provider as unknown as { inject: unknown }).inject),
      ).toBe(true);
      expect((provider as unknown as { inject: unknown[] }).inject).toEqual([
        TestOptionsFactory,
      ]);
      const useFactory = (
        provider as {
          useFactory: (
            f: AuthVaultOptionsFactory,
          ) => Promise<IAuthVaultModuleOptions>;
        }
      ).useFactory;
      const opts = await useFactory(new TestOptionsFactory());
      expect(opts.strategyConfig).toEqual(validKeycloakConfig);
    });
  });

  describe('forFeatureAsync', () => {
    it('retorna DynamicModule com useFactory', () => {
      const dynamic = AuthVaultModule.forFeatureAsync({
        useFactory: () => ({ strategyConfig: validKeycloakConfig }),
        inject: [],
      });
      expect(dynamic.module).toBe(AuthVaultModule);
      expect(dynamic.providers?.length).toBeGreaterThan(0);
    });

    it('compila e exporta AuthVaultService', async () => {
      const module: TestingModule = await Test.createTestingModule({
        imports: [
          HttpModule,
          AuthVaultModule.forFeatureAsync({
            useFactory: () => ({
              strategyConfig: validKeycloakConfig,
            }),
            inject: [],
          }),
        ],
      }).compile();

      expect(module.get(AuthVaultService)).toBeDefined();
    });

    it('lança ao compilar quando strategyConfig.name não existe no registry', async () => {
      await expect(
        Test.createTestingModule({
          imports: [
            HttpModule,
            AuthVaultModule.forFeatureAsync({
              useFactory: () => ({
                strategyConfig: {
                  name: 'invalid-strategy',
                } as unknown as IAuthVaultModuleOptions['strategyConfig'],
              }),
              inject: [],
            }),
          ],
        }).compile(),
      ).rejects.toThrow(/Strategy .* not found/);
    });
  });
});
