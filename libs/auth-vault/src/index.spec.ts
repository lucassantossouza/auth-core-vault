import * as authVault from './index';

const validKeycloakConfig = {
  name: 'keycloak',
  clientId: 'test',
  clientSecret: 'secret',
  realm: 'realm',
  url: 'https://auth.example.com',
};

describe('auth-vault index', () => {
  it('exporta AuthVaultModule e AuthVaultService', () => {
    expect(authVault.AuthVaultModule).toBeDefined();
    expect(authVault.AuthVaultService).toBeDefined();
  });

  it('exporta constants, decorators, guards, tokens', () => {
    expect(authVault.AUTH_VAULT_SERVICE).toBeDefined();
    expect(authVault.Public).toBeDefined();
    expect(authVault.AuthGuard).toBeDefined();
  });

  it('forRoot pode ser chamado via barrel e retorna DynamicModule', () => {
    const dynamic = authVault.AuthVaultModule.forRoot({
      strategyConfig: validKeycloakConfig as Parameters<
        typeof authVault.AuthVaultModule.forRoot
      >[0]['strategyConfig'],
    });
    expect(dynamic.module).toBe(authVault.AuthVaultModule);
    expect(dynamic.global).toBe(false);
    expect(dynamic.providers?.length).toBeGreaterThan(0);
  });

  it('forFeature pode ser chamado via barrel e retorna DynamicModule', () => {
    const dynamic = authVault.AuthVaultModule.forFeature({
      strategyConfig: validKeycloakConfig as Parameters<
        typeof authVault.AuthVaultModule.forFeature
      >[0]['strategyConfig'],
    });
    expect(dynamic.module).toBe(authVault.AuthVaultModule);
    expect(dynamic.global).toBe(false);
    expect(dynamic.providers?.length).toBeGreaterThan(0);
  });

  it('forRootAsync pode ser chamado via barrel', () => {
    const dynamic = authVault.AuthVaultModule.forRootAsync({
      useFactory: () => ({ strategyConfig: validKeycloakConfig }),
      inject: [],
    });
    expect(dynamic.module).toBe(authVault.AuthVaultModule);
    expect(dynamic.providers?.length).toBeGreaterThan(0);
  });

  it('forFeatureAsync pode ser chamado via barrel', () => {
    const dynamic = authVault.AuthVaultModule.forFeatureAsync({
      useFactory: () => ({ strategyConfig: validKeycloakConfig }),
      inject: [],
    });
    expect(dynamic.module).toBe(authVault.AuthVaultModule);
    expect(dynamic.providers?.length).toBeGreaterThan(0);
  });
});
