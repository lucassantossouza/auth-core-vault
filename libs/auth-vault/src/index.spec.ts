import * as authVault from './index';

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
});
