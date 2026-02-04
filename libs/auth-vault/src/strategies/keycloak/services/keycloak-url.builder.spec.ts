import { KeycloakUrlBuilder } from './keycloak-url.builder';
import type { ConfigForStrategy } from '../../../types';

function makeConfig(
  overrides: Partial<ConfigForStrategy<'keycloak'>> = {},
): ConfigForStrategy<'keycloak'> {
  return {
    name: 'keycloak',
    clientId: 'app',
    clientSecret: 'secret',
    realm: 'myrealm',
    url: 'https://auth.example.com',
    ...overrides,
  };
}

describe('KeycloakUrlBuilder', () => {
  let builder: KeycloakUrlBuilder;

  beforeEach(() => {
    builder = new KeycloakUrlBuilder(makeConfig());
  });

  it('tokenEndpoint retorna URL do token', () => {
    expect(builder.tokenEndpoint()).toBe(
      'https://auth.example.com/realms/myrealm/protocol/openid-connect/token',
    );
  });

  it('userInfoEndpoint retorna URL do userinfo', () => {
    expect(builder.userInfoEndpoint()).toBe(
      'https://auth.example.com/realms/myrealm/protocol/openid-connect/userinfo',
    );
  });

  it('logoutEndpoint retorna URL de revoke', () => {
    expect(builder.logoutEndpoint()).toBe(
      'https://auth.example.com/realms/myrealm/protocol/openid-connect/revoke',
    );
  });

  it('loginEndpoint retorna URL de login', () => {
    expect(builder.loginEndpoint()).toBe(
      'https://auth.example.com/realms/myrealm/protocol/openid-connect/login',
    );
  });

  it('refreshTokenEndpoint retorna URL do token', () => {
    expect(builder.refreshTokenEndpoint()).toBe(
      'https://auth.example.com/realms/myrealm/protocol/openid-connect/token',
    );
  });

  it('validateTokenEndpoint retorna URL de introspect', () => {
    expect(builder.validateTokenEndpoint()).toBe(
      'https://auth.example.com/realms/myrealm/protocol/openid-connect/token/introspect',
    );
  });

  it('usa realm e url do config', () => {
    const custom = new KeycloakUrlBuilder(
      makeConfig({ realm: 'other', url: 'https://keycloak.local' }),
    );
    expect(custom.tokenEndpoint()).toBe(
      'https://keycloak.local/realms/other/protocol/openid-connect/token',
    );
  });
});
