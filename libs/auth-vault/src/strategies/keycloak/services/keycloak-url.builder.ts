import { ConfigForStrategy } from '@app/auth-vault/types';

export class KeycloakUrlBuilder {
  constructor(private readonly config: ConfigForStrategy<'keycloak'>) {}

  tokenEndpoint(): string {
    return `${this.config.url}/realms/${this.config.realm}/protocol/openid-connect/token`;
  }

  userInfoEndpoint(): string {
    return `${this.config.url}/realms/${this.config.realm}/protocol/openid-connect/userinfo`;
  }

  logoutEndpoint(): string {
    return `${this.config.url}/realms/${this.config.realm}/protocol/openid-connect/revoke`;
  }

  loginEndpoint(): string {
    return `${this.config.url}/realms/${this.config.realm}/protocol/openid-connect/login`;
  }

  refreshTokenEndpoint(): string {
    return `${this.config.url}/realms/${this.config.realm}/protocol/openid-connect/token`;
  }

  validateTokenEndpoint(): string {
    return `${this.config.url}/realms/${this.config.realm}/protocol/openid-connect/token/introspect`;
  }
}
