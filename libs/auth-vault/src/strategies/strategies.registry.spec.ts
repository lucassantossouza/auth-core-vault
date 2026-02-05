import {
  STRATEGY_NAMES,
  AUTH_STRATEGIES_REGISTRY,
  type AuthStrategyName,
  type AuthStrategyClass,
} from './strategies.registry';
import { KeycloakStrategy } from './keycloak/keycloak.strategy';

describe('strategies.registry', () => {
  it('STRATEGY_NAMES contém keycloak', () => {
    expect(STRATEGY_NAMES.keycloak).toBe('keycloak');
  });

  it('AUTH_STRATEGIES_REGISTRY associa keycloak à KeycloakStrategy', () => {
    expect(AUTH_STRATEGIES_REGISTRY.keycloak).toBe(KeycloakStrategy);
  });

  it('AuthStrategyName é union dos nomes do registry', () => {
    const name: AuthStrategyName = 'keycloak';
    expect(name).toBe('keycloak');
  });

  it('AuthStrategyClass keycloak é KeycloakStrategy', () => {
    const StrategyClass: AuthStrategyClass<'keycloak'> =
      AUTH_STRATEGIES_REGISTRY.keycloak;
    expect(StrategyClass).toBe(KeycloakStrategy);
  });
});
