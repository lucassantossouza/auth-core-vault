import { KeycloakStrategy } from './keycloak/keycloak.strategy';

export const STRATEGY_NAMES = {
  keycloak: 'keycloak',
} as const;

export const AUTH_STRATEGIES_REGISTRY = {
  [STRATEGY_NAMES.keycloak]: KeycloakStrategy,
} as const;

export type AuthStrategyName = keyof typeof AUTH_STRATEGIES_REGISTRY;

export type AuthStrategyClass<T extends AuthStrategyName> =
  (typeof AUTH_STRATEGIES_REGISTRY)[T];
