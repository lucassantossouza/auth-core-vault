import { KeycloakConfigDto } from '../strategies/keycloak/dto/keycloak-config.dto';
import type { AuthStrategyName } from '../strategies/strategies.registry';

export const StrategyConfigDtoClassMap = {
  keycloak: KeycloakConfigDto,
} as const;

export type StrategyConfigDtoMap = {
  [K in keyof typeof StrategyConfigDtoClassMap]: InstanceType<
    (typeof StrategyConfigDtoClassMap)[K]
  >;
};

/** Tipo do DTO de config para a strategy K (inferido do mapa central). */
export type StrategyConfigDto<T extends AuthStrategyName = AuthStrategyName> =
  StrategyConfigDtoMap[T];

/**
 * Config completa injetada (DTO + name). Usado em AuthVaultModuleOptions.strategyConfig
 * e no construtor das strategies (param config).
 */
export type StrategyConfigMap = {
  [K in AuthStrategyName]: StrategyConfigDtoMap[K] & { name: K };
}[AuthStrategyName];

/** Config recebida por uma strategy específica K (para tipar o @Inject(AUTH_STRATEGY_CONFIG)). */
export type ConfigForStrategy<K extends AuthStrategyName> =
  StrategyConfigDtoMap[K] & { name: K };
