import { AuthStrategyName } from '../strategies/strategies.registry';
import { HttpModuleOptions } from '@nestjs/axios';
import { StrategyConfigMap } from '../types/strategy-config-dto.types';
import { AuthVaultLibraryOptions } from './auth-vault-library-options.interface';

export type StrategyName = AuthStrategyName;

export const AuthLogLevel = {
  SILENT: 'silent',
  ERROR: 'error',
  WARN: 'warn',
  VERBOSE: 'verbose',
  DEBUG: 'debug',
  LOG: 'log',
} as const;

export type AuthLogLevelValue =
  (typeof AuthLogLevel)[keyof typeof AuthLogLevel];

/**
 * Root module options. strategyConfig key = strategy name, value = strategy-specific config (each strategy validates with its own DTO).
 */
export interface IAuthVaultModuleOptions extends AuthVaultLibraryOptions {
  /** Whether the module is global. */
  isGlobal?: boolean;
  /** Per-strategy config: key = strategy name, value = config object. */
  strategyConfig?: StrategyConfigMap;
  /** HttpModule options (timeout, etc.). */
  http?: HttpModuleOptions;
  /** Log levels (silent, error, warn, verbose, debug, log). */
  logLevels?: AuthLogLevelValue | AuthLogLevelValue[] | undefined;
}
