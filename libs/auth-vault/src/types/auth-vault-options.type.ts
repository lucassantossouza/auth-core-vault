import type { ConfigurableModuleOptionsFactory } from '@nestjs/common';
import type { IAuthVaultModuleOptions } from '../interfaces/auth-vault-module-options.interface';

/**
 * Factory das opções do AuthVault (forRootAsync com useClass/useExisting). Padrão NestJS.
 */
export type AuthVaultOptionsFactory = ConfigurableModuleOptionsFactory<
  IAuthVaultModuleOptions,
  'createAuthVaultOptions'
>;
