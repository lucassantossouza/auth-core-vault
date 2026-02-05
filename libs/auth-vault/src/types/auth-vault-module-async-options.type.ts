import type { ConfigurableModuleAsyncOptions } from '@nestjs/common';
import type { IAuthVaultModuleOptions } from '../interfaces/auth-vault-module-options.interface';

/**
 * Objeto retornado pela useFactory do forRootAsync.
 * isGlobal é proibido aqui: use no nível do forRootAsync (opção de registro do módulo).
 */
export type AuthVaultModuleOptionsFactoryReturn = Omit<
  IAuthVaultModuleOptions,
  'isGlobal'
> & {
  /** Não use aqui. Passe isGlobal nas opções do forRootAsync. */
  isGlobal?: never;
};

/**
 * Opções assíncronas do AuthVault (forRootAsync).
 * isGlobal deve ser passado aqui (nível do forRootAsync), não dentro da useFactory.
 */
export type AuthVaultModuleAsyncOptions = Omit<
  ConfigurableModuleAsyncOptions<
    IAuthVaultModuleOptions,
    'createAuthVaultOptions'
  >,
  'useFactory'
> & {
  /** Se true, o módulo fica global. Passar aqui, não dentro da useFactory. */
  isGlobal?: boolean;
  useFactory?: (
    ...args: any[]
  ) =>
    | Promise<AuthVaultModuleOptionsFactoryReturn>
    | AuthVaultModuleOptionsFactoryReturn;
};
