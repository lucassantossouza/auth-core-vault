import type { AuthVaultModuleOptionsFactoryReturn } from './auth-vault-module-async-options.type';

export interface AuthVaultFeatureAsyncOptions {
  useFactory: (
    ...args: any[]
  ) =>
    | Promise<AuthVaultModuleOptionsFactoryReturn>
    | AuthVaultModuleOptionsFactoryReturn;
  inject?: any[];
}
