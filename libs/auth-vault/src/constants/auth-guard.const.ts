import { TokenValidation } from './token-validation.const';

export const AUTH_GUARD_OPTIONS = Symbol('AUTH_GUARD_OPTIONS');
export const AUTH_GUARD_COOKIE_DEFAULT = 'auth-token';

export interface AuthGuardOptions {
  cookieKey?: string;

  /** Modo de validação do token: via servidor (ONLINE) ou só assinatura JWT (OFFLINE). */
  tokenValidation?: TokenValidation;
}
