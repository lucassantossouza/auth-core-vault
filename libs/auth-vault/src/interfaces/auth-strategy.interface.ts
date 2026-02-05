import { ValidateResponseDto } from '../dto';
import { LoginCredentialsDto } from '../dto/login-credentials.dto';
import { LogoutCredentialsDto } from '../dto/logout-credentials.dto';
import { RefreshTokenCredentialsDto } from '../dto/refresh-token-credentials.dto';
import { TokenCredentialsDto } from '../dto/token-credentials.dto';
import { LoginApiResponse } from '../types/login-response.type';
import { LogoutApiResponse } from '../types/logout-response.type';
import { RefreshTokenApiResponse } from '../types/refresh-token-response.type';
import { UserInfoApiResponse } from '../types/user-info-response.type';
import { ValidateApiResponse } from '../types/validate-response.type';

/** Identifier used to resolve a strategy (e.g. strategy name or "type:instance"). */
export type AuthStrategyId = string;

/**
 * Strategy contract for auth operations. Implement for Keycloak or custom IdPs.
 */
export interface IAuthStrategy {
  readonly name: string;

  /** Performs login (e.g. username/password). */
  login: (credentials: LoginCredentialsDto) => Promise<LoginApiResponse>;
  /** Performs logout (e.g. refresh token or session). */
  logout: (logoutToken: LogoutCredentialsDto) => Promise<LogoutApiResponse>;
  /** Exchanges refresh token for new tokens. */
  refreshToken: (
    credentials: RefreshTokenCredentialsDto,
  ) => Promise<RefreshTokenApiResponse>;
  /** Returns user info for the given token. */
  getUserInfo: (
    credentials: TokenCredentialsDto,
  ) => Promise<UserInfoApiResponse>;
  /** Validates token (introspect or JWT). Used by AuthGuard. */
  validate: (credentials: TokenCredentialsDto) => Promise<ValidateApiResponse>;
  /** Returns user roles/scopes for the resource. Used by ResourceGuard. */
  getRolesForResource: (
    user: ValidateResponseDto,
    resource: string,
  ) => string[] | Promise<string[]>;
  /** Returns all user roles (realm + resource_access). Used by RoleGuard. */
  getRoles: (user: ValidateResponseDto) => string[] | Promise<string[]>;
}
