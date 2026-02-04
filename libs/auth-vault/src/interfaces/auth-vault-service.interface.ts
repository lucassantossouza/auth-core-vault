import { ValidateApiResponse } from '@app/auth-vault/types';
import {
  LoginCredentialsDto,
  LoginResponseDto,
  LogoutCredentialsDto,
  LogoutResponseDto,
  ValidateResponseDto,
  RefreshTokenCredentialsDto,
  RefreshTokenResponseDto,
  TokenCredentialsDto,
  UserInfoResponseDto,
} from '@app/auth-vault/dto';

/**
 * Auth service contract. Guards and controllers should depend on this interface (inject AUTH_VAULT_SERVICE).
 */
export interface IAuthVaultService {
  validate(credentials: { token: string }): Promise<ValidateApiResponse>;
  getRoles(user: ValidateResponseDto): Promise<string[]>;
  getRolesForResource(
    user: ValidateResponseDto,
    resource: string,
  ): Promise<string[]>;
  login(credentials: LoginCredentialsDto): Promise<LoginResponseDto>;
  logout(credentials: LogoutCredentialsDto): Promise<LogoutResponseDto>;
  refreshToken(
    credentials: RefreshTokenCredentialsDto,
  ): Promise<RefreshTokenResponseDto>;
  getUserInfo(credentials: TokenCredentialsDto): Promise<UserInfoResponseDto>;
}
