import {
  BadRequestException,
  ForbiddenException,
  Inject,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { AUTH_STRATEGIES_TOKEN } from './tokens/auth-strategies.token';
import { AuthStrategyName } from './strategies/strategies.registry';
import { ValidateApiResponse } from './types/validate-response.type';
import { AUTH_VAULT_OPTIONS } from './tokens';
import { AUTH_VAULT_LOGGER_FACTORY } from './constants/auth-vault-logger-factory.const';
import {
  type IAuthVaultModuleOptions,
  IAuthStrategy,
  IAuthVaultLogger,
  IAuthVaultService,
} from './interfaces';
import {
  LoginCredentialsDto,
  LoginResponseDto,
  LogoutCredentialsDto,
  LogoutResponseDto,
  RefreshTokenCredentialsDto,
  RefreshTokenResponseDto,
  TokenCredentialsDto,
  UserInfoResponseDto,
  ValidateResponseDto,
} from './dto';

/**
 * Central auth service: delegates to the configured strategy for login, logout,
 * refresh, validate, and role resolution. Inject AUTH_VAULT_SERVICE or AuthVaultService.
 */
@Injectable()
export class AuthVaultService implements IAuthVaultService {
  private readonly logger: IAuthVaultLogger;
  private readonly strategy!: IAuthStrategy;

  constructor(
    @Inject(AUTH_STRATEGIES_TOKEN)
    private readonly authStrategies: IAuthStrategy[],
    @Inject(AUTH_VAULT_OPTIONS)
    private readonly moduleOptions: IAuthVaultModuleOptions,
    @Inject(AUTH_VAULT_LOGGER_FACTORY)
    createLogger: (context: string) => IAuthVaultLogger,
  ) {
    this.logger = createLogger(AuthVaultService.name);
    const name = this.moduleOptions?.strategyConfig?.name;
    if (!name) throw new Error('Strategy name is required');
    this.strategy = this.getStrategy(name);
  }

  private getStrategy(strategyName: AuthStrategyName): IAuthStrategy {
    const strategy = this.authStrategies.find(
      (strategy) => strategy.name === strategyName,
    );

    if (!strategy) throw new Error(`Strategy ${strategyName} not found`);

    return strategy;
  }

  /**
   * Logs in with the strategy (e.g. username/password). Throws UnauthorizedException on failure.
   */
  async login(credentials: LoginCredentialsDto): Promise<LoginResponseDto> {
    const response = await this.strategy.login(credentials);

    if (response.success) return response.data;

    throw new UnauthorizedException(response.data);
  }

  /**
   * Logs out (e.g. refresh token or session). Throws BadRequestException on failure.
   */
  async logout(logoutToken: LogoutCredentialsDto): Promise<LogoutResponseDto> {
    const response = await this.strategy.logout(logoutToken);

    if (response.success) return response.data;

    throw new BadRequestException(response.data);
  }

  /**
   * Exchanges a refresh token for new tokens. Throws UnauthorizedException on failure.
   */
  async refreshToken(
    refreshToken: RefreshTokenCredentialsDto,
  ): Promise<RefreshTokenResponseDto> {
    const response = await this.strategy.refreshToken(refreshToken);

    if (response.success) return response.data;

    throw new UnauthorizedException(response.data);
  }

  /**
   * Returns user info for the given token. Throws UnauthorizedException/ForbiddenException/BadRequestException on failure.
   */
  async getUserInfo(token: TokenCredentialsDto): Promise<UserInfoResponseDto> {
    const response = await this.strategy.getUserInfo(token);

    if (response.success) return response.data;

    if (response.statusCode === 401)
      throw new UnauthorizedException(response.data);
    if (response.statusCode === 403)
      throw new ForbiddenException(response.data);
    throw new BadRequestException(response.data);
  }

  /**
   * Validates a token (introspect/JWT). Used by AuthGuard to attach user to request.
   */
  async validate(
    credentials: TokenCredentialsDto,
  ): Promise<ValidateApiResponse> {
    return await this.strategy.validate(credentials);
  }

  /**
   * Returns roles for the user on the given resource. Used by ResourceGuard.
   */
  async getRolesForResource(
    user: ValidateResponseDto,
    resource: string,
  ): Promise<string[]> {
    const roles = await this.strategy.getRolesForResource(user, resource);
    return Array.isArray(roles) ? roles : [];
  }

  /**
   * Returns all roles for the user. Used by RoleGuard.
   */
  async getRoles(user: ValidateResponseDto): Promise<string[]> {
    const roles = await this.strategy.getRoles(user);
    return Array.isArray(roles) ? roles : [];
  }
}
