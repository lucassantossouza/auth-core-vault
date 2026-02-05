import { AUTH_METHOD_HEADER } from './../constants/auth-method-header.const';
import { validateSync } from 'class-validator';
import { plainToInstance } from 'class-transformer';
import { IAuthStrategy } from '../interfaces/auth-strategy.interface';
import { LoginApiResponse } from '../types/login-response.type';
import { LogoutApiResponse } from '../types/logout-response.type';
import { LogoutCredentialsDto } from '../dto/logout-credentials.dto';
import { LoginCredentialsDto } from '../dto/login-credentials.dto';
import { HttpService } from '@nestjs/axios';
import { Method, AxiosResponse } from 'axios';
import { firstValueFrom, retry, throwError, timer, catchError } from 'rxjs';
import { RefreshTokenApiResponse } from '../types/refresh-token-response.type';
import { RefreshTokenCredentialsDto } from '../dto/refresh-token-credentials.dto';
import { UserInfoApiResponse } from '../types/user-info-response.type';
import { TokenCredentialsDto } from '../dto/token-credentials.dto';
import { ValidateApiResponse } from '../types/validate-response.type';
import { ValidateResponseDto } from '../dto/validate-response.dto';
import { AuthStrategyName } from './strategies.registry';
import { ConfigForStrategy, StrategyConfigDtoClassMap } from '../types';
import { IAuthVaultLogger } from '../interfaces/auth-vault.logger.interface';

type AuthHeaderBearerOptions = {
  token: string;
};

type AuthHeaderBasicOptions = {
  identifier: string;
  secret: string;
};

/** Auth header: Bearer (token) or Basic (identifier + secret). */
export type AuthHeaderOptions =
  | AuthHeaderBearerOptions
  | AuthHeaderBasicOptions;

/**
 * Base class for auth strategies. Validates config with the strategy DTO, provides request() with retry and auth headers.
 * Extend and implement login, logout, refreshToken, getUserInfo, validate, getRoles, getRolesForResource.
 */
export abstract class AuthStrategyBase<
  K extends AuthStrategyName,
> implements IAuthStrategy {
  readonly name!: K;
  readonly logger!: IAuthVaultLogger;
  protected readonly httpService?: HttpService;

  protected readonly config: ConfigForStrategy<K>;

  constructor(
    config: ConfigForStrategy<K>,
    createLogger: (context: string) => IAuthVaultLogger,
    httpService?: HttpService,
  ) {
    if (!config) {
      const msg = `Config is required for ${this.constructor.name}`;
      const logger = createLogger(this.constructor.name);
      logger.error(msg);
      throw new Error(msg);
    }
    this.name = config.name;
    this.logger = createLogger(this.constructor.name);

    const DtoClass = StrategyConfigDtoClassMap[this.name];

    this.config = this.validateAndTransformConfig(
      config as Record<string, unknown>,
      DtoClass,
    ) as ConfigForStrategy<K>;

    this.httpService = httpService;

    this.logger.log(`Strategy ${this.name} initialized`);
  }

  // Validação síncrona no construtor (similar às pipes do NestJS)
  private validateAndTransformConfig<T>(
    config: Record<string, unknown>,
    DtoClass: new () => T,
  ): T {
    // Transforma para instância do DTO (similar ao que pipes fazem)
    const dto = plainToInstance<T, typeof DtoClass>(
      DtoClass,
      config as unknown as (new () => T)[],
      {
        enableImplicitConversion: true,
        excludeExtraneousValues: false,
      },
    );

    // Verifica se a transformação funcionou
    if (!dto || !(dto instanceof DtoClass)) {
      const msg = `Failed to transform config for ${this.name}`;
      this.logger.error(msg);
      throw new Error(msg);
    }

    // Valida usando class-validator (mesmo que pipes usam)
    const errors = validateSync(dto, {
      whitelist: true,
      forbidNonWhitelisted: false,
      skipMissingProperties: false,
    });

    if (errors.length > 0) {
      const errorMessages = errors
        .map((e) => Object.values(e.constraints || {}))
        .flat()
        .join(', ');
      const msg = `Invalid ${this.name} config: ${errorMessages}`;
      this.logger.error(msg);
      throw new Error(msg);
    }

    return dto;
  }

  protected async request<TResponse = unknown>(
    url: string,
    method: Method,
    data?: unknown,
    headers?: Record<string, string>,
  ): Promise<AxiosResponse<TResponse>> {
    if (!this.httpService)
      throw new Error(`${this.name} does not support http requests`);

    const urlObject = new URL(url);

    const maxRetries = 2;

    const response = await firstValueFrom(
      this.httpService
        .request<TResponse>({
          method,
          url: urlObject.href,
          data,
          headers,
        })
        .pipe(
          retry({
            count: maxRetries,
            delay: (error: unknown, retryCount: number) => {
              const status = (error as { response?: { status: number } })
                .response?.status;
              const isRetryable = status == null || status >= 500;

              if (!isRetryable) return throwError(() => error as Error);
              this.logger[!status || status >= 500 ? 'error' : 'warn'](
                `Tentativa ${retryCount} de ${maxRetries} para chamar ${url.toString()}: ${status ?? 'unknown status'}`,
              );
              return timer(500 * (retryCount + 1));
            },
          }),
          catchError((error) => {
            const status = (error as { response?: { status: number } }).response
              ?.status;

            const statusWhitelist = [400, 401, 403, 409];

            if (status && (!statusWhitelist.includes(status) || status > 500)) {
              this.logger.error(
                `Erro ao chamar Workflow Service (${url.toString()}): ${(error as Error)?.message}`,
              );
            }
            return throwError(() => error as Error);
          }),
        ),
    );

    return response;
  }

  /**
   * Gera o header de autenticação HTTP suportando diferentes métodos de assinatura.
   * @param token - Token de autenticação.
   * @returns Header de autenticação HTTP.
   */
  protected buildAuthHeader(token: string): string;
  /**
   * Gera o header de autenticação HTTP suportando diferentes métodos de assinatura.
   * @param identifier - Identificador de autenticação.
   * @param secret - Senha de autenticação.
   * @returns Header de autenticação HTTP.
   */
  protected buildAuthHeader(identifier: string, secret: string): string;
  protected buildAuthHeader(...args: unknown[]): string {
    const [token, identifier, secret] = args as [string, string, string];

    if (identifier && secret)
      return `${AUTH_METHOD_HEADER.BASIC} ${Buffer.from(`${identifier}:${secret}`).toString('base64')}`;

    if (token) return `${AUTH_METHOD_HEADER.BEARER} ${token}`;

    throw new Error(
      `Error building auth header: invalid arguments supplied: ${JSON.stringify(args)}`,
    );
  }

  // Métodos da interface (cada strategy implementa)
  abstract login(credentials: LoginCredentialsDto): Promise<LoginApiResponse>;
  abstract logout(
    logoutToken: LogoutCredentialsDto,
  ): Promise<LogoutApiResponse>;
  abstract refreshToken(
    credentials: RefreshTokenCredentialsDto,
  ): Promise<RefreshTokenApiResponse>;
  abstract getUserInfo(
    credentials: TokenCredentialsDto,
  ): Promise<UserInfoApiResponse>;
  abstract validate(
    credentials: TokenCredentialsDto,
  ): Promise<ValidateApiResponse>;
  abstract getRolesForResource(
    user: ValidateResponseDto,
    resource: string,
  ): string[] | Promise<string[]>;
  abstract getRoles(user: ValidateResponseDto): string[] | Promise<string[]>;
}
