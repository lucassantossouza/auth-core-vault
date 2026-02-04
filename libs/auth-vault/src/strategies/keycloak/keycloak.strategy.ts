import { AuthStrategyBase } from '../auth-strategy.abstract';
import { KeycloakUrlBuilder } from './services/keycloak-url.builder';
import { HttpService } from '@nestjs/axios';
import { Inject, Injectable } from '@nestjs/common';
import {
  LoginApiResponse,
  LogoutApiResponse,
  RefreshTokenApiResponse,
  UserInfoApiResponse,
  ValidateApiResponse,
} from '../../types';
import { getAuthErrorMessage } from './mappers/auth-keycloak.mapper';
import { AUTH_MESSAGES } from '../../constants/auth-messages.const';
import { LogoutCredentialsDto } from '../../dto/logout-credentials.dto';
import { RefreshTokenCredentialsDto } from '../../dto/refresh-token-credentials.dto';
import { TokenCredentialsDto } from '../../dto/token-credentials.dto';
import { ValidateResponseDto } from '../../dto';
import { AUTH_STRATEGY_CONFIG } from '../../tokens';
import type { ConfigForStrategy } from '../../types/strategy-config-dto.types';
import { IAuthVaultLogger } from '../../interfaces/auth-vault.logger.interface';
import { AUTH_VAULT_LOGGER_FACTORY } from '../../constants/auth-vault-logger-factory.const';

/**
 * Keycloak strategy: login (password grant), logout, refresh, userinfo, token introspection, roles from realm_access and resource_access.
 * Use strategyConfig: { name: 'keycloak', ...KeycloakConfigDto } when registering AuthVaultModule.
 */
@Injectable()
export class KeycloakStrategy extends AuthStrategyBase<'keycloak'> {
  private readonly urlBuilder: KeycloakUrlBuilder;

  constructor(
    @Inject(AUTH_STRATEGY_CONFIG)
    config: ConfigForStrategy<'keycloak'>,
    protected readonly httpService: HttpService,
    @Inject(AUTH_VAULT_LOGGER_FACTORY)
    createLogger: (context: string) => IAuthVaultLogger,
  ) {
    super(config, createLogger, httpService);

    this.urlBuilder = this.createUrlBuilder();
  }

  private createUrlBuilder(): KeycloakUrlBuilder {
    return new KeycloakUrlBuilder(this.config);
  }

  async login(credentials: {
    username: string;
    password: string;
  }): Promise<LoginApiResponse> {
    const formData = new URLSearchParams({
      grant_type: 'password',
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
      username: credentials.username,
      password: credentials.password,
    });

    try {
      const response = await this.request(
        this.urlBuilder.tokenEndpoint(),
        'POST',
        formData.toString(),
        {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      );

      const body = response.data as Record<string, unknown>;
      return {
        success: true,
        data: {
          accessToken: body?.access_token as string,
          expiresIn: body?.expires_in as number,
          refreshToken: body?.refresh_token as string,
          refreshTokenExpiresIn: body?.refresh_token_expires_in as number,
          scope: body?.scope as string,
          sessionState: body?.session_state as string,
          tokenType: body?.token_type as string,
        },
      } as LoginApiResponse;
    } catch (error: unknown) {
      const err = error as {
        response?: { status: number; data?: Record<string, unknown> };
      };
      const body = err.response?.data ?? {};

      return {
        success: false,
        data: {
          error: (body.error as string) ?? 'unknown',
          message: getAuthErrorMessage(body.error as string),
          details:
            (body.error_description as string) ?? (error as Error).message,
        },
      } as LoginApiResponse;
    }
  }

  async logout({
    refreshToken,
    accessToken,
  }: LogoutCredentialsDto): Promise<LogoutApiResponse> {
    try {
      const formData = new URLSearchParams({
        token: (refreshToken || accessToken) as string,
        token_type_hint: refreshToken ? 'refresh_token' : 'access_token',
      });

      const response = await this.request(
        this.urlBuilder.logoutEndpoint(),
        'POST',
        formData.toString(),
        {
          // 'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Basic ${Buffer.from(`${this.config.clientId}:${this.config.clientSecret}`).toString('base64')}`,
        },
      );

      const data = (response?.data ?? {}) as Record<string, unknown>;
      const isObject =
        data != null && typeof data === 'object' && !Array.isArray(data);

      if (isObject && 'error' in data)
        throw {
          response: { status: response.status, data: response.data },
        } as unknown as Error;
      return {
        success: true,
        data: {
          message: AUTH_MESSAGES.SUCCESS_LOGOUT,
        },
      } as LogoutApiResponse;
    } catch (error: unknown) {
      const err = error as {
        response?: { status: number; data?: Record<string, unknown> };
      };
      const body = err.response?.data ?? {};
      return {
        success: false,
        data: {
          error: (body.error as string) ?? 'unknown',
          message: getAuthErrorMessage(body.error as string),
          details:
            (body.error_description as string) ?? (error as Error).message,
        },
      } as LogoutApiResponse;
    }
  }

  async refreshToken(
    credentials: RefreshTokenCredentialsDto,
  ): Promise<RefreshTokenApiResponse> {
    try {
      const formData = new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret,
        refresh_token: credentials.refreshToken,
      });

      const response = await this.request(
        this.urlBuilder.refreshTokenEndpoint(),
        'POST',
        formData.toString(),
        {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      );
      const body = response.data as Record<string, unknown>;

      return {
        success: true,
        data: {
          accessToken: body?.access_token as string,
          expiresIn: body?.expires_in as number,
          refreshToken: body?.refresh_token as string,
          refreshTokenExpiresIn: body?.refresh_token_expires_in as number,
          scope: body?.scope as string,
          sessionState: body?.session_state as string,
          tokenType: body?.token_type as string,
        },
      } as RefreshTokenApiResponse;
    } catch (error: unknown) {
      const err = error as {
        response?: { status: number; data?: Record<string, unknown> };
      };
      const body = err.response?.data ?? {};
      return {
        success: false,
        data: {
          error: (body.error as string) ?? 'unknown',
          message: getAuthErrorMessage(body.error as string),
          details:
            (body.error_description as string) ?? (error as Error).message,
        },
      } as RefreshTokenApiResponse;
    }
  }

  async getUserInfo({
    token,
  }: TokenCredentialsDto): Promise<UserInfoApiResponse> {
    try {
      const response = await this.request(
        this.urlBuilder.userInfoEndpoint(),
        'GET',
        undefined,
        { Authorization: `Bearer ${token}` },
      );

      const body = response.data as Record<string, unknown>;
      return {
        success: true,
        statusCode: response.status,
        data: {
          sub: body.sub as string,
          ...body,
        },
      } as UserInfoApiResponse;
    } catch (error: unknown) {
      const err = error as {
        response?: { status: number; data?: Record<string, unknown> };
      };
      const body = err.response?.data ?? {};

      return {
        success: false,
        statusCode: err.response?.status ?? 500,
        data: {
          error: (body.error as string) ?? 'unknown',
          message: getAuthErrorMessage(body.error as string),
          details:
            (body.error_description as string) ?? (error as Error).message,
        },
      } as UserInfoApiResponse;
    }
  }

  async validate(
    credentials: TokenCredentialsDto,
  ): Promise<ValidateApiResponse> {
    try {
      const formData = new URLSearchParams({
        token_type_hint: 'access_token',
        token: credentials.token,
      });
      const response = await this.request(
        this.urlBuilder.validateTokenEndpoint(),
        'POST',
        formData.toString(),
        {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Basic ${Buffer.from(`${this.config.clientId}:${this.config.clientSecret}`).toString('base64')}`,
        },
      );
      const body = response.data as ValidateResponseDto;
      if ('active' in body && !body.active)
        throw {
          response: {
            status: 401,
            data: {
              error: (body?.['error'] ?? 'invalid_token') as string,
              error_description: (body?.['error_description'] ??
                AUTH_MESSAGES.OAUTH_INVALID_TOKEN) as string,
            },
          },
        } as unknown as Error;
      return {
        success: true,
        statusCode: response.status,
        data: body,
      } as ValidateApiResponse;
    } catch (error: unknown) {
      const err = error as {
        response?: { status: number; data?: Record<string, unknown> };
      };
      const body = err.response?.data ?? {};
      return {
        success: false,
        statusCode: err.response?.status ?? 500,
        data: {
          error: (body.error as string) ?? 'unknown',
          message: getAuthErrorMessage(body.error as string),
          details:
            (body.error_description as string) ?? (error as Error).message,
        },
      } as ValidateApiResponse;
    }
  }

  getRolesForResource(user: ValidateResponseDto, resource: string): string[] {
    const set = new Set<string>();
    if (user.realm_access?.roles?.length)
      user.realm_access.roles.forEach((r) => set.add(r));

    if (user.resource_access?.[resource]?.roles?.length)
      user.resource_access[resource].roles.forEach((r) => set.add(r));

    if (user.roles?.length) user.roles.forEach((r) => set.add(r));

    return Array.from(set);
  }

  getRoles(user: ValidateResponseDto): string[] {
    const set = new Set<string>();
    if (user.realm_access?.roles?.length)
      user.realm_access.roles.forEach((r) => set.add(r));
    if (user.resource_access && typeof user.resource_access === 'object') {
      for (const resourceRoles of Object.values(user.resource_access)) {
        if (resourceRoles?.roles?.length)
          resourceRoles.roles.forEach((r) => set.add(r));
      }
    }
    if (user.roles?.length) user.roles.forEach((r) => set.add(r));
    return Array.from(set);
  }
}
