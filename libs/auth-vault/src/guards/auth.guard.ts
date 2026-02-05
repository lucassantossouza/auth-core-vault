import {
  CanActivate,
  ExecutionContext,
  Inject,
  Injectable,
  Optional,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import {
  AUTH_GUARD_COOKIE_DEFAULT,
  AUTH_GUARD_OPTIONS,
  AUTH_MESSAGES,
  type AuthGuardOptions,
} from '../constants';
import {
  extractRequestAndAttachCookie,
  parseToken,
} from '../utils/internal.util';
import { META_PUBLIC } from '../decorators/public.decorator';
import { ValidateResponseDto } from '../dto/validate-response.dto';
import { IAuthVaultLogger } from '../interfaces/auth-vault.logger.interface';
import { AUTH_VAULT_LOGGER_FACTORY } from '../constants/auth-vault-logger-factory.const';
import { AUTH_VAULT_SERVICE } from '../tokens';
import { type IAuthVaultService } from '../interfaces';

/**
 * Validates JWT from Authorization header (Bearer), calls AuthVaultService.validate,
 * and attaches user, jwtPayload, and accessToken to the request.
 * Routes marked with @Public() skip validation or allow invalid token on public routes.
 *
 * @example
 * ```ts
 * // Use globally or on controller/route
 * @UseGuards(AuthGuard)
 * @Get('profile')
 * profile(@AuthUser() user: ValidateResponseDto) { return user; }
 * ```
 */
@Injectable()
export class AuthGuard implements CanActivate {
  private readonly logger: IAuthVaultLogger;

  constructor(
    @Inject(AUTH_VAULT_SERVICE)
    private readonly authVaultService: IAuthVaultService,
    private readonly reflector: Reflector,
    @Inject(AUTH_VAULT_LOGGER_FACTORY)
    createLogger: (context: string) => IAuthVaultLogger,
    @Optional()
    @Inject(AUTH_GUARD_OPTIONS)
    private readonly options?: AuthGuardOptions,
  ) {
    this.logger = createLogger(AuthGuard.name);
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const isPublic = this.reflector.getAllAndOverride<boolean>(META_PUBLIC, [
      context.getClass(),
      context.getHandler(),
    ]);

    const cookieKey = this.options?.cookieKey || AUTH_GUARD_COOKIE_DEFAULT;
    const [request] = extractRequestAndAttachCookie<
      Request & {
        user: ValidateResponseDto;
        jwtPayload: Record<string, any>;
        accessToken: string;
      },
      Response
    >(context, cookieKey);

    // Se não for requisição http ignora esse guard
    if (!request) return true;

    const jwt: string =
      this.extractJwtFromHeader(
        request.headers as unknown as Record<string, unknown>,
      ) ?? '';
    const isJwtEmpty = !jwt || jwt.trim() === '';

    // Não é uma rota pública e requer autenticação
    if (!isPublic && isJwtEmpty) {
      this.logger.verbose(AUTH_MESSAGES.GUARD_TOKEN_MISSING);
      throw new UnauthorizedException(AUTH_MESSAGES.HTTP_UNAUTHORIZED);
    }

    // É uma rota pública e o JWT está vazio, permite acesso
    if (isPublic && isJwtEmpty) return true;

    this.logger.verbose(AUTH_MESSAGES.GUARD_TOKEN_VALIDATING, { jwt });

    const response = await this.authVaultService.validate({ token: jwt });

    if (response.success) {
      request.user = response.data;
      request.jwtPayload = parseToken(jwt) as Record<string, unknown>;

      request.accessToken = jwt;

      this.logger.verbose(AUTH_MESSAGES.GUARD_USER_AUTHENTICATED, {
        user: request.user,
      });

      return true;
    }

    if (isPublic) {
      this.logger.warn(
        AUTH_MESSAGES.GUARD_TOKEN_VALIDATION_FAILED_ON_PUBLIC_ROUTE,
        { jwt },
      );
      return true;
    }

    this.logger.verbose(AUTH_MESSAGES.GUARD_TOKEN_INVALID, { jwt });
    throw new UnauthorizedException(AUTH_MESSAGES.HTTP_UNAUTHENTICATED);
  }

  private extractJwtFromHeader(headers: {
    authorization?: string;
    [key: string]: unknown;
  }): string | null | undefined {
    if (headers && !headers?.authorization) {
      this.logger.verbose(AUTH_MESSAGES.GUARD_HEADER_AUTHORIZATION_MISSING);
      return null;
    }

    const auth = (headers?.authorization ?? '').split(' ');

    // Nos permitimos apenas o tipo Bearer
    if (auth[0].toLowerCase() !== 'bearer') {
      this.logger.verbose(AUTH_MESSAGES.GUARD_HEADER_BEARER_NOT_FOUND);
      return null;
    }

    return auth[1];
  }
}
