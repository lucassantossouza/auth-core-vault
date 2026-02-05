import { AUTH_MESSAGES } from './../constants/auth-messages.const';
import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Inject,
  Injectable,
  Optional,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLE_GUARD_OPTIONS } from '../constants/role-guard.const';
import { type IAuthVaultService, type IRoleGuardOptions } from '../interfaces';
import { AUTH_GUARD_COOKIE_DEFAULT, RoleMatch, RoleMerge } from '../constants';
import { META_ROLE_MATCHING_MODE, META_ROLES } from '../decorators';
import { extractRequestAndAttachCookie } from '../utils';
import { ValidateResponseDto } from '../dto';
import { IAuthVaultLogger } from '../interfaces/auth-vault.logger.interface';
import { AUTH_VAULT_LOGGER_FACTORY } from '../constants/auth-vault-logger-factory.const';
import { AUTH_VAULT_SERVICE } from '../tokens';

type RequestWithAuth = Request & {
  user?: ValidateResponseDto;
  accessToken?: string;
};

/**
 * Ensures the user has the required roles from @Roles(). RoleMatch.ANY = at least one; RoleMatch.ALL = all.
 * RoleMerge.ALL = class + method roles; OVERRIDE = method overrides. Runs after AuthGuard.
 *
 * @example
 * ```ts
 * // Use globally or on controller/route
 * @UseGuards(AuthGuard, RoleGuard)
 * @Roles('admin')
 * @Get('admin') adminOnly() { ... }
 * ```
 */
@Injectable()
export class RoleGuard implements CanActivate {
  private readonly logger: IAuthVaultLogger;

  constructor(
    private readonly reflector: Reflector,
    @Inject(AUTH_VAULT_SERVICE)
    private readonly authVaultService: IAuthVaultService,
    @Inject(AUTH_VAULT_LOGGER_FACTORY)
    createLogger: (context: string) => IAuthVaultLogger,
    @Optional()
    @Inject(ROLE_GUARD_OPTIONS)
    private readonly options?: IRoleGuardOptions,
  ) {
    this.logger = createLogger(RoleGuard.name);
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const defaultMatch = this.options?.roleMatch ?? RoleMatch.ANY;

    const requiredRoles: string[] = this.getRequiredRoles(context);

    const matchingMode =
      this.reflector.getAllAndOverride<RoleMatch>(META_ROLE_MATCHING_MODE, [
        context.getClass(),
        context.getHandler(),
      ]) ?? defaultMatch;

    if (!requiredRoles.length) {
      this.logger.warn(AUTH_MESSAGES.GUARD_NO_ROLES_REQUIRED);
      return true;
    }

    this.logger.verbose(`Modo de matching: ${matchingMode}`, {
      roles: requiredRoles,
    });

    // Extrai a requisição/Response do contexto
    const cookieKey = this.options?.cookieKey || AUTH_GUARD_COOKIE_DEFAULT;
    const [request] = extractRequestAndAttachCookie<RequestWithAuth, unknown>(
      context,
      cookieKey,
    );

    // Se não for requisição http ignora esse guard
    if (!request) return true;

    if (!request.accessToken) {
      this.logger.warn(AUTH_MESSAGES.GUARD_ACCESS_TOKEN_NOT_FOUND);
      throw new ForbiddenException(AUTH_MESSAGES.HTTP_FORBIDDEN);
    }

    if (!request.user) {
      this.logger.warn(AUTH_MESSAGES.ROLE_ACCESS_DENIED);
      throw new ForbiddenException(AUTH_MESSAGES.ROLE_ACCESS_DENIED);
    }

    const strategyRoles = await this.authVaultService.getRoles(request.user);
    // ANY: Usuario precisa ter pelo menos uma das roles exigidas (some)
    // ALL: Usuario precisa ter todas as roles exigidas (every requiredRoles)
    const granted =
      matchingMode === RoleMatch.ANY
        ? requiredRoles.some((role) => strategyRoles.includes(role))
        : requiredRoles.every((role) => strategyRoles.includes(role));

    if (granted) this.logger.verbose('Acesso permitido por role(s)');
    else {
      this.logger.verbose('Acesso negado: role(s) não conferem.');
      throw new ForbiddenException(AUTH_MESSAGES.ROLE_ACCESS_DENIED);
    }

    return granted;
  }

  private getRequiredRoles(context: ExecutionContext): string[] {
    const roleMerge = this.options?.roleMerge ?? RoleMerge.OVERRIDE;

    let requiredRoles: string[] = [];
    switch (roleMerge) {
      case RoleMerge.ALL: {
        const merged = this.reflector.getAllAndMerge<string[]>(META_ROLES, [
          context.getClass(),
          context.getHandler(),
        ]);
        if (merged) requiredRoles = merged;
        break;
      }
      case RoleMerge.OVERRIDE: {
        const overridden = this.reflector.getAllAndOverride<string[]>(
          META_ROLES,
          [context.getClass(), context.getHandler()],
        );
        if (overridden) requiredRoles = overridden;
        break;
      }
      default:
        throw Error(`Invalid role merge mode: ${String(roleMerge)}`);
    }
    return requiredRoles;
  }
}
