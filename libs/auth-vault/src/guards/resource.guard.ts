import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Inject,
  Injectable,
  Optional,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ValidateResponseDto } from '../dto/validate-response.dto';
import {
  PolicyEnforcementMode,
  AUTH_GUARD_COOKIE_DEFAULT,
  AUTH_MESSAGES,
  RESOURCE_GUARD_OPTIONS,
  META_ENFORCER_OPTIONS,
} from '../constants';
import { extractRequestAndAttachCookie } from '../utils';
import { type ConditionalScopeFn } from '../types';
import {
  META_SCOPES,
  META_CONDITIONAL_SCOPES,
  META_PUBLIC,
  META_RESOURCE,
} from '../decorators';
import {
  type IAuthVaultService,
  IEnforcerOptions,
  type IResourceGuardOptions,
} from '../interfaces';
import { AUTH_VAULT_LOGGER_FACTORY } from '../constants/auth-vault-logger-factory.const';
import { IAuthVaultLogger } from '../interfaces/auth-vault.logger.interface';
import { AUTH_VAULT_SERVICE } from '../tokens';

type RequestWithAuth = Request & {
  user?: ValidateResponseDto;
  accessToken?: string;
  scopes?: string[];
};

/**
 * Checks that the user has at least one of the required scopes for the controller resource.
 * Use @Resource() on the controller and @Scopes() on the handler. Runs after AuthGuard.
 *
 * @example
 * ```ts
 * // Use globally or on controller/route
 * @Resource('account')
 * @UseGuards(AuthGuard, ResourceGuard)
 * @Scopes('view-profile')
 * @Get('me') me() { ... }
 * ```
 */
@Injectable()
export class ResourceGuard implements CanActivate {
  private readonly logger: IAuthVaultLogger;

  constructor(
    private readonly reflector: Reflector,
    @Inject(AUTH_VAULT_SERVICE)
    private readonly authVaultService: IAuthVaultService,
    @Inject(AUTH_VAULT_LOGGER_FACTORY)
    createLogger: (context: string) => IAuthVaultLogger,
    @Optional()
    @Inject(RESOURCE_GUARD_OPTIONS)
    private readonly options?: IResourceGuardOptions,
  ) {
    this.logger = createLogger(ResourceGuard.name);
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const resource = this.reflector.get<string>(
      META_RESOURCE,
      context.getClass(),
    );

    const explicitScopes =
      this.reflector.get<string[]>(META_SCOPES, context.getHandler()) ?? [];

    const conditionalScopes = this.reflector.get<ConditionalScopeFn>(
      META_CONDITIONAL_SCOPES,
      context.getHandler(),
    );

    const isPublic = this.reflector.getAllAndOverride<boolean>(META_PUBLIC, [
      context.getClass(),
      context.getHandler(),
    ]);

    const enforcerOpts = this.reflector.getAllAndOverride<IEnforcerOptions>(
      META_ENFORCER_OPTIONS,
      [context.getClass(), context.getHandler()],
    );

    // Padrão PERMISSIVE
    const policyEnforcementMode =
      // this.options?.policyEnforcementMode ?? PolicyEnforcementMode.PERMISSIVE;
      enforcerOpts?.policyEnforcementMode ??
      this.options?.policyEnforcementMode ??
      PolicyEnforcementMode.PERMISSIVE;
    const shouldAllow =
      policyEnforcementMode === PolicyEnforcementMode.PERMISSIVE;

    // Extrai a requisição/Response do contexto
    const cookieKey = this.options?.cookieKey || AUTH_GUARD_COOKIE_DEFAULT;
    const [request] = extractRequestAndAttachCookie<RequestWithAuth, unknown>(
      context,
      cookieKey,
    );

    // Se não for requisição http ignora esse guard
    if (!request) return true;

    if (!request.user && isPublic) {
      this.logger.verbose(
        AUTH_MESSAGES.GUARD_TOKEN_VALIDATION_FAILED_ON_PUBLIC_ROUTE,
      );
      return true;
    }

    if (!resource) {
      if (shouldAllow)
        this.logger.verbose(
          AUTH_MESSAGES.GUARD_CONTROLLER_WITHOUT_RESOURCE_PERMISSIVE,
        );
      else {
        this.logger.verbose(
          AUTH_MESSAGES.GUARD_CONTROLLER_WITHOUT_RESOURCE_ENFORCING,
        );
        throw new ForbiddenException(AUTH_MESSAGES.HTTP_FORBIDDEN);
      }
      return shouldAllow;
    }

    // Construir os escopos necessários para a verificação
    const conditionalScopesResult =
      conditionalScopes != null
        ? conditionalScopes(request, request.accessToken ?? '')
        : [];

    const scopes = [...explicitScopes, ...conditionalScopesResult];

    // Anexar escopos resolvidos
    request.scopes = scopes;

    if (!scopes || !scopes.length) {
      if (shouldAllow)
        this.logger.verbose(
          AUTH_MESSAGES.GUARD_CONTROLLER_WITHOUT_SCOPES_PERMISSIVE,
        );
      else {
        this.logger.verbose(
          AUTH_MESSAGES.GUARD_CONTROLLER_WITHOUT_SCOPES_ENFORCING,
        );
        throw new ForbiddenException(AUTH_MESSAGES.HTTP_FORBIDDEN);
      }
      return shouldAllow;
    }

    this.logger.verbose(
      `Protegendo recurso [ "${resource}" ] com escopos [ ${scopes.join(', ')} ].`,
    );

    const userLabel = request.user?.preferred_username ?? 'user';

    if (!request.user) {
      this.logger.verbose(
        `Recurso [ "${resource}" ] negado para [ ${userLabel} ].`,
      );
      throw new ForbiddenException(AUTH_MESSAGES.RESOURCE_ACCESS_DENIED);
    }

    const userRoles = await this.authVaultService.getRolesForResource(
      request.user,
      resource,
    );
    const isAllowed = scopes.some((scope) => userRoles.includes(scope));

    if (!isAllowed) {
      this.logger.verbose(
        `Recurso [ "${resource}" ] negado para [ ${userLabel} ].`,
      );
      throw new ForbiddenException(AUTH_MESSAGES.RESOURCE_ACCESS_DENIED);
    }

    this.logger.verbose(
      `Recurso [ "${resource}" ] permitido para [ ${userLabel} ].`,
    );
    return true;
  }
}
