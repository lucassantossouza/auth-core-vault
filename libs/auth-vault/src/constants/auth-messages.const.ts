/**
 * Mensagens de autenticação: chaves por contexto (GUARD, OAUTH, HTTP, SUCCESS, COMMON, ROLE, RESOURCE).
 * Use as chaves nos guards, mappers e DTOs para manter consistência.
 */

// ---- AuthGuard: token, header, validação ----
const AUTH_MESSAGES_GUARD = {
  /** Log: token ausente ou vazio (rota protegida → 401) */
  GUARD_TOKEN_MISSING:
    'Token ausente ou vazio. Não autorizado a acessar este recurso.',
  /** Log: header Authorization ausente */
  GUARD_HEADER_AUTHORIZATION_MISSING: 'Header Authorization não presente.',
  /** Log: header não é Bearer */
  GUARD_HEADER_BEARER_NOT_FOUND:
    'Header Authorization deve conter o esquema Bearer.',
  /** Log: token encontrado, iniciando validação */
  GUARD_TOKEN_VALIDATING: 'Token encontrado, validando...',
  /** Log: usuário autenticado com sucesso */
  GUARD_USER_AUTHENTICATED: 'Usuário autenticado com sucesso.',
  /** Log: token inválido ou expirado */
  GUARD_TOKEN_INVALID: 'Token inválido ou expirado.',
  /** Log: token foi enviado mas falhou na validação (rota pública → permite) */
  GUARD_TOKEN_VALIDATION_FAILED_ON_PUBLIC_ROUTE:
    'O token enviado não pôde ser validado, mas esta rota é pública. O acesso foi permitido.',
  /** Log: controller sem @Resource (acesso permitido em PERMISSIVE) */
  GUARD_CONTROLLER_WITHOUT_RESOURCE_PERMISSIVE:
    'Controller sem @Resource: acesso permitido (política permissiva).',
  /** Log: controller sem @Resource (acesso negado em ENFORCING) */
  GUARD_CONTROLLER_WITHOUT_RESOURCE_ENFORCING:
    'Controller sem @Resource: acesso negado (política restritiva).',
  /** Log: controller sem @Scopes (acesso permitido em PERMISSIVE) */
  GUARD_CONTROLLER_WITHOUT_SCOPES_PERMISSIVE:
    'Controller sem @Scopes: acesso permitido (política permissiva).',
  /** Log: controller sem @Scopes (acesso negado em ENFORCING) */
  GUARD_CONTROLLER_WITHOUT_SCOPES_ENFORCING:
    'Controller sem @Scopes: acesso negado (política restritiva).',
  /** Log: sem roles necessárias (acesso permitido) */
  GUARD_NO_ROLES_REQUIRED: 'Nenhuma role exigida em @Roles: acesso permitido.',
  /** Log: token de acesso não encontrado no request (auth guard não passou?) */
  GUARD_ACCESS_TOKEN_NOT_FOUND:
    'Token de acesso não encontrado no request. O AuthGuard está antes do RoleGuard na cadeia?',
} as const;

// ---- Respostas HTTP (401, 403) ----
const AUTH_MESSAGES_HTTP = {
  /** Resposta 401: não autenticado (sem token) */
  HTTP_UNAUTHORIZED:
    'É necessário estar autenticado para acessar este recurso.',
  /** Resposta 401: token inválido ou expirado */
  HTTP_UNAUTHENTICATED: 'Sessão inválida ou expirada. Faça login novamente.',
  /** Resposta 403: sem permissão (para uso futuro em RoleGuard/ResourceGuard) */
  HTTP_FORBIDDEN: 'Você não tem permissão para acessar este recurso.',
} as const;

// ---- OAuth / IdP: mapeamento de códigos de erro (getAuthErrorMessage) ----
const AUTH_MESSAGES_OAUTH = {
  OAUTH_INVALID_CREDENTIALS: 'Usuário ou senha inválidos.',
  OAUTH_INVALID_CLIENT: 'Configuração do cliente inválida.',
  OAUTH_INVALID_REQUEST: 'Requisição inválida.',
  OAUTH_INVALID_SCOPE: 'Escopo solicitado inválido.',
  OAUTH_INVALID_TOKEN: 'Token inválido ou expirado.',
  OAUTH_INVALID_GRANT: 'Grant inválido.',
  OAUTH_UNSUPPORTED_GRANT_TYPE: 'Tipo de grant não suportado.',
} as const;

// ---- Sucesso ----
const AUTH_MESSAGES_SUCCESS = {
  SUCCESS_LOGOUT: 'Logout realizado com sucesso.',
} as const;

// ---- Genérico ----
const AUTH_MESSAGES_COMMON = {
  COMMON_DEFAULT_ERROR:
    'Não foi possível atender à sua solicitação no momento. Tente novamente mais tarde.',
} as const;

// ---- Uso futuro: RoleGuard, ResourceGuard ----
const AUTH_MESSAGES_ROLE = {
  ROLE_ACCESS_DENIED: 'Você não possui a permissão necessária para esta ação.',
  ROLE_REQUIRED: 'Esta rota exige permissões específicas.',
} as const;

const AUTH_MESSAGES_RESOURCE = {
  RESOURCE_ACCESS_DENIED: 'Acesso negado a este recurso.',
  RESOURCE_SCOPE_REQUIRED: 'Escopo insuficiente para este recurso.',
} as const;

// ---- Export unificado (mantém AUTH_MESSAGES para não quebrar imports) ----
export const AUTH_MESSAGES = {
  ...AUTH_MESSAGES_GUARD,
  ...AUTH_MESSAGES_HTTP,
  ...AUTH_MESSAGES_OAUTH,
  ...AUTH_MESSAGES_SUCCESS,
  ...AUTH_MESSAGES_COMMON,
  ...AUTH_MESSAGES_ROLE,
  ...AUTH_MESSAGES_RESOURCE,
} as const;

export type AuthMessageKey = keyof typeof AUTH_MESSAGES;
export type AuthErrorMessage = (typeof AUTH_MESSAGES)[AuthMessageKey];
