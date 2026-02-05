/******/ (() => { // webpackBootstrap
/******/ 	"use strict";
/******/ 	var __webpack_modules__ = ([
/* 0 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
__exportStar(__webpack_require__(1), exports);
__exportStar(__webpack_require__(12), exports);
__exportStar(__webpack_require__(38), exports);
__exportStar(__webpack_require__(57), exports);
__exportStar(__webpack_require__(23), exports);
__exportStar(__webpack_require__(68), exports);
__exportStar(__webpack_require__(61), exports);
__exportStar(__webpack_require__(79), exports);
__exportStar(__webpack_require__(81), exports);


/***/ }),
/* 1 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
__exportStar(__webpack_require__(2), exports);
__exportStar(__webpack_require__(5), exports);
__exportStar(__webpack_require__(6), exports);
__exportStar(__webpack_require__(7), exports);
__exportStar(__webpack_require__(8), exports);
__exportStar(__webpack_require__(9), exports);
__exportStar(__webpack_require__(10), exports);
__exportStar(__webpack_require__(11), exports);


/***/ }),
/* 2 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.defaultHttpOptions = void 0;
const http_1 = __webpack_require__(3);
const https_1 = __webpack_require__(4);
const agentOptions = {
    keepAlive: true,
    keepAliveMsecs: 1000,
    maxSockets: 50,
    maxFreeSockets: 10,
};
const httpsAgentOptions = {
    ...agentOptions,
    rejectUnauthorized: true,
};
exports.defaultHttpOptions = {
    timeout: 3000,
    maxRedirects: 3,
    httpAgent: new http_1.Agent({ ...agentOptions }),
    httpsAgent: new https_1.Agent(httpsAgentOptions),
};


/***/ }),
/* 3 */
/***/ ((module) => {

module.exports = require("http");

/***/ }),
/* 4 */
/***/ ((module) => {

module.exports = require("https");

/***/ }),
/* 5 */
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AUTH_GUARD_COOKIE_DEFAULT = exports.AUTH_GUARD_OPTIONS = void 0;
exports.AUTH_GUARD_OPTIONS = Symbol('AUTH_GUARD_OPTIONS');
exports.AUTH_GUARD_COOKIE_DEFAULT = 'auth-token';


/***/ }),
/* 6 */
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AUTH_MESSAGES = void 0;
const AUTH_MESSAGES_GUARD = {
    GUARD_TOKEN_MISSING: 'Token ausente ou vazio. Não autorizado a acessar este recurso.',
    GUARD_HEADER_AUTHORIZATION_MISSING: 'Header Authorization não presente.',
    GUARD_HEADER_BEARER_NOT_FOUND: 'Header Authorization deve conter o esquema Bearer.',
    GUARD_TOKEN_VALIDATING: 'Token encontrado, validando...',
    GUARD_USER_AUTHENTICATED: 'Usuário autenticado com sucesso.',
    GUARD_TOKEN_INVALID: 'Token inválido ou expirado.',
    GUARD_TOKEN_VALIDATION_FAILED_ON_PUBLIC_ROUTE: 'O token enviado não pôde ser validado, mas esta rota é pública. O acesso foi permitido.',
    GUARD_CONTROLLER_WITHOUT_RESOURCE_PERMISSIVE: 'Controller sem @Resource: acesso permitido (política permissiva).',
    GUARD_CONTROLLER_WITHOUT_RESOURCE_ENFORCING: 'Controller sem @Resource: acesso negado (política restritiva).',
    GUARD_CONTROLLER_WITHOUT_SCOPES_PERMISSIVE: 'Controller sem @Scopes: acesso permitido (política permissiva).',
    GUARD_CONTROLLER_WITHOUT_SCOPES_ENFORCING: 'Controller sem @Scopes: acesso negado (política restritiva).',
    GUARD_NO_ROLES_REQUIRED: 'Nenhuma role exigida em @Roles: acesso permitido.',
    GUARD_ACCESS_TOKEN_NOT_FOUND: 'Token de acesso não encontrado no request. O AuthGuard está antes do RoleGuard na cadeia?',
};
const AUTH_MESSAGES_HTTP = {
    HTTP_UNAUTHORIZED: 'É necessário estar autenticado para acessar este recurso.',
    HTTP_UNAUTHENTICATED: 'Sessão inválida ou expirada. Faça login novamente.',
    HTTP_FORBIDDEN: 'Você não tem permissão para acessar este recurso.',
};
const AUTH_MESSAGES_OAUTH = {
    OAUTH_INVALID_CREDENTIALS: 'Usuário ou senha inválidos.',
    OAUTH_INVALID_CLIENT: 'Configuração do cliente inválida.',
    OAUTH_INVALID_REQUEST: 'Requisição inválida.',
    OAUTH_INVALID_SCOPE: 'Escopo solicitado inválido.',
    OAUTH_INVALID_TOKEN: 'Token inválido ou expirado.',
    OAUTH_INVALID_GRANT: 'Grant inválido.',
    OAUTH_UNSUPPORTED_GRANT_TYPE: 'Tipo de grant não suportado.',
};
const AUTH_MESSAGES_SUCCESS = {
    SUCCESS_LOGOUT: 'Logout realizado com sucesso.',
};
const AUTH_MESSAGES_COMMON = {
    COMMON_DEFAULT_ERROR: 'Não foi possível atender à sua solicitação no momento. Tente novamente mais tarde.',
};
const AUTH_MESSAGES_ROLE = {
    ROLE_ACCESS_DENIED: 'Você não possui a permissão necessária para esta ação.',
    ROLE_REQUIRED: 'Esta rota exige permissões específicas.',
};
const AUTH_MESSAGES_RESOURCE = {
    RESOURCE_ACCESS_DENIED: 'Acesso negado a este recurso.',
    RESOURCE_SCOPE_REQUIRED: 'Escopo insuficiente para este recurso.',
};
exports.AUTH_MESSAGES = {
    ...AUTH_MESSAGES_GUARD,
    ...AUTH_MESSAGES_HTTP,
    ...AUTH_MESSAGES_OAUTH,
    ...AUTH_MESSAGES_SUCCESS,
    ...AUTH_MESSAGES_COMMON,
    ...AUTH_MESSAGES_ROLE,
    ...AUTH_MESSAGES_RESOURCE,
};


/***/ }),
/* 7 */
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.RoleMerge = exports.RoleMatch = exports.PolicyEnforcementMode = void 0;
var PolicyEnforcementMode;
(function (PolicyEnforcementMode) {
    PolicyEnforcementMode["PERMISSIVE"] = "permissive";
    PolicyEnforcementMode["ENFORCING"] = "enforcing";
})(PolicyEnforcementMode || (exports.PolicyEnforcementMode = PolicyEnforcementMode = {}));
var RoleMatch;
(function (RoleMatch) {
    RoleMatch["ANY"] = "any";
    RoleMatch["ALL"] = "all";
})(RoleMatch || (exports.RoleMatch = RoleMatch = {}));
var RoleMerge;
(function (RoleMerge) {
    RoleMerge["ALL"] = "all";
    RoleMerge["OVERRIDE"] = "override";
})(RoleMerge || (exports.RoleMerge = RoleMerge = {}));


/***/ }),
/* 8 */
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AUTH_METHOD_HEADER = void 0;
exports.AUTH_METHOD_HEADER = {
    BASIC: 'Basic',
    BEARER: 'Bearer',
};


/***/ }),
/* 9 */
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.RESOURCE_GUARD_OPTIONS = void 0;
exports.RESOURCE_GUARD_OPTIONS = Symbol('RESOURCE_GUARD_OPTIONS');


/***/ }),
/* 10 */
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ROLE_GUARD_OPTIONS = void 0;
exports.ROLE_GUARD_OPTIONS = Symbol('ROLE_GUARD_OPTIONS');


/***/ }),
/* 11 */
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.META_ENFORCER_OPTIONS = void 0;
exports.META_ENFORCER_OPTIONS = 'enforcer-options';


/***/ }),
/* 12 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
__exportStar(__webpack_require__(13), exports);
__exportStar(__webpack_require__(15), exports);
__exportStar(__webpack_require__(16), exports);
__exportStar(__webpack_require__(17), exports);
__exportStar(__webpack_require__(18), exports);
__exportStar(__webpack_require__(33), exports);
__exportStar(__webpack_require__(34), exports);
__exportStar(__webpack_require__(35), exports);
__exportStar(__webpack_require__(36), exports);
__exportStar(__webpack_require__(37), exports);


/***/ }),
/* 13 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.Public = exports.META_PUBLIC = void 0;
const common_1 = __webpack_require__(14);
exports.META_PUBLIC = 'public';
const Public = () => (0, common_1.SetMetadata)(exports.META_PUBLIC, true);
exports.Public = Public;


/***/ }),
/* 14 */
/***/ ((module) => {

module.exports = require("@nestjs/common");

/***/ }),
/* 15 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.Resource = exports.META_RESOURCE = void 0;
const common_1 = __webpack_require__(14);
exports.META_RESOURCE = 'resource';
const Resource = (resource) => (0, common_1.SetMetadata)(exports.META_RESOURCE, resource);
exports.Resource = Resource;


/***/ }),
/* 16 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.Scopes = exports.META_SCOPES = void 0;
const common_1 = __webpack_require__(14);
exports.META_SCOPES = 'scopes';
const Scopes = (...scopes) => (0, common_1.SetMetadata)(exports.META_SCOPES, scopes);
exports.Scopes = Scopes;


/***/ }),
/* 17 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ConditionalScopes = exports.META_CONDITIONAL_SCOPES = void 0;
const common_1 = __webpack_require__(14);
exports.META_CONDITIONAL_SCOPES = 'conditional-scopes';
const ConditionalScopes = (resolver) => (0, common_1.SetMetadata)(exports.META_CONDITIONAL_SCOPES, resolver);
exports.ConditionalScopes = ConditionalScopes;


/***/ }),
/* 18 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ResolvedScopes = void 0;
exports.getResolvedScopesFromContext = getResolvedScopesFromContext;
const common_1 = __webpack_require__(14);
const utils_1 = __webpack_require__(19);
function getResolvedScopesFromContext(ctx) {
    const [request] = (0, utils_1.extractRequest)(ctx);
    return request?.scopes;
}
exports.ResolvedScopes = (0, common_1.createParamDecorator)((data, ctx) => getResolvedScopesFromContext(ctx));


/***/ }),
/* 19 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
__exportStar(__webpack_require__(20), exports);
__exportStar(__webpack_require__(22), exports);


/***/ }),
/* 20 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.extractRequestAndAttachCookie = exports.attachCookieToHeader = exports.extractRequest = void 0;
exports.parseToken = parseToken;
const graphql_1 = __webpack_require__(21);
const extractRequest = (context) => {
    if (context.getType() === 'http') {
        const httpContext = context.switchToHttp();
        return [httpContext.getRequest(), httpContext.getResponse()];
    }
    if (context.getType() === 'graphql') {
        const gqlContext = graphql_1.GqlExecutionContext.create(context).getContext();
        return [gqlContext.req, gqlContext.res];
    }
    return [undefined, undefined];
};
exports.extractRequest = extractRequest;
const attachCookieToHeader = (request, cookieKey) => {
    if (request && request?.cookies && request?.cookies?.[cookieKey])
        request.headers.authorization = `Bearer ${request.cookies?.[cookieKey]}`;
    return request;
};
exports.attachCookieToHeader = attachCookieToHeader;
const extractRequestAndAttachCookie = (context, cookieKey) => {
    const [tmpRequest, response] = (0, exports.extractRequest)(context);
    const request = (0, exports.attachCookieToHeader)(tmpRequest, cookieKey);
    return [request, response];
};
exports.extractRequestAndAttachCookie = extractRequestAndAttachCookie;
function parseToken(token, throwOnError) {
    const parts = (token ?? '').split('.');
    try {
        return JSON.parse(Buffer.from(parts[1], 'base64').toString());
    }
    catch (error) {
        if (throwOnError)
            throw error;
        return {};
    }
}


/***/ }),
/* 21 */
/***/ ((module) => {

module.exports = require("@nestjs/graphql");

/***/ }),
/* 22 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AuthVaultLogLevelsValidationError = exports.AUTH_VAULT_LOG_LEVELS_ERROR = void 0;
exports.validateAndNormalizeLogLevels = validateAndNormalizeLogLevels;
const interfaces_1 = __webpack_require__(23);
const VALID_VALUES = new Set(Object.values(interfaces_1.AuthLogLevel));
exports.AUTH_VAULT_LOG_LEVELS_ERROR = 'AuthVaultLogLevelsValidationError';
class AuthVaultLogLevelsValidationError extends Error {
    invalidValues;
    allowedValues;
    constructor(message, invalidValues, allowedValues) {
        super(message);
        this.invalidValues = invalidValues;
        this.allowedValues = allowedValues;
        this.name = exports.AUTH_VAULT_LOG_LEVELS_ERROR;
        Object.setPrototypeOf(this, AuthVaultLogLevelsValidationError.prototype);
    }
}
exports.AuthVaultLogLevelsValidationError = AuthVaultLogLevelsValidationError;
function validateAndNormalizeLogLevels(value) {
    if (value == null)
        return undefined;
    const arr = Array.isArray(value) ? value : [value];
    const unique = [...new Set(arr)];
    const invalid = [];
    const valid = [];
    for (const item of unique) {
        if (VALID_VALUES.has(item)) {
            valid.push(item);
        }
        else {
            invalid.push(item);
        }
    }
    if (invalid.length > 0) {
        throw new AuthVaultLogLevelsValidationError(`Invalid logLevels: [${invalid.join(', ')}]. Allowed: [${Object.values(interfaces_1.AuthLogLevel).join(', ')}].`, invalid, Object.values(interfaces_1.AuthLogLevel));
    }
    return valid.length === 0 ? undefined : valid;
}


/***/ }),
/* 23 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
__exportStar(__webpack_require__(24), exports);
__exportStar(__webpack_require__(25), exports);
__exportStar(__webpack_require__(26), exports);
__exportStar(__webpack_require__(27), exports);
__exportStar(__webpack_require__(28), exports);
__exportStar(__webpack_require__(29), exports);
__exportStar(__webpack_require__(30), exports);
__exportStar(__webpack_require__(31), exports);
__exportStar(__webpack_require__(32), exports);


/***/ }),
/* 24 */
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));


/***/ }),
/* 25 */
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));


/***/ }),
/* 26 */
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));


/***/ }),
/* 27 */
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));


/***/ }),
/* 28 */
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));


/***/ }),
/* 29 */
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AuthLogLevel = void 0;
exports.AuthLogLevel = {
    SILENT: 'silent',
    ERROR: 'error',
    WARN: 'warn',
    VERBOSE: 'verbose',
    DEBUG: 'debug',
    LOG: 'log',
};


/***/ }),
/* 30 */
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));


/***/ }),
/* 31 */
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));


/***/ }),
/* 32 */
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));


/***/ }),
/* 33 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.Roles = exports.META_ROLES = void 0;
const common_1 = __webpack_require__(14);
exports.META_ROLES = 'auth:roles';
const Roles = (...roles) => (0, common_1.SetMetadata)(exports.META_ROLES, roles);
exports.Roles = Roles;


/***/ }),
/* 34 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.RoleMatchMode = exports.META_ROLE_MATCHING_MODE = void 0;
const common_1 = __webpack_require__(14);
exports.META_ROLE_MATCHING_MODE = 'auth:roleMatchingMode';
const RoleMatchMode = (mode) => (0, common_1.SetMetadata)(exports.META_ROLE_MATCHING_MODE, mode);
exports.RoleMatchMode = RoleMatchMode;


/***/ }),
/* 35 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AuthUser = void 0;
exports.getAuthUserFromContext = getAuthUserFromContext;
const common_1 = __webpack_require__(14);
const utils_1 = __webpack_require__(19);
function getAuthUserFromContext(ctx) {
    const [request] = (0, utils_1.extractRequest)(ctx);
    return request?.user;
}
exports.AuthUser = (0, common_1.createParamDecorator)((data, ctx) => getAuthUserFromContext(ctx));


/***/ }),
/* 36 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.EnforcerOptions = void 0;
const constants_1 = __webpack_require__(1);
const common_1 = __webpack_require__(14);
const EnforcerOptions = (options) => (0, common_1.SetMetadata)(constants_1.META_ENFORCER_OPTIONS, options);
exports.EnforcerOptions = EnforcerOptions;


/***/ }),
/* 37 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AccessToken = void 0;
exports.getAccessTokenFromContext = getAccessTokenFromContext;
const common_1 = __webpack_require__(14);
const utils_1 = __webpack_require__(19);
function getAccessTokenFromContext(ctx) {
    const [request] = (0, utils_1.extractRequest)(ctx);
    return request?.accessToken;
}
exports.AccessToken = (0, common_1.createParamDecorator)((data, ctx) => getAccessTokenFromContext(ctx));


/***/ }),
/* 38 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
__exportStar(__webpack_require__(39), exports);
__exportStar(__webpack_require__(42), exports);
__exportStar(__webpack_require__(43), exports);
__exportStar(__webpack_require__(44), exports);
__exportStar(__webpack_require__(45), exports);
__exportStar(__webpack_require__(46), exports);
__exportStar(__webpack_require__(47), exports);
__exportStar(__webpack_require__(48), exports);
__exportStar(__webpack_require__(49), exports);
__exportStar(__webpack_require__(50), exports);
__exportStar(__webpack_require__(51), exports);
__exportStar(__webpack_require__(52), exports);
__exportStar(__webpack_require__(53), exports);
__exportStar(__webpack_require__(54), exports);
__exportStar(__webpack_require__(55), exports);
__exportStar(__webpack_require__(56), exports);
__exportStar(__webpack_require__(43), exports);
__exportStar(__webpack_require__(39), exports);
__exportStar(__webpack_require__(44), exports);
__exportStar(__webpack_require__(46), exports);
__exportStar(__webpack_require__(54), exports);


/***/ }),
/* 39 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.LoginCredentialsDto = void 0;
const swagger_1 = __webpack_require__(40);
const class_validator_1 = __webpack_require__(41);
class LoginCredentialsDto {
    username;
    password;
}
exports.LoginCredentialsDto = LoginCredentialsDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Username',
        example: 'john.doe',
    }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", String)
], LoginCredentialsDto.prototype, "username", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Password',
        example: 'password',
    }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", String)
], LoginCredentialsDto.prototype, "password", void 0);


/***/ }),
/* 40 */
/***/ ((module) => {

module.exports = require("@nestjs/swagger");

/***/ }),
/* 41 */
/***/ ((module) => {

module.exports = require("class-validator");

/***/ }),
/* 42 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.LoginErrorResponseDto = void 0;
const auth_messages_const_1 = __webpack_require__(6);
const swagger_1 = __webpack_require__(40);
const class_validator_1 = __webpack_require__(41);
class LoginErrorResponseDto {
    error;
    message;
    details;
}
exports.LoginErrorResponseDto = LoginErrorResponseDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Código estável do erro para tratamento no front (ex.: invalid_grant, invalid_credentials).',
        example: 'invalid_grant',
    }),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], LoginErrorResponseDto.prototype, "error", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Mensagem do provedor de autenticação (ex.: error_description). Repassada para exibição ou log no front.',
        example: auth_messages_const_1.AUTH_MESSAGES.OAUTH_INVALID_CREDENTIALS,
    }),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", Object)
], LoginErrorResponseDto.prototype, "message", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Detalhe adicional do erro (opcional; em produção pode ser omitido ou sanitizado).',
        example: 'Account is disabled',
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], LoginErrorResponseDto.prototype, "details", void 0);


/***/ }),
/* 43 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.LoginResponseDto = void 0;
const swagger_1 = __webpack_require__(40);
const class_validator_1 = __webpack_require__(41);
class LoginResponseDto {
    accessToken;
    expiresIn;
    refreshTokenExpiresIn;
    refreshToken;
    tokenType;
    sessionState;
    scope;
}
exports.LoginResponseDto = LoginResponseDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Token de acesso JWT utilizado no header Authorization (Bearer).',
        example: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...',
    }),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], LoginResponseDto.prototype, "accessToken", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Validade do access token em segundos. Ex.: 300 = 5 minutos.',
        example: 300,
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsNumber)(),
    __metadata("design:type", Number)
], LoginResponseDto.prototype, "expiresIn", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Validade do refresh token em segundos. Só presente quando o provedor devolve refresh token.',
        example: 1800,
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsNumber)(),
    __metadata("design:type", Number)
], LoginResponseDto.prototype, "refreshTokenExpiresIn", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Token de atualização para obter novo access token sem novo login.',
        example: 'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9...',
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], LoginResponseDto.prototype, "refreshToken", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Tipo do token. Geralmente "Bearer" (padrão OAuth2).',
        example: 'Bearer',
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], LoginResponseDto.prototype, "tokenType", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Identificador da sessão no provedor (ex.: Keycloak session_state).',
        example: 'b909feea-ed27-4390-8280-660730964dcc',
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], LoginResponseDto.prototype, "sessionState", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Escopos concedidos ao token (ex.: openid, profile, email).',
        example: 'email profile',
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], LoginResponseDto.prototype, "scope", void 0);


/***/ }),
/* 44 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.LogoutCredentialsDto = void 0;
const class_validator_1 = __webpack_require__(41);
const swagger_1 = __webpack_require__(40);
const LOGOUT_TOKEN_MESSAGE = 'É necessário fornecer um refreshToken ou accessToken para realizar o logout.';
class LogoutCredentialsDto {
    refreshToken;
    accessToken;
}
exports.LogoutCredentialsDto = LogoutCredentialsDto;
__decorate([
    (0, swagger_1.ApiPropertyOptional)({ description: 'Refresh token do usuário' }),
    (0, class_validator_1.ValidateIf)((o) => !o.accessToken),
    (0, class_validator_1.IsNotEmpty)({ message: LOGOUT_TOKEN_MESSAGE }),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], LogoutCredentialsDto.prototype, "refreshToken", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({ description: 'Access token do usuário' }),
    (0, class_validator_1.ValidateIf)((o) => !o.refreshToken),
    (0, class_validator_1.IsNotEmpty)({ message: LOGOUT_TOKEN_MESSAGE }),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], LogoutCredentialsDto.prototype, "accessToken", void 0);


/***/ }),
/* 45 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.LogoutErrorResponseDto = void 0;
const swagger_1 = __webpack_require__(40);
const class_validator_1 = __webpack_require__(41);
class LogoutErrorResponseDto {
    message;
    error;
    details;
}
exports.LogoutErrorResponseDto = LogoutErrorResponseDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Mensagem de erro',
        example: 'Erro ao logout',
    }),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], LogoutErrorResponseDto.prototype, "message", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Erro',
        example: 'Erro ao logout',
    }),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], LogoutErrorResponseDto.prototype, "error", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Detalhe adicional do erro (opcional; em produção pode ser omitido ou sanitizado).',
        example: 'Erro ao logout',
    }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsOptional)(),
    __metadata("design:type", String)
], LogoutErrorResponseDto.prototype, "details", void 0);


/***/ }),
/* 46 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.LogoutResponseDto = void 0;
const swagger_1 = __webpack_require__(40);
const class_validator_1 = __webpack_require__(41);
class LogoutResponseDto {
    message;
}
exports.LogoutResponseDto = LogoutResponseDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Mensagem de logout',
        example: 'Logout realizado com sucesso',
    }),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], LogoutResponseDto.prototype, "message", void 0);


/***/ }),
/* 47 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.RefreshTokenCredentialsDto = void 0;
const swagger_1 = __webpack_require__(40);
const class_validator_1 = __webpack_require__(41);
class RefreshTokenCredentialsDto {
    refreshToken;
}
exports.RefreshTokenCredentialsDto = RefreshTokenCredentialsDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Refresh Token',
        example: 'refresh_token',
    }),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], RefreshTokenCredentialsDto.prototype, "refreshToken", void 0);


/***/ }),
/* 48 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.RefreshTokenErrorResponseDto = void 0;
const swagger_1 = __webpack_require__(40);
const class_validator_1 = __webpack_require__(41);
class RefreshTokenErrorResponseDto {
    error;
    message;
    details;
}
exports.RefreshTokenErrorResponseDto = RefreshTokenErrorResponseDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Código estável do erro para tratamento no front (ex.: invalid_grant, invalid_credentials).',
        example: 'invalid_grant',
    }),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], RefreshTokenErrorResponseDto.prototype, "error", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Mensagem do provedor de autenticação (ex.: error_description). Repassada para exibição ou log no front.',
        example: 'Invalid grant',
    }),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], RefreshTokenErrorResponseDto.prototype, "message", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Detalhe adicional do erro (opcional; em produção pode ser omitido ou sanitizado).',
        example: 'Invalid grant',
    }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsOptional)(),
    __metadata("design:type", String)
], RefreshTokenErrorResponseDto.prototype, "details", void 0);


/***/ }),
/* 49 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.RefreshTokenResponseDto = void 0;
const swagger_1 = __webpack_require__(40);
const class_validator_1 = __webpack_require__(41);
class RefreshTokenResponseDto {
    accessToken;
    expiresIn;
    refreshTokenExpiresIn;
    refreshToken;
    tokenType;
    sessionState;
    scope;
}
exports.RefreshTokenResponseDto = RefreshTokenResponseDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Token de acesso',
        example: '1234567890',
    }),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], RefreshTokenResponseDto.prototype, "accessToken", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Tempo de expiração do token de acesso',
        example: 3600,
    }),
    (0, class_validator_1.IsNumber)(),
    __metadata("design:type", Number)
], RefreshTokenResponseDto.prototype, "expiresIn", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Tempo de expiração do token de atualização',
        example: 3600,
    }),
    (0, class_validator_1.IsNumber)(),
    __metadata("design:type", Number)
], RefreshTokenResponseDto.prototype, "refreshTokenExpiresIn", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Token de atualização',
        example: '1234567890',
    }),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], RefreshTokenResponseDto.prototype, "refreshToken", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Tipo de token',
        example: 'Bearer',
    }),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], RefreshTokenResponseDto.prototype, "tokenType", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Estado da sessão',
        example: '1234567890',
    }),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], RefreshTokenResponseDto.prototype, "sessionState", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Escopo do token',
        example: 'openid profile email',
    }),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], RefreshTokenResponseDto.prototype, "scope", void 0);


/***/ }),
/* 50 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.TokenCredentialsDto = void 0;
const swagger_1 = __webpack_require__(40);
const class_validator_1 = __webpack_require__(41);
class TokenCredentialsDto {
    token;
}
exports.TokenCredentialsDto = TokenCredentialsDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Access token (Bearer)',
        example: 'access_token',
        required: true,
    }),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], TokenCredentialsDto.prototype, "token", void 0);


/***/ }),
/* 51 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UserInfoErrorResponseDto = void 0;
const swagger_1 = __webpack_require__(40);
const class_validator_1 = __webpack_require__(41);
const auth_messages_const_1 = __webpack_require__(6);
class UserInfoErrorResponseDto {
    error;
    message;
    details;
}
exports.UserInfoErrorResponseDto = UserInfoErrorResponseDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Código estável do erro para tratamento no front (ex.: invalid_grant, invalid_credentials).',
        example: 'invalid_grant',
    }),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], UserInfoErrorResponseDto.prototype, "error", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Mensagem do provedor de autenticação (ex.: error_description). Repassada para exibição ou log no front.',
        example: auth_messages_const_1.AUTH_MESSAGES.OAUTH_INVALID_CREDENTIALS,
    }),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", Object)
], UserInfoErrorResponseDto.prototype, "message", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Detalhe adicional do erro (opcional; em produção pode ser omitido ou sanitizado).',
        example: 'Account is disabled',
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], UserInfoErrorResponseDto.prototype, "details", void 0);


/***/ }),
/* 52 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UserInfoResponseDto = void 0;
const swagger_1 = __webpack_require__(40);
const class_validator_1 = __webpack_require__(41);
class UserInfoResponseDto {
    sub;
    email_verified;
    name;
    preferred_username;
    given_name;
    family_name;
    locale;
    email;
}
exports.UserInfoResponseDto = UserInfoResponseDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Sub do usuário',
        example: 'user_1234567890',
    }),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], UserInfoResponseDto.prototype, "sub", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Email verificado do usuário',
        example: false,
    }),
    (0, class_validator_1.IsBoolean)(),
    __metadata("design:type", Boolean)
], UserInfoResponseDto.prototype, "email_verified", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Nome do usuário',
        example: 'John Doe',
    }),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], UserInfoResponseDto.prototype, "name", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Nome social do usuário',
        example: 'John Doe',
    }),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], UserInfoResponseDto.prototype, "preferred_username", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Primeiro nome do usuário',
        example: 'John',
    }),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], UserInfoResponseDto.prototype, "given_name", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Sobrenome do usuário',
        example: 'Doe',
    }),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], UserInfoResponseDto.prototype, "family_name", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Localização do usuário',
        example: 'pt-BR',
    }),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], UserInfoResponseDto.prototype, "locale", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Email do usuário',
        example: 'user@example.com',
    }),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], UserInfoResponseDto.prototype, "email", void 0);


/***/ }),
/* 53 */
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ValidateErrorResponseDto = void 0;
class ValidateErrorResponseDto {
}
exports.ValidateErrorResponseDto = ValidateErrorResponseDto;


/***/ }),
/* 54 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a, _b, _c;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ValidateResponseDto = void 0;
const swagger_1 = __webpack_require__(40);
const class_validator_1 = __webpack_require__(41);
const dto_1 = __webpack_require__(38);
class ValidateResponseDto {
    sub;
    exp;
    iat;
    jti;
    iss;
    aud;
    typ;
    scope;
    email;
    email_verified;
    name;
    preferred_username;
    given_name;
    family_name;
    locale;
    roles;
    realm_access;
    resource_access;
    additionalClaims;
}
exports.ValidateResponseDto = ValidateResponseDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Subject - user identifier (OIDC)',
        example: 'c29e18b3-8ad4-4bcd-b5ab-b075e0d6f6ef',
    }),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], ValidateResponseDto.prototype, "sub", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Token expiration (seconds since Unix epoch)',
        example: 1769963193,
    }),
    (0, class_validator_1.IsNumber)(),
    __metadata("design:type", Number)
], ValidateResponseDto.prototype, "exp", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Token issued at (seconds since Unix epoch)',
        example: 1769962893,
    }),
    (0, class_validator_1.IsNumber)(),
    __metadata("design:type", Number)
], ValidateResponseDto.prototype, "iat", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'JWT ID',
        example: 'b2a88ebe-a4bf-4620-842d-3c031834757d',
    }),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], ValidateResponseDto.prototype, "jti", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Issuer',
        example: 'https://auth.tiwiki.com.br/realms/orchestron-core',
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsUrl)(),
    __metadata("design:type", String)
], ValidateResponseDto.prototype, "iss", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Audience',
        example: 'account',
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], ValidateResponseDto.prototype, "aud", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Tipo do token',
        example: 'Bearer',
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], ValidateResponseDto.prototype, "typ", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Scopes (OAuth2/OIDC)',
        example: 'email profile openid',
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], ValidateResponseDto.prototype, "scope", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'User email',
        example: 'test@test.com',
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], ValidateResponseDto.prototype, "email", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Email verified',
        example: false,
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsBoolean)(),
    __metadata("design:type", Boolean)
], ValidateResponseDto.prototype, "email_verified", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Full name',
        example: 'Teste Silva',
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], ValidateResponseDto.prototype, "name", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Preferred username',
        example: 'test',
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], ValidateResponseDto.prototype, "preferred_username", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Given name',
        example: 'Teste',
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], ValidateResponseDto.prototype, "given_name", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Family name',
        example: 'Silva',
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], ValidateResponseDto.prototype, "family_name", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'User locale',
        example: 'pt-BR',
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], ValidateResponseDto.prototype, "locale", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Roles list (each strategy maps as needed)',
        example: [
            'offline_access',
            'default-roles-orchestron-core',
            'manage-account',
        ],
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsArray)(),
    (0, class_validator_1.IsString)({ each: true }),
    __metadata("design:type", Array)
], ValidateResponseDto.prototype, "roles", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Realm roles (e.g. Keycloak realm_access)',
        type: dto_1.RealmAccessDto,
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsObject)(),
    __metadata("design:type", typeof (_a = typeof dto_1.RealmAccessDto !== "undefined" && dto_1.RealmAccessDto) === "function" ? _a : Object)
], ValidateResponseDto.prototype, "realm_access", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Roles per resource (e.g. Keycloak resource_access)',
        example: { account: { roles: ['manage-account', 'view-profile'] } },
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsObject)(),
    __metadata("design:type", typeof (_b = typeof Record !== "undefined" && Record) === "function" ? _b : Object)
], ValidateResponseDto.prototype, "resource_access", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Additional strategy-specific claims (azp, sid, acr, etc.)',
        example: {
            azp: 'orchestron-core',
            sid: '9641f0fa-ab1e-40f8-b093-f4c32ae163c2',
        },
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsObject)(),
    __metadata("design:type", typeof (_c = typeof Record !== "undefined" && Record) === "function" ? _c : Object)
], ValidateResponseDto.prototype, "additionalClaims", void 0);


/***/ }),
/* 55 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.RealmAccessDto = void 0;
const swagger_1 = __webpack_require__(40);
const class_validator_1 = __webpack_require__(41);
class RealmAccessDto {
    roles;
}
exports.RealmAccessDto = RealmAccessDto;
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Roles do realm',
        example: ['offline_access', 'default-roles-orchestron-core'],
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsArray)(),
    (0, class_validator_1.IsString)({ each: true }),
    __metadata("design:type", Array)
], RealmAccessDto.prototype, "roles", void 0);


/***/ }),
/* 56 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ResourceAccessDto = void 0;
const swagger_1 = __webpack_require__(40);
const class_validator_1 = __webpack_require__(41);
class ResourceAccessDto {
    roles;
}
exports.ResourceAccessDto = ResourceAccessDto;
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Roles do recurso',
        example: ['manage-account', 'view-profile'],
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsArray)(),
    (0, class_validator_1.IsString)({ each: true }),
    __metadata("design:type", Array)
], ResourceAccessDto.prototype, "roles", void 0);


/***/ }),
/* 57 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
__exportStar(__webpack_require__(58), exports);
__exportStar(__webpack_require__(66), exports);
__exportStar(__webpack_require__(67), exports);


/***/ }),
/* 58 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var AuthGuard_1;
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AuthGuard = void 0;
const common_1 = __webpack_require__(14);
const core_1 = __webpack_require__(59);
const constants_1 = __webpack_require__(1);
const internal_util_1 = __webpack_require__(20);
const public_decorator_1 = __webpack_require__(13);
const auth_vault_logger_factory_const_1 = __webpack_require__(60);
const tokens_1 = __webpack_require__(61);
let AuthGuard = AuthGuard_1 = class AuthGuard {
    authVaultService;
    reflector;
    options;
    logger;
    constructor(authVaultService, reflector, createLogger, options) {
        this.authVaultService = authVaultService;
        this.reflector = reflector;
        this.options = options;
        this.logger = createLogger(AuthGuard_1.name);
    }
    async canActivate(context) {
        const isPublic = this.reflector.getAllAndOverride(public_decorator_1.META_PUBLIC, [
            context.getClass(),
            context.getHandler(),
        ]);
        const cookieKey = this.options?.cookieKey || constants_1.AUTH_GUARD_COOKIE_DEFAULT;
        const [request] = (0, internal_util_1.extractRequestAndAttachCookie)(context, cookieKey);
        if (!request)
            return true;
        const jwt = this.extractJwtFromHeader(request.headers) ?? '';
        const isJwtEmpty = !jwt || jwt.trim() === '';
        if (!isPublic && isJwtEmpty) {
            this.logger.verbose(constants_1.AUTH_MESSAGES.GUARD_TOKEN_MISSING);
            throw new common_1.UnauthorizedException(constants_1.AUTH_MESSAGES.HTTP_UNAUTHORIZED);
        }
        if (isPublic && isJwtEmpty)
            return true;
        this.logger.verbose(constants_1.AUTH_MESSAGES.GUARD_TOKEN_VALIDATING, { jwt });
        const response = await this.authVaultService.validate({ token: jwt });
        if (response.success) {
            request.user = response.data;
            request.jwtPayload = (0, internal_util_1.parseToken)(jwt);
            request.accessToken = jwt;
            this.logger.verbose(constants_1.AUTH_MESSAGES.GUARD_USER_AUTHENTICATED, {
                user: request.user,
            });
            return true;
        }
        if (isPublic) {
            this.logger.warn(constants_1.AUTH_MESSAGES.GUARD_TOKEN_VALIDATION_FAILED_ON_PUBLIC_ROUTE, { jwt });
            return true;
        }
        this.logger.verbose(constants_1.AUTH_MESSAGES.GUARD_TOKEN_INVALID, { jwt });
        throw new common_1.UnauthorizedException(constants_1.AUTH_MESSAGES.HTTP_UNAUTHENTICATED);
    }
    extractJwtFromHeader(headers) {
        if (headers && !headers?.authorization) {
            this.logger.verbose(constants_1.AUTH_MESSAGES.GUARD_HEADER_AUTHORIZATION_MISSING);
            return null;
        }
        const auth = (headers?.authorization ?? '').split(' ');
        if (auth[0].toLowerCase() !== 'bearer') {
            this.logger.verbose(constants_1.AUTH_MESSAGES.GUARD_HEADER_BEARER_NOT_FOUND);
            return null;
        }
        return auth[1];
    }
};
exports.AuthGuard = AuthGuard;
exports.AuthGuard = AuthGuard = AuthGuard_1 = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, common_1.Inject)(tokens_1.AUTH_VAULT_SERVICE)),
    __param(2, (0, common_1.Inject)(auth_vault_logger_factory_const_1.AUTH_VAULT_LOGGER_FACTORY)),
    __param(3, (0, common_1.Optional)()),
    __param(3, (0, common_1.Inject)(constants_1.AUTH_GUARD_OPTIONS)),
    __metadata("design:paramtypes", [Object, typeof (_a = typeof core_1.Reflector !== "undefined" && core_1.Reflector) === "function" ? _a : Object, Function, Object])
], AuthGuard);


/***/ }),
/* 59 */
/***/ ((module) => {

module.exports = require("@nestjs/core");

/***/ }),
/* 60 */
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AUTH_VAULT_LOGGER_FACTORY = void 0;
exports.AUTH_VAULT_LOGGER_FACTORY = 'AUTH_VAULT_LOGGER_FACTORY';


/***/ }),
/* 61 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
__exportStar(__webpack_require__(62), exports);
__exportStar(__webpack_require__(63), exports);
__exportStar(__webpack_require__(64), exports);
__exportStar(__webpack_require__(65), exports);


/***/ }),
/* 62 */
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AUTH_STRATEGIES_TOKEN = void 0;
exports.AUTH_STRATEGIES_TOKEN = Symbol('AUTH_STRATEGIES');


/***/ }),
/* 63 */
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AUTH_VAULT_OPTIONS = void 0;
exports.AUTH_VAULT_OPTIONS = 'AUTH_VAULT_OPTIONS';


/***/ }),
/* 64 */
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AUTH_STRATEGY_CONFIG = void 0;
exports.AUTH_STRATEGY_CONFIG = Symbol('AUTH_STRATEGY_CONFIG');


/***/ }),
/* 65 */
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AUTH_VAULT_SERVICE = void 0;
exports.AUTH_VAULT_SERVICE = Symbol.for('IAuthVaultService');


/***/ }),
/* 66 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var ResourceGuard_1;
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ResourceGuard = void 0;
const common_1 = __webpack_require__(14);
const core_1 = __webpack_require__(59);
const constants_1 = __webpack_require__(1);
const utils_1 = __webpack_require__(19);
const decorators_1 = __webpack_require__(12);
const auth_vault_logger_factory_const_1 = __webpack_require__(60);
const tokens_1 = __webpack_require__(61);
let ResourceGuard = ResourceGuard_1 = class ResourceGuard {
    reflector;
    authVaultService;
    options;
    logger;
    constructor(reflector, authVaultService, createLogger, options) {
        this.reflector = reflector;
        this.authVaultService = authVaultService;
        this.options = options;
        this.logger = createLogger(ResourceGuard_1.name);
    }
    async canActivate(context) {
        const resource = this.reflector.get(decorators_1.META_RESOURCE, context.getClass());
        const explicitScopes = this.reflector.get(decorators_1.META_SCOPES, context.getHandler()) ?? [];
        const conditionalScopes = this.reflector.get(decorators_1.META_CONDITIONAL_SCOPES, context.getHandler());
        const isPublic = this.reflector.getAllAndOverride(decorators_1.META_PUBLIC, [
            context.getClass(),
            context.getHandler(),
        ]);
        const enforcerOpts = this.reflector.getAllAndOverride(constants_1.META_ENFORCER_OPTIONS, [context.getClass(), context.getHandler()]);
        const policyEnforcementMode = enforcerOpts?.policyEnforcementMode ??
            this.options?.policyEnforcementMode ??
            constants_1.PolicyEnforcementMode.PERMISSIVE;
        const shouldAllow = policyEnforcementMode === constants_1.PolicyEnforcementMode.PERMISSIVE;
        const cookieKey = this.options?.cookieKey || constants_1.AUTH_GUARD_COOKIE_DEFAULT;
        const [request] = (0, utils_1.extractRequestAndAttachCookie)(context, cookieKey);
        if (!request)
            return true;
        if (!request.user && isPublic) {
            this.logger.verbose(constants_1.AUTH_MESSAGES.GUARD_TOKEN_VALIDATION_FAILED_ON_PUBLIC_ROUTE);
            return true;
        }
        if (!resource) {
            if (shouldAllow)
                this.logger.verbose(constants_1.AUTH_MESSAGES.GUARD_CONTROLLER_WITHOUT_RESOURCE_PERMISSIVE);
            else {
                this.logger.verbose(constants_1.AUTH_MESSAGES.GUARD_CONTROLLER_WITHOUT_RESOURCE_ENFORCING);
                throw new common_1.ForbiddenException(constants_1.AUTH_MESSAGES.HTTP_FORBIDDEN);
            }
            return shouldAllow;
        }
        const conditionalScopesResult = conditionalScopes != null
            ? conditionalScopes(request, request.accessToken ?? '')
            : [];
        const scopes = [...explicitScopes, ...conditionalScopesResult];
        request.scopes = scopes;
        if (!scopes || !scopes.length) {
            if (shouldAllow)
                this.logger.verbose(constants_1.AUTH_MESSAGES.GUARD_CONTROLLER_WITHOUT_SCOPES_PERMISSIVE);
            else {
                this.logger.verbose(constants_1.AUTH_MESSAGES.GUARD_CONTROLLER_WITHOUT_SCOPES_ENFORCING);
                throw new common_1.ForbiddenException(constants_1.AUTH_MESSAGES.HTTP_FORBIDDEN);
            }
            return shouldAllow;
        }
        this.logger.verbose(`Protegendo recurso [ "${resource}" ] com escopos [ ${scopes.join(', ')} ].`);
        const userLabel = request.user?.preferred_username ?? 'user';
        if (!request.user) {
            this.logger.verbose(`Recurso [ "${resource}" ] negado para [ ${userLabel} ].`);
            throw new common_1.ForbiddenException(constants_1.AUTH_MESSAGES.RESOURCE_ACCESS_DENIED);
        }
        const userRoles = await this.authVaultService.getRolesForResource(request.user, resource);
        const isAllowed = scopes.some((scope) => userRoles.includes(scope));
        if (!isAllowed) {
            this.logger.verbose(`Recurso [ "${resource}" ] negado para [ ${userLabel} ].`);
            throw new common_1.ForbiddenException(constants_1.AUTH_MESSAGES.RESOURCE_ACCESS_DENIED);
        }
        this.logger.verbose(`Recurso [ "${resource}" ] permitido para [ ${userLabel} ].`);
        return true;
    }
};
exports.ResourceGuard = ResourceGuard;
exports.ResourceGuard = ResourceGuard = ResourceGuard_1 = __decorate([
    (0, common_1.Injectable)(),
    __param(1, (0, common_1.Inject)(tokens_1.AUTH_VAULT_SERVICE)),
    __param(2, (0, common_1.Inject)(auth_vault_logger_factory_const_1.AUTH_VAULT_LOGGER_FACTORY)),
    __param(3, (0, common_1.Optional)()),
    __param(3, (0, common_1.Inject)(constants_1.RESOURCE_GUARD_OPTIONS)),
    __metadata("design:paramtypes", [typeof (_a = typeof core_1.Reflector !== "undefined" && core_1.Reflector) === "function" ? _a : Object, Object, Function, Object])
], ResourceGuard);


/***/ }),
/* 67 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var RoleGuard_1;
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.RoleGuard = void 0;
const auth_messages_const_1 = __webpack_require__(6);
const common_1 = __webpack_require__(14);
const core_1 = __webpack_require__(59);
const role_guard_const_1 = __webpack_require__(10);
const constants_1 = __webpack_require__(1);
const decorators_1 = __webpack_require__(12);
const utils_1 = __webpack_require__(19);
const auth_vault_logger_factory_const_1 = __webpack_require__(60);
const tokens_1 = __webpack_require__(61);
let RoleGuard = RoleGuard_1 = class RoleGuard {
    reflector;
    authVaultService;
    options;
    logger;
    constructor(reflector, authVaultService, createLogger, options) {
        this.reflector = reflector;
        this.authVaultService = authVaultService;
        this.options = options;
        this.logger = createLogger(RoleGuard_1.name);
    }
    async canActivate(context) {
        const defaultMatch = this.options?.roleMatch ?? constants_1.RoleMatch.ANY;
        const requiredRoles = this.getRequiredRoles(context);
        const matchingMode = this.reflector.getAllAndOverride(decorators_1.META_ROLE_MATCHING_MODE, [
            context.getClass(),
            context.getHandler(),
        ]) ?? defaultMatch;
        if (!requiredRoles.length) {
            this.logger.warn(auth_messages_const_1.AUTH_MESSAGES.GUARD_NO_ROLES_REQUIRED);
            return true;
        }
        this.logger.verbose(`Modo de matching: ${matchingMode}`, {
            roles: requiredRoles,
        });
        const cookieKey = this.options?.cookieKey || constants_1.AUTH_GUARD_COOKIE_DEFAULT;
        const [request] = (0, utils_1.extractRequestAndAttachCookie)(context, cookieKey);
        if (!request)
            return true;
        if (!request.accessToken) {
            this.logger.warn(auth_messages_const_1.AUTH_MESSAGES.GUARD_ACCESS_TOKEN_NOT_FOUND);
            throw new common_1.ForbiddenException(auth_messages_const_1.AUTH_MESSAGES.HTTP_FORBIDDEN);
        }
        if (!request.user) {
            this.logger.warn(auth_messages_const_1.AUTH_MESSAGES.ROLE_ACCESS_DENIED);
            throw new common_1.ForbiddenException(auth_messages_const_1.AUTH_MESSAGES.ROLE_ACCESS_DENIED);
        }
        const strategyRoles = await this.authVaultService.getRoles(request.user);
        const granted = matchingMode === constants_1.RoleMatch.ANY
            ? requiredRoles.some((role) => strategyRoles.includes(role))
            : requiredRoles.every((role) => strategyRoles.includes(role));
        if (granted)
            this.logger.verbose('Acesso permitido por role(s)');
        else {
            this.logger.verbose('Acesso negado: role(s) não conferem.');
            throw new common_1.ForbiddenException(auth_messages_const_1.AUTH_MESSAGES.ROLE_ACCESS_DENIED);
        }
        return granted;
    }
    getRequiredRoles(context) {
        const roleMerge = this.options?.roleMerge ?? constants_1.RoleMerge.OVERRIDE;
        let requiredRoles = [];
        switch (roleMerge) {
            case constants_1.RoleMerge.ALL: {
                const merged = this.reflector.getAllAndMerge(decorators_1.META_ROLES, [
                    context.getClass(),
                    context.getHandler(),
                ]);
                if (merged)
                    requiredRoles = merged;
                break;
            }
            case constants_1.RoleMerge.OVERRIDE: {
                const overridden = this.reflector.getAllAndOverride(decorators_1.META_ROLES, [context.getClass(), context.getHandler()]);
                if (overridden)
                    requiredRoles = overridden;
                break;
            }
            default:
                throw Error(`Invalid role merge mode: ${String(roleMerge)}`);
        }
        return requiredRoles;
    }
};
exports.RoleGuard = RoleGuard;
exports.RoleGuard = RoleGuard = RoleGuard_1 = __decorate([
    (0, common_1.Injectable)(),
    __param(1, (0, common_1.Inject)(tokens_1.AUTH_VAULT_SERVICE)),
    __param(2, (0, common_1.Inject)(auth_vault_logger_factory_const_1.AUTH_VAULT_LOGGER_FACTORY)),
    __param(3, (0, common_1.Optional)()),
    __param(3, (0, common_1.Inject)(role_guard_const_1.ROLE_GUARD_OPTIONS)),
    __metadata("design:paramtypes", [typeof (_a = typeof core_1.Reflector !== "undefined" && core_1.Reflector) === "function" ? _a : Object, Object, Function, Object])
], RoleGuard);


/***/ }),
/* 68 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
__exportStar(__webpack_require__(69), exports);
__exportStar(__webpack_require__(70), exports);
__exportStar(__webpack_require__(71), exports);
__exportStar(__webpack_require__(72), exports);
__exportStar(__webpack_require__(73), exports);
__exportStar(__webpack_require__(74), exports);
__exportStar(__webpack_require__(75), exports);
__exportStar(__webpack_require__(76), exports);
__exportStar(__webpack_require__(77), exports);


/***/ }),
/* 69 */
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));


/***/ }),
/* 70 */
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));


/***/ }),
/* 71 */
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));


/***/ }),
/* 72 */
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));


/***/ }),
/* 73 */
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));


/***/ }),
/* 74 */
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));


/***/ }),
/* 75 */
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));


/***/ }),
/* 76 */
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));


/***/ }),
/* 77 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.StrategyConfigDtoClassMap = void 0;
const keycloak_config_dto_1 = __webpack_require__(78);
exports.StrategyConfigDtoClassMap = {
    keycloak: keycloak_config_dto_1.KeycloakConfigDto,
};


/***/ }),
/* 78 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.KeycloakConfigDto = void 0;
const class_validator_1 = __webpack_require__(41);
class KeycloakConfigDto {
    clientId;
    clientSecret;
    realm;
    url;
    authServerUrl;
    bearerOnly;
    realmPublicKey;
    minTimeBetweenJwksRequests;
    verifyTokenAudience;
    public;
}
exports.KeycloakConfigDto = KeycloakConfigDto;
__decorate([
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", String)
], KeycloakConfigDto.prototype, "clientId", void 0);
__decorate([
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", String)
], KeycloakConfigDto.prototype, "clientSecret", void 0);
__decorate([
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", String)
], KeycloakConfigDto.prototype, "realm", void 0);
__decorate([
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsNotEmpty)(),
    (0, class_validator_1.IsUrl)(),
    __metadata("design:type", String)
], KeycloakConfigDto.prototype, "url", void 0);
__decorate([
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsUrl)(),
    __metadata("design:type", String)
], KeycloakConfigDto.prototype, "authServerUrl", void 0);
__decorate([
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsBoolean)(),
    __metadata("design:type", Boolean)
], KeycloakConfigDto.prototype, "bearerOnly", void 0);
__decorate([
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], KeycloakConfigDto.prototype, "realmPublicKey", void 0);
__decorate([
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsNumber)(),
    (0, class_validator_1.Min)(0),
    __metadata("design:type", Number)
], KeycloakConfigDto.prototype, "minTimeBetweenJwksRequests", void 0);
__decorate([
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsBoolean)(),
    __metadata("design:type", Boolean)
], KeycloakConfigDto.prototype, "verifyTokenAudience", void 0);
__decorate([
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsBoolean)(),
    __metadata("design:type", Boolean)
], KeycloakConfigDto.prototype, "public", void 0);


/***/ }),
/* 79 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var AuthVaultModule_1;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AuthVaultModule = void 0;
exports.buildAsyncOptionsProvider = buildAsyncOptionsProvider;
const common_1 = __webpack_require__(14);
const axios_1 = __webpack_require__(80);
const tokens_1 = __webpack_require__(61);
const auth_vault_service_1 = __webpack_require__(81);
const constants_1 = __webpack_require__(1);
const auth_vault_providers_1 = __webpack_require__(82);
const rootImports = [axios_1.HttpModule.register(constants_1.defaultHttpOptions)];
let AuthVaultModule = AuthVaultModule_1 = class AuthVaultModule {
    static forRoot(options) {
        const opts = { ...options };
        const providers = [
            { provide: tokens_1.AUTH_VAULT_OPTIONS, useValue: opts },
            ...(0, auth_vault_providers_1.buildProviders)(opts),
        ];
        const httpOptions = { ...constants_1.defaultHttpOptions, ...opts.http };
        return {
            module: AuthVaultModule_1,
            global: options.isGlobal ?? false,
            imports: [...rootImports, axios_1.HttpModule.register(httpOptions)],
            providers,
            exports: [auth_vault_service_1.AuthVaultService, tokens_1.AUTH_VAULT_SERVICE],
            controllers: [],
        };
    }
    static forRootAsync(options) {
        const asyncProvider = AuthVaultModule_1.createAsyncOptionsProvider(options);
        const providers = [
            asyncProvider,
            ...(0, auth_vault_providers_1.buildCoreProviders)(),
            ...(0, auth_vault_providers_1.buildOptionsProvidersAsync)(),
        ];
        return {
            module: AuthVaultModule_1,
            global: options.isGlobal ?? false,
            imports: rootImports,
            providers,
            exports: [auth_vault_service_1.AuthVaultService, tokens_1.AUTH_VAULT_SERVICE],
            controllers: [],
        };
    }
    static forFeature(options) {
        const providers = (0, auth_vault_providers_1.buildFeatureProviders)(options);
        return {
            module: AuthVaultModule_1,
            global: false,
            imports: [axios_1.HttpModule.register(constants_1.defaultHttpOptions)],
            providers,
            exports: [auth_vault_service_1.AuthVaultService, tokens_1.AUTH_VAULT_SERVICE],
            controllers: [],
        };
    }
    static forFeatureAsync(asyncOptions) {
        const providers = (0, auth_vault_providers_1.buildFeatureProvidersAsync)(asyncOptions);
        return {
            module: AuthVaultModule_1,
            global: false,
            imports: [axios_1.HttpModule.register(constants_1.defaultHttpOptions)],
            providers,
            exports: [auth_vault_service_1.AuthVaultService, tokens_1.AUTH_VAULT_SERVICE],
            controllers: [],
        };
    }
    static createAsyncOptionsProvider(options) {
        return buildAsyncOptionsProvider(options);
    }
};
exports.AuthVaultModule = AuthVaultModule;
exports.AuthVaultModule = AuthVaultModule = AuthVaultModule_1 = __decorate([
    (0, common_1.Module)({})
], AuthVaultModule);
function buildAsyncOptionsProvider(options) {
    if (options.useFactory) {
        return {
            provide: tokens_1.AUTH_VAULT_OPTIONS,
            useFactory: options.useFactory,
            inject: options.inject || [],
        };
    }
    const useClass = options.useClass ?? options.useExisting;
    if (!useClass)
        throw new Error('AuthVaultModuleAsyncOptions must provide useFactory, useClass or useExisting');
    return {
        provide: tokens_1.AUTH_VAULT_OPTIONS,
        useFactory: async (factory) => await factory.createAuthVaultOptions(),
        inject: [useClass],
    };
}


/***/ }),
/* 80 */
/***/ ((module) => {

module.exports = require("@nestjs/axios");

/***/ }),
/* 81 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var AuthVaultService_1;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AuthVaultService = void 0;
const common_1 = __webpack_require__(14);
const auth_strategies_token_1 = __webpack_require__(62);
const tokens_1 = __webpack_require__(61);
const auth_vault_logger_factory_const_1 = __webpack_require__(60);
let AuthVaultService = AuthVaultService_1 = class AuthVaultService {
    authStrategies;
    moduleOptions;
    logger;
    strategy;
    constructor(authStrategies, moduleOptions, createLogger) {
        this.authStrategies = authStrategies;
        this.moduleOptions = moduleOptions;
        this.logger = createLogger(AuthVaultService_1.name);
        const name = this.moduleOptions?.strategyConfig?.name;
        if (!name)
            throw new Error('Strategy name is required');
        this.strategy = this.getStrategy(name);
    }
    getStrategy(strategyName) {
        const strategy = this.authStrategies.find((strategy) => strategy.name === strategyName);
        if (!strategy)
            throw new Error(`Strategy ${strategyName} not found`);
        return strategy;
    }
    async login(credentials) {
        const response = await this.strategy.login(credentials);
        if (response.success)
            return response.data;
        throw new common_1.UnauthorizedException(response.data);
    }
    async logout(logoutToken) {
        const response = await this.strategy.logout(logoutToken);
        if (response.success)
            return response.data;
        throw new common_1.BadRequestException(response.data);
    }
    async refreshToken(refreshToken) {
        const response = await this.strategy.refreshToken(refreshToken);
        if (response.success)
            return response.data;
        throw new common_1.UnauthorizedException(response.data);
    }
    async getUserInfo(token) {
        const response = await this.strategy.getUserInfo(token);
        if (response.success)
            return response.data;
        if (response.statusCode === 401)
            throw new common_1.UnauthorizedException(response.data);
        if (response.statusCode === 403)
            throw new common_1.ForbiddenException(response.data);
        throw new common_1.BadRequestException(response.data);
    }
    async validate(credentials) {
        return await this.strategy.validate(credentials);
    }
    async getRolesForResource(user, resource) {
        const roles = await this.strategy.getRolesForResource(user, resource);
        return Array.isArray(roles) ? roles : [];
    }
    async getRoles(user) {
        const roles = await this.strategy.getRoles(user);
        return Array.isArray(roles) ? roles : [];
    }
};
exports.AuthVaultService = AuthVaultService;
exports.AuthVaultService = AuthVaultService = AuthVaultService_1 = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, common_1.Inject)(auth_strategies_token_1.AUTH_STRATEGIES_TOKEN)),
    __param(1, (0, common_1.Inject)(tokens_1.AUTH_VAULT_OPTIONS)),
    __param(2, (0, common_1.Inject)(auth_vault_logger_factory_const_1.AUTH_VAULT_LOGGER_FACTORY)),
    __metadata("design:paramtypes", [Array, Object, Function])
], AuthVaultService);


/***/ }),
/* 82 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.buildCoreProviders = buildCoreProviders;
exports.buildOptionsProvidersSync = buildOptionsProvidersSync;
exports.buildOptionsProvidersAsync = buildOptionsProvidersAsync;
exports.buildProviders = buildProviders;
exports.buildFeatureProviders = buildFeatureProviders;
exports.buildFeatureProvidersAsync = buildFeatureProvidersAsync;
const axios_1 = __webpack_require__(80);
const core_1 = __webpack_require__(59);
const auth_guard_const_1 = __webpack_require__(5);
const tokens_1 = __webpack_require__(61);
const strategies_registry_1 = __webpack_require__(83);
const constants_1 = __webpack_require__(1);
const auth_vault_logger_factory_const_1 = __webpack_require__(60);
const auth_vault_logger_1 = __webpack_require__(90);
const auth_vault_service_1 = __webpack_require__(81);
const guards_1 = __webpack_require__(57);
const FEATURE_STRATEGY_INSTANCE = Symbol('AuthVaultFeatureStrategyInstance');
const strategies = Object.values(strategies_registry_1.AUTH_STRATEGIES_REGISTRY);
function buildGuardOptionsFromLibrary(options) {
    const cookieKey = options?.cookieKey ?? auth_guard_const_1.AUTH_GUARD_COOKIE_DEFAULT;
    return {
        authGuard: {
            cookieKey,
            tokenValidation: options?.tokenValidation,
        },
        resourceGuard: {
            cookieKey,
            policyEnforcementMode: options?.policyEnforcement ?? constants_1.PolicyEnforcementMode.PERMISSIVE,
        },
        roleGuard: {
            cookieKey,
            roleMerge: options?.roleMerge ?? constants_1.RoleMerge.OVERRIDE,
            roleMatch: options?.roleMatch ?? constants_1.RoleMatch.ANY,
        },
    };
}
function buildCoreProviders() {
    return [
        {
            provide: tokens_1.AUTH_STRATEGIES_TOKEN,
            useFactory: (...injectedStrategies) => injectedStrategies,
            inject: [...strategies],
        },
        {
            provide: auth_vault_logger_factory_const_1.AUTH_VAULT_LOGGER_FACTORY,
            useFactory: (opts) => (context) => new auth_vault_logger_1.AuthVaultLogger(opts?.logLevels, context),
            inject: [tokens_1.AUTH_VAULT_OPTIONS],
        },
        {
            provide: tokens_1.AUTH_VAULT_SERVICE,
            useExisting: auth_vault_service_1.AuthVaultService,
        },
        auth_vault_service_1.AuthVaultService,
        ...strategies,
        {
            provide: core_1.APP_GUARD,
            useClass: guards_1.AuthGuard,
        },
        {
            provide: core_1.APP_GUARD,
            useClass: guards_1.ResourceGuard,
        },
        {
            provide: core_1.APP_GUARD,
            useClass: guards_1.RoleGuard,
        },
    ];
}
function buildOptionsProvidersSync(options) {
    const guardOptions = buildGuardOptionsFromLibrary(options);
    return [
        {
            provide: tokens_1.AUTH_STRATEGY_CONFIG,
            useValue: options.strategyConfig,
        },
        {
            provide: auth_guard_const_1.AUTH_GUARD_OPTIONS,
            useValue: guardOptions.authGuard,
        },
        {
            provide: constants_1.RESOURCE_GUARD_OPTIONS,
            useValue: guardOptions.resourceGuard,
        },
        {
            provide: constants_1.ROLE_GUARD_OPTIONS,
            useValue: guardOptions.roleGuard,
        },
    ];
}
function buildOptionsProvidersAsync() {
    return [
        {
            provide: tokens_1.AUTH_STRATEGY_CONFIG,
            useFactory: (opts) => opts.strategyConfig,
            inject: [tokens_1.AUTH_VAULT_OPTIONS],
        },
        {
            provide: auth_guard_const_1.AUTH_GUARD_OPTIONS,
            useFactory: (opts) => buildGuardOptionsFromLibrary(opts).authGuard,
            inject: [tokens_1.AUTH_VAULT_OPTIONS],
        },
        {
            provide: constants_1.RESOURCE_GUARD_OPTIONS,
            useFactory: (opts) => buildGuardOptionsFromLibrary(opts).resourceGuard,
            inject: [tokens_1.AUTH_VAULT_OPTIONS],
        },
        {
            provide: constants_1.ROLE_GUARD_OPTIONS,
            useFactory: (opts) => buildGuardOptionsFromLibrary(opts).roleGuard,
            inject: [tokens_1.AUTH_VAULT_OPTIONS],
        },
    ];
}
function buildProviders(options) {
    const strategyName = options.strategyConfig?.name;
    if (!strategyName)
        throw new Error('Strategy name is required');
    return [...buildCoreProviders(), ...buildOptionsProvidersSync(options)];
}
function buildFeatureProviders(options) {
    const strategyName = options.strategyConfig?.name;
    if (!strategyName)
        throw new Error('Strategy name is required');
    const guardOptions = buildGuardOptionsFromLibrary(options);
    const StrategyClass = strategies_registry_1.AUTH_STRATEGIES_REGISTRY[strategyName];
    if (!StrategyClass)
        throw new Error(`Strategy ${strategyName} not found`);
    return [
        { provide: tokens_1.AUTH_VAULT_OPTIONS, useValue: options },
        { provide: tokens_1.AUTH_STRATEGY_CONFIG, useValue: options.strategyConfig },
        { provide: auth_guard_const_1.AUTH_GUARD_OPTIONS, useValue: guardOptions.authGuard },
        { provide: constants_1.RESOURCE_GUARD_OPTIONS, useValue: guardOptions.resourceGuard },
        { provide: constants_1.ROLE_GUARD_OPTIONS, useValue: guardOptions.roleGuard },
        {
            provide: auth_vault_logger_factory_const_1.AUTH_VAULT_LOGGER_FACTORY,
            useFactory: (opts) => (context) => new auth_vault_logger_1.AuthVaultLogger(opts?.logLevels, context),
            inject: [tokens_1.AUTH_VAULT_OPTIONS],
        },
        {
            provide: FEATURE_STRATEGY_INSTANCE,
            useFactory: (config, httpService, createLogger) => new StrategyClass(config, httpService, createLogger),
            inject: [tokens_1.AUTH_STRATEGY_CONFIG, axios_1.HttpService, auth_vault_logger_factory_const_1.AUTH_VAULT_LOGGER_FACTORY],
        },
        {
            provide: tokens_1.AUTH_STRATEGIES_TOKEN,
            useFactory: (instance) => [instance],
            inject: [FEATURE_STRATEGY_INSTANCE],
        },
        {
            provide: auth_vault_service_1.AuthVaultService,
            useFactory: (strategies, opts, createLogger) => new auth_vault_service_1.AuthVaultService(strategies, opts, createLogger),
            inject: [
                tokens_1.AUTH_STRATEGIES_TOKEN,
                tokens_1.AUTH_VAULT_OPTIONS,
                auth_vault_logger_factory_const_1.AUTH_VAULT_LOGGER_FACTORY,
            ],
        },
        {
            provide: tokens_1.AUTH_VAULT_SERVICE,
            useExisting: auth_vault_service_1.AuthVaultService,
        },
        {
            provide: core_1.APP_GUARD,
            useFactory: (svc, reflector, createLogger, guardOpts) => new guards_1.AuthGuard(svc, reflector, createLogger, guardOpts),
            inject: [
                tokens_1.AUTH_VAULT_SERVICE,
                core_1.Reflector,
                auth_vault_logger_factory_const_1.AUTH_VAULT_LOGGER_FACTORY,
                auth_guard_const_1.AUTH_GUARD_OPTIONS,
            ],
        },
        {
            provide: core_1.APP_GUARD,
            useFactory: (reflector, svc, createLogger, guardOpts) => new guards_1.RoleGuard(reflector, svc, createLogger, guardOpts),
            inject: [
                core_1.Reflector,
                tokens_1.AUTH_VAULT_SERVICE,
                auth_vault_logger_factory_const_1.AUTH_VAULT_LOGGER_FACTORY,
                constants_1.ROLE_GUARD_OPTIONS,
            ],
        },
        {
            provide: core_1.APP_GUARD,
            useFactory: (reflector, svc, createLogger, guardOpts) => new guards_1.ResourceGuard(reflector, svc, createLogger, guardOpts),
            inject: [
                core_1.Reflector,
                tokens_1.AUTH_VAULT_SERVICE,
                auth_vault_logger_factory_const_1.AUTH_VAULT_LOGGER_FACTORY,
                constants_1.RESOURCE_GUARD_OPTIONS,
            ],
        },
    ];
}
function buildFeatureProvidersAsync(asyncOptions) {
    const asyncProvider = {
        provide: tokens_1.AUTH_VAULT_OPTIONS,
        useFactory: asyncOptions.useFactory,
        inject: asyncOptions.inject ?? [],
    };
    return [
        asyncProvider,
        {
            provide: tokens_1.AUTH_STRATEGY_CONFIG,
            useFactory: (opts) => opts.strategyConfig,
            inject: [tokens_1.AUTH_VAULT_OPTIONS],
        },
        {
            provide: auth_guard_const_1.AUTH_GUARD_OPTIONS,
            useFactory: (opts) => buildGuardOptionsFromLibrary(opts).authGuard,
            inject: [tokens_1.AUTH_VAULT_OPTIONS],
        },
        {
            provide: constants_1.RESOURCE_GUARD_OPTIONS,
            useFactory: (opts) => buildGuardOptionsFromLibrary(opts).resourceGuard,
            inject: [tokens_1.AUTH_VAULT_OPTIONS],
        },
        {
            provide: constants_1.ROLE_GUARD_OPTIONS,
            useFactory: (opts) => buildGuardOptionsFromLibrary(opts).roleGuard,
            inject: [tokens_1.AUTH_VAULT_OPTIONS],
        },
        {
            provide: auth_vault_logger_factory_const_1.AUTH_VAULT_LOGGER_FACTORY,
            useFactory: (opts) => (context) => new auth_vault_logger_1.AuthVaultLogger(opts?.logLevels, context),
            inject: [tokens_1.AUTH_VAULT_OPTIONS],
        },
        {
            provide: FEATURE_STRATEGY_INSTANCE,
            useFactory: (config, httpService, createLogger) => {
                const strategyName = config?.name;
                const StrategyClass = strategyName
                    ? strategies_registry_1.AUTH_STRATEGIES_REGISTRY[strategyName]
                    : null;
                if (!StrategyClass)
                    throw new Error(`Strategy ${strategyName} not found`);
                return new StrategyClass(config, httpService, createLogger);
            },
            inject: [tokens_1.AUTH_STRATEGY_CONFIG, axios_1.HttpService, auth_vault_logger_factory_const_1.AUTH_VAULT_LOGGER_FACTORY],
        },
        {
            provide: tokens_1.AUTH_STRATEGIES_TOKEN,
            useFactory: (instance) => [instance],
            inject: [FEATURE_STRATEGY_INSTANCE],
        },
        {
            provide: auth_vault_service_1.AuthVaultService,
            useFactory: (strategies, opts, createLogger) => new auth_vault_service_1.AuthVaultService(strategies, opts, createLogger),
            inject: [
                tokens_1.AUTH_STRATEGIES_TOKEN,
                tokens_1.AUTH_VAULT_OPTIONS,
                auth_vault_logger_factory_const_1.AUTH_VAULT_LOGGER_FACTORY,
            ],
        },
        {
            provide: tokens_1.AUTH_VAULT_SERVICE,
            useExisting: auth_vault_service_1.AuthVaultService,
        },
        {
            provide: core_1.APP_GUARD,
            useFactory: (svc, reflector, createLogger, guardOpts) => new guards_1.AuthGuard(svc, reflector, createLogger, guardOpts),
            inject: [
                tokens_1.AUTH_VAULT_SERVICE,
                core_1.Reflector,
                auth_vault_logger_factory_const_1.AUTH_VAULT_LOGGER_FACTORY,
                auth_guard_const_1.AUTH_GUARD_OPTIONS,
            ],
        },
        {
            provide: core_1.APP_GUARD,
            useFactory: (reflector, svc, createLogger, guardOpts) => new guards_1.RoleGuard(reflector, svc, createLogger, guardOpts),
            inject: [
                core_1.Reflector,
                tokens_1.AUTH_VAULT_SERVICE,
                auth_vault_logger_factory_const_1.AUTH_VAULT_LOGGER_FACTORY,
                constants_1.ROLE_GUARD_OPTIONS,
            ],
        },
        {
            provide: core_1.APP_GUARD,
            useFactory: (reflector, svc, createLogger, guardOpts) => new guards_1.ResourceGuard(reflector, svc, createLogger, guardOpts),
            inject: [
                core_1.Reflector,
                tokens_1.AUTH_VAULT_SERVICE,
                auth_vault_logger_factory_const_1.AUTH_VAULT_LOGGER_FACTORY,
                constants_1.RESOURCE_GUARD_OPTIONS,
            ],
        },
    ];
}


/***/ }),
/* 83 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AUTH_STRATEGIES_REGISTRY = exports.STRATEGY_NAMES = void 0;
const keycloak_strategy_1 = __webpack_require__(84);
exports.STRATEGY_NAMES = {
    keycloak: 'keycloak',
};
exports.AUTH_STRATEGIES_REGISTRY = {
    [exports.STRATEGY_NAMES.keycloak]: keycloak_strategy_1.KeycloakStrategy,
};


/***/ }),
/* 84 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.KeycloakStrategy = void 0;
const auth_strategy_abstract_1 = __webpack_require__(85);
const keycloak_url_builder_1 = __webpack_require__(88);
const axios_1 = __webpack_require__(80);
const common_1 = __webpack_require__(14);
const auth_keycloak_mapper_1 = __webpack_require__(89);
const auth_messages_const_1 = __webpack_require__(6);
const tokens_1 = __webpack_require__(61);
const auth_vault_logger_factory_const_1 = __webpack_require__(60);
let KeycloakStrategy = class KeycloakStrategy extends auth_strategy_abstract_1.AuthStrategyBase {
    httpService;
    urlBuilder;
    constructor(config, httpService, createLogger) {
        super(config, createLogger, httpService);
        this.httpService = httpService;
        this.urlBuilder = this.createUrlBuilder();
    }
    createUrlBuilder() {
        return new keycloak_url_builder_1.KeycloakUrlBuilder(this.config);
    }
    async login(credentials) {
        const formData = new URLSearchParams({
            grant_type: 'password',
            client_id: this.config.clientId,
            client_secret: this.config.clientSecret,
            username: credentials.username,
            password: credentials.password,
        });
        try {
            const response = await this.request(this.urlBuilder.tokenEndpoint(), 'POST', formData.toString(), {
                'Content-Type': 'application/x-www-form-urlencoded',
            });
            const body = response.data;
            return {
                success: true,
                data: {
                    accessToken: body?.access_token,
                    expiresIn: body?.expires_in,
                    refreshToken: body?.refresh_token,
                    refreshTokenExpiresIn: body?.refresh_token_expires_in,
                    scope: body?.scope,
                    sessionState: body?.session_state,
                    tokenType: body?.token_type,
                },
            };
        }
        catch (error) {
            const err = error;
            const body = err.response?.data ?? {};
            return {
                success: false,
                data: {
                    error: body.error ?? 'unknown',
                    message: (0, auth_keycloak_mapper_1.getAuthErrorMessage)(body.error),
                    details: body.error_description ?? error.message,
                },
            };
        }
    }
    async logout({ refreshToken, accessToken, }) {
        try {
            const formData = new URLSearchParams({
                token: (refreshToken || accessToken),
                token_type_hint: refreshToken ? 'refresh_token' : 'access_token',
            });
            const response = await this.request(this.urlBuilder.logoutEndpoint(), 'POST', formData.toString(), {
                Authorization: `Basic ${Buffer.from(`${this.config.clientId}:${this.config.clientSecret}`).toString('base64')}`,
            });
            const data = (response?.data ?? {});
            const isObject = data != null && typeof data === 'object' && !Array.isArray(data);
            if (isObject && 'error' in data)
                throw {
                    response: { status: response.status, data: response.data },
                };
            return {
                success: true,
                data: {
                    message: auth_messages_const_1.AUTH_MESSAGES.SUCCESS_LOGOUT,
                },
            };
        }
        catch (error) {
            const err = error;
            const body = err.response?.data ?? {};
            return {
                success: false,
                data: {
                    error: body.error ?? 'unknown',
                    message: (0, auth_keycloak_mapper_1.getAuthErrorMessage)(body.error),
                    details: body.error_description ?? error.message,
                },
            };
        }
    }
    async refreshToken(credentials) {
        try {
            const formData = new URLSearchParams({
                grant_type: 'refresh_token',
                client_id: this.config.clientId,
                client_secret: this.config.clientSecret,
                refresh_token: credentials.refreshToken,
            });
            const response = await this.request(this.urlBuilder.refreshTokenEndpoint(), 'POST', formData.toString(), {
                'Content-Type': 'application/x-www-form-urlencoded',
            });
            const body = response.data;
            return {
                success: true,
                data: {
                    accessToken: body?.access_token,
                    expiresIn: body?.expires_in,
                    refreshToken: body?.refresh_token,
                    refreshTokenExpiresIn: body?.refresh_token_expires_in,
                    scope: body?.scope,
                    sessionState: body?.session_state,
                    tokenType: body?.token_type,
                },
            };
        }
        catch (error) {
            const err = error;
            const body = err.response?.data ?? {};
            return {
                success: false,
                data: {
                    error: body.error ?? 'unknown',
                    message: (0, auth_keycloak_mapper_1.getAuthErrorMessage)(body.error),
                    details: body.error_description ?? error.message,
                },
            };
        }
    }
    async getUserInfo({ token, }) {
        try {
            const response = await this.request(this.urlBuilder.userInfoEndpoint(), 'GET', undefined, { Authorization: `Bearer ${token}` });
            const body = response.data;
            return {
                success: true,
                statusCode: response.status,
                data: {
                    sub: body.sub,
                    ...body,
                },
            };
        }
        catch (error) {
            const err = error;
            const body = err.response?.data ?? {};
            return {
                success: false,
                statusCode: err.response?.status ?? 500,
                data: {
                    error: body.error ?? 'unknown',
                    message: (0, auth_keycloak_mapper_1.getAuthErrorMessage)(body.error),
                    details: body.error_description ?? error.message,
                },
            };
        }
    }
    async validate(credentials) {
        try {
            const formData = new URLSearchParams({
                token_type_hint: 'access_token',
                token: credentials.token,
            });
            const response = await this.request(this.urlBuilder.validateTokenEndpoint(), 'POST', formData.toString(), {
                'Content-Type': 'application/x-www-form-urlencoded',
                Authorization: `Basic ${Buffer.from(`${this.config.clientId}:${this.config.clientSecret}`).toString('base64')}`,
            });
            const body = response.data;
            if ('active' in body && !body.active)
                throw {
                    response: {
                        status: 401,
                        data: {
                            error: (body?.['error'] ?? 'invalid_token'),
                            error_description: (body?.['error_description'] ??
                                auth_messages_const_1.AUTH_MESSAGES.OAUTH_INVALID_TOKEN),
                        },
                    },
                };
            return {
                success: true,
                statusCode: response.status,
                data: body,
            };
        }
        catch (error) {
            const err = error;
            const body = err.response?.data ?? {};
            return {
                success: false,
                statusCode: err.response?.status ?? 500,
                data: {
                    error: body.error ?? 'unknown',
                    message: (0, auth_keycloak_mapper_1.getAuthErrorMessage)(body.error),
                    details: body.error_description ?? error.message,
                },
            };
        }
    }
    getRolesForResource(user, resource) {
        const set = new Set();
        if (user.realm_access?.roles?.length)
            user.realm_access.roles.forEach((r) => set.add(r));
        if (user.resource_access?.[resource]?.roles?.length)
            user.resource_access[resource].roles.forEach((r) => set.add(r));
        if (user.roles?.length)
            user.roles.forEach((r) => set.add(r));
        return Array.from(set);
    }
    getRoles(user) {
        const set = new Set();
        if (user.realm_access?.roles?.length)
            user.realm_access.roles.forEach((r) => set.add(r));
        if (user.resource_access && typeof user.resource_access === 'object') {
            for (const resourceRoles of Object.values(user.resource_access)) {
                if (resourceRoles?.roles?.length)
                    resourceRoles.roles.forEach((r) => set.add(r));
            }
        }
        if (user.roles?.length)
            user.roles.forEach((r) => set.add(r));
        return Array.from(set);
    }
};
exports.KeycloakStrategy = KeycloakStrategy;
exports.KeycloakStrategy = KeycloakStrategy = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, common_1.Inject)(tokens_1.AUTH_STRATEGY_CONFIG)),
    __param(2, (0, common_1.Inject)(auth_vault_logger_factory_const_1.AUTH_VAULT_LOGGER_FACTORY)),
    __metadata("design:paramtypes", [Object, typeof (_a = typeof axios_1.HttpService !== "undefined" && axios_1.HttpService) === "function" ? _a : Object, Function])
], KeycloakStrategy);


/***/ }),
/* 85 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AuthStrategyBase = void 0;
const auth_method_header_const_1 = __webpack_require__(8);
const class_validator_1 = __webpack_require__(41);
const class_transformer_1 = __webpack_require__(86);
const rxjs_1 = __webpack_require__(87);
const types_1 = __webpack_require__(68);
class AuthStrategyBase {
    name;
    logger;
    httpService;
    config;
    constructor(config, createLogger, httpService) {
        if (!config) {
            const msg = `Config is required for ${this.constructor.name}`;
            const logger = createLogger(this.constructor.name);
            logger.error(msg);
            throw new Error(msg);
        }
        this.name = config.name;
        this.logger = createLogger(this.constructor.name);
        const DtoClass = types_1.StrategyConfigDtoClassMap[this.name];
        this.config = this.validateAndTransformConfig(config, DtoClass);
        this.httpService = httpService;
        this.logger.log(`Strategy ${this.name} initialized`);
    }
    validateAndTransformConfig(config, DtoClass) {
        const dto = (0, class_transformer_1.plainToInstance)(DtoClass, config, {
            enableImplicitConversion: true,
            excludeExtraneousValues: false,
        });
        if (!dto || !(dto instanceof DtoClass)) {
            const msg = `Failed to transform config for ${this.name}`;
            this.logger.error(msg);
            throw new Error(msg);
        }
        const errors = (0, class_validator_1.validateSync)(dto, {
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
    async request(url, method, data, headers) {
        if (!this.httpService)
            throw new Error(`${this.name} does not support http requests`);
        const urlObject = new URL(url);
        const maxRetries = 2;
        const response = await (0, rxjs_1.firstValueFrom)(this.httpService
            .request({
            method,
            url: urlObject.href,
            data,
            headers,
        })
            .pipe((0, rxjs_1.retry)({
            count: maxRetries,
            delay: (error, retryCount) => {
                const status = error
                    .response?.status;
                const isRetryable = status == null || status >= 500;
                if (!isRetryable)
                    return (0, rxjs_1.throwError)(() => error);
                this.logger[!status || status >= 500 ? 'error' : 'warn'](`Tentativa ${retryCount} de ${maxRetries} para chamar ${url.toString()}: ${status ?? 'unknown status'}`);
                return (0, rxjs_1.timer)(500 * (retryCount + 1));
            },
        }), (0, rxjs_1.catchError)((error) => {
            const status = error.response
                ?.status;
            const statusWhitelist = [400, 401, 403, 409];
            if (status && (!statusWhitelist.includes(status) || status > 500)) {
                this.logger.error(`Erro ao chamar Workflow Service (${url.toString()}): ${error?.message}`);
            }
            return (0, rxjs_1.throwError)(() => error);
        })));
        return response;
    }
    buildAuthHeader(...args) {
        const [token, identifier, secret] = args;
        if (identifier && secret)
            return `${auth_method_header_const_1.AUTH_METHOD_HEADER.BASIC} ${Buffer.from(`${identifier}:${secret}`).toString('base64')}`;
        if (token)
            return `${auth_method_header_const_1.AUTH_METHOD_HEADER.BEARER} ${token}`;
        throw new Error(`Error building auth header: invalid arguments supplied: ${JSON.stringify(args)}`);
    }
}
exports.AuthStrategyBase = AuthStrategyBase;


/***/ }),
/* 86 */
/***/ ((module) => {

module.exports = require("class-transformer");

/***/ }),
/* 87 */
/***/ ((module) => {

module.exports = require("rxjs");

/***/ }),
/* 88 */
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.KeycloakUrlBuilder = void 0;
class KeycloakUrlBuilder {
    config;
    constructor(config) {
        this.config = config;
    }
    tokenEndpoint() {
        return `${this.config.url}/realms/${this.config.realm}/protocol/openid-connect/token`;
    }
    userInfoEndpoint() {
        return `${this.config.url}/realms/${this.config.realm}/protocol/openid-connect/userinfo`;
    }
    logoutEndpoint() {
        return `${this.config.url}/realms/${this.config.realm}/protocol/openid-connect/revoke`;
    }
    loginEndpoint() {
        return `${this.config.url}/realms/${this.config.realm}/protocol/openid-connect/login`;
    }
    refreshTokenEndpoint() {
        return `${this.config.url}/realms/${this.config.realm}/protocol/openid-connect/token`;
    }
    validateTokenEndpoint() {
        return `${this.config.url}/realms/${this.config.realm}/protocol/openid-connect/token/introspect`;
    }
}
exports.KeycloakUrlBuilder = KeycloakUrlBuilder;


/***/ }),
/* 89 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.getAuthErrorMessage = getAuthErrorMessage;
const auth_messages_const_1 = __webpack_require__(6);
function getAuthErrorMessage(error) {
    const mapper = {
        invalid_grant: auth_messages_const_1.AUTH_MESSAGES.OAUTH_INVALID_GRANT,
        invalid_client: auth_messages_const_1.AUTH_MESSAGES.OAUTH_INVALID_CLIENT,
        invalid_request: auth_messages_const_1.AUTH_MESSAGES.OAUTH_INVALID_REQUEST,
        unauthorized_client: auth_messages_const_1.AUTH_MESSAGES.HTTP_UNAUTHORIZED,
        unsupported_grant_type: auth_messages_const_1.AUTH_MESSAGES.OAUTH_UNSUPPORTED_GRANT_TYPE,
        invalid_scope: auth_messages_const_1.AUTH_MESSAGES.OAUTH_INVALID_SCOPE,
        invalid_token: auth_messages_const_1.AUTH_MESSAGES.OAUTH_INVALID_TOKEN,
        unknown_error: auth_messages_const_1.AUTH_MESSAGES.COMMON_DEFAULT_ERROR,
    };
    return mapper[error ?? ''] || auth_messages_const_1.AUTH_MESSAGES.COMMON_DEFAULT_ERROR;
}


/***/ }),
/* 90 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AuthVaultLogger = void 0;
const common_1 = __webpack_require__(14);
const interfaces_1 = __webpack_require__(23);
const log_levels_validator_1 = __webpack_require__(22);
class AuthVaultLogger {
    nestLogger;
    logLevels;
    constructor(logLevels, context) {
        this.nestLogger = new common_1.Logger(context);
        this.logLevels = (0, log_levels_validator_1.validateAndNormalizeLogLevels)(logLevels);
    }
    shouldLog(level) {
        const arr = this.logLevels;
        if (arr == null)
            return true;
        if (arr.length === 0 || arr.includes(interfaces_1.AuthLogLevel.SILENT))
            return false;
        return arr.includes(level);
    }
    verbose(message, ...optionalParams) {
        if (this.shouldLog(interfaces_1.AuthLogLevel.VERBOSE))
            this.nestLogger.verbose?.(message, ...optionalParams);
    }
    log(message, ...optionalParams) {
        if (this.shouldLog(interfaces_1.AuthLogLevel.LOG))
            this.nestLogger.log?.(message, ...optionalParams);
    }
    debug(message, ...optionalParams) {
        if (this.shouldLog(interfaces_1.AuthLogLevel.DEBUG))
            this.nestLogger.debug?.(message, ...optionalParams);
    }
    warn(message, ...optionalParams) {
        if (this.shouldLog(interfaces_1.AuthLogLevel.WARN))
            this.nestLogger.warn?.(message, ...optionalParams);
    }
    error(message, ...optionalParams) {
        if (this.shouldLog(interfaces_1.AuthLogLevel.ERROR))
            this.nestLogger.error?.(message, ...optionalParams);
    }
}
exports.AuthVaultLogger = AuthVaultLogger;


/***/ })
/******/ 	]);
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		__webpack_modules__[moduleId].call(module.exports, module, module.exports, __webpack_require__);
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
/******/ 	
/******/ 	// startup
/******/ 	// Load entry module and return exports
/******/ 	// This entry module is referenced by other modules so it can't be inlined
/******/ 	var __webpack_exports__ = __webpack_require__(0);
/******/ 	
/******/ })()
;