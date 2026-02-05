/** Function for @ConditionalScopes: (request, accessToken) => additional scope names. */
export type ConditionalScopeFn = (request: Request, token: string) => string[];
