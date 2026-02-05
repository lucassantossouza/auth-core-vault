/** Modo de validação do token: via servidor (ONLINE) ou só assinatura JWT (OFFLINE). */
export enum TokenValidation {
  /** Validar token no servidor (introspection/userinfo). Default. */
  ONLINE = 'online',
  /** Validar apenas assinatura JWT (realm public key). */
  OFFLINE = 'offline',
}
