/** Modo de política do ResourceGuard: permissivo ou restritivo. */
export enum PolicyEnforcementMode {
  /** Sem @Resource ou @Scopes na rota → permite acesso. */
  PERMISSIVE = 'permissive',
  /** Sem @Resource ou @Scopes na rota → nega acesso. */
  ENFORCING = 'enforcing',
}

/** Modo de matching: usuário precisa ter pelo menos uma role (ANY) ou todas (ALL). */
export enum RoleMatch {
  /** Pelo menos uma das roles exigidas. */
  ANY = 'any',
  /** Todas as roles exigidas. */
  ALL = 'all',
}

/** Modo de merge: juntar roles da classe + método (ALL) ou só do método sobrescreve (OVERRIDE). */
export enum RoleMerge {
  /** Junta roles da classe e do método. */
  ALL = 'all',
  /** Método sobrescreve; se método tem roles, usa só as do método. */
  OVERRIDE = 'override',
}
