import { AuthLogLevel, AuthLogLevelValue } from '../interfaces';

const VALID_VALUES = new Set<AuthLogLevelValue>(
  Object.values(AuthLogLevel) as AuthLogLevelValue[],
);

export const AUTH_VAULT_LOG_LEVELS_ERROR = 'AuthVaultLogLevelsValidationError';

export class AuthVaultLogLevelsValidationError extends Error {
  constructor(
    message: string,
    public readonly invalidValues: unknown[],
    public readonly allowedValues: AuthLogLevelValue[],
  ) {
    super(message);
    this.name = AUTH_VAULT_LOG_LEVELS_ERROR;
    Object.setPrototypeOf(this, AuthVaultLogLevelsValidationError.prototype);
  }
}

/**
 * Valida e normaliza logLevels: array único, apenas valores válidos.
 * @throws {AuthVaultLogLevelsValidationError} se algum valor não for permitido
 */
export function validateAndNormalizeLogLevels(
  value: AuthLogLevelValue | AuthLogLevelValue[] | undefined,
): AuthLogLevelValue[] | undefined {
  if (value == null) return undefined;

  const arr = Array.isArray(value) ? value : [value];
  const unique = [...new Set(arr)] as unknown[];

  const invalid: unknown[] = [];
  const valid: AuthLogLevelValue[] = [];

  for (const item of unique) {
    if (VALID_VALUES.has(item as AuthLogLevelValue)) {
      valid.push(item as AuthLogLevelValue);
    } else {
      invalid.push(item);
    }
  }

  if (invalid.length > 0) {
    throw new AuthVaultLogLevelsValidationError(
      `Invalid logLevels: [${invalid.join(', ')}]. Allowed: [${(Object.values(AuthLogLevel) as AuthLogLevelValue[]).join(', ')}].`,
      invalid,
      Object.values(AuthLogLevel) as AuthLogLevelValue[],
    );
  }

  return valid.length === 0 ? undefined : valid;
}
