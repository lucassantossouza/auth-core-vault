import { Logger } from '@nestjs/common';
import { IAuthVaultLogger } from '../interfaces/auth-vault.logger.interface';
import { AuthLogLevel, AuthLogLevelValue } from '../interfaces';
import { validateAndNormalizeLogLevels } from '../utils/log-levels.validator';

export class AuthVaultLogger implements IAuthVaultLogger {
  private readonly nestLogger: Logger;
  /** Após validação, sempre array único ou undefined. */
  private readonly logLevels: AuthLogLevelValue[] | undefined;

  constructor(
    logLevels: AuthLogLevelValue[] | AuthLogLevelValue | undefined,
    context: string,
  ) {
    this.nestLogger = new Logger(context);
    this.logLevels = validateAndNormalizeLogLevels(logLevels);
  }

  private shouldLog(level: AuthLogLevelValue): boolean {
    const arr = this.logLevels;
    if (arr == null) return true;
    if (arr.length === 0 || arr.includes(AuthLogLevel.SILENT)) return false;
    return arr.includes(level);
  }

  verbose(message?: unknown, ...optionalParams: unknown[]): void {
    if (this.shouldLog(AuthLogLevel.VERBOSE))
      this.nestLogger.verbose?.(message, ...optionalParams);
  }

  log(message?: unknown, ...optionalParams: unknown[]): void {
    if (this.shouldLog(AuthLogLevel.LOG))
      this.nestLogger.log?.(message, ...optionalParams);
  }

  debug(message?: unknown, ...optionalParams: unknown[]): void {
    if (this.shouldLog(AuthLogLevel.DEBUG))
      this.nestLogger.debug?.(message, ...optionalParams);
  }

  warn(message?: unknown, ...optionalParams: unknown[]): void {
    if (this.shouldLog(AuthLogLevel.WARN))
      this.nestLogger.warn?.(message, ...optionalParams);
  }

  error(message?: unknown, ...optionalParams: unknown[]): void {
    if (this.shouldLog(AuthLogLevel.ERROR))
      this.nestLogger.error?.(message, ...optionalParams);
  }
}
