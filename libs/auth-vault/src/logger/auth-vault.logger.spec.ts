import { Logger } from '@nestjs/common';
import { AuthLogLevel, type AuthLogLevelValue } from '../interfaces';
import { AuthVaultLogLevelsValidationError } from '../utils/log-levels.validator';
import { AuthVaultLogger } from './auth-vault.logger';

describe('AuthVaultLogger', () => {
  const context = 'TestContext';

  let verboseSpy: jest.SpyInstance;
  let logSpy: jest.SpyInstance;
  let warnSpy: jest.SpyInstance;
  let errorSpy: jest.SpyInstance;
  let debugSpy: jest.SpyInstance;

  beforeEach(() => {
    verboseSpy = jest.spyOn(Logger.prototype, 'verbose').mockImplementation();
    logSpy = jest.spyOn(Logger.prototype, 'log').mockImplementation();
    warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation();
    errorSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation();
    debugSpy = jest.spyOn(Logger.prototype, 'debug').mockImplementation();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('deve ser instanciável com context', () => {
    const logger = new AuthVaultLogger(undefined, context);
    expect(logger).toBeDefined();
  });

  describe('quando logLevels é undefined', () => {
    it('todas as funções de log chamam o Logger do Nest', () => {
      const authLogger = new AuthVaultLogger(undefined, context);

      authLogger.verbose('v');
      authLogger.log('l');
      authLogger.warn('w');
      authLogger.error('e');
      authLogger.debug('d');

      expect(verboseSpy).toHaveBeenCalledWith('v');
      expect(logSpy).toHaveBeenCalledWith('l');
      expect(warnSpy).toHaveBeenCalledWith('w');
      expect(errorSpy).toHaveBeenCalledWith('e');
      expect(debugSpy).toHaveBeenCalledWith('d');
    });
  });

  describe('quando logLevels é array vazio (normalizado para undefined)', () => {
    it('todas as funções de log chamam o Logger do Nest', () => {
      const authLogger = new AuthVaultLogger([], context);

      authLogger.verbose('v');
      authLogger.log('l');

      expect(verboseSpy).toHaveBeenCalled();
      expect(logSpy).toHaveBeenCalled();
    });
  });

  describe('quando logLevels inclui SILENT', () => {
    it('nenhuma função de log chama o Logger do Nest', () => {
      const authLogger = new AuthVaultLogger([AuthLogLevel.SILENT], context);

      authLogger.verbose('v');
      authLogger.log('l');
      authLogger.warn('w');
      authLogger.error('e');
      authLogger.debug('d');

      expect(verboseSpy).not.toHaveBeenCalled();
      expect(logSpy).not.toHaveBeenCalled();
      expect(warnSpy).not.toHaveBeenCalled();
      expect(errorSpy).not.toHaveBeenCalled();
      expect(debugSpy).not.toHaveBeenCalled();
    });
  });

  describe('quando logLevels contém apenas error', () => {
    it('apenas error() chama o Logger do Nest', () => {
      const authLogger = new AuthVaultLogger([AuthLogLevel.ERROR], context);

      authLogger.verbose('v');
      authLogger.log('l');
      authLogger.warn('w');
      authLogger.error('e');
      authLogger.debug('d');

      expect(verboseSpy).not.toHaveBeenCalled();
      expect(logSpy).not.toHaveBeenCalled();
      expect(warnSpy).not.toHaveBeenCalled();
      expect(errorSpy).toHaveBeenCalledWith('e');
      expect(debugSpy).not.toHaveBeenCalled();
    });
  });

  describe('quando logLevels contém error e warn', () => {
    it('apenas error() e warn() chamam o Logger do Nest', () => {
      const authLogger = new AuthVaultLogger(
        [AuthLogLevel.ERROR, AuthLogLevel.WARN],
        context,
      );

      authLogger.verbose('v');
      authLogger.log('l');
      authLogger.warn('w');
      authLogger.error('e');

      expect(verboseSpy).not.toHaveBeenCalled();
      expect(logSpy).not.toHaveBeenCalled();
      expect(warnSpy).toHaveBeenCalledWith('w');
      expect(errorSpy).toHaveBeenCalledWith('e');
    });
  });

  describe('quando logLevels é valor único válido', () => {
    it('apenas o nível informado é logado', () => {
      const authLogger = new AuthVaultLogger(AuthLogLevel.LOG, context);

      authLogger.log('msg');
      authLogger.verbose('v');

      expect(logSpy).toHaveBeenCalledWith('msg');
      expect(verboseSpy).not.toHaveBeenCalled();
    });
  });

  it('lança quando logLevels contém valor inválido', () => {
    expect(
      () =>
        new AuthVaultLogger(
          ['invalid'] as unknown as
            | AuthLogLevelValue
            | AuthLogLevelValue[]
            | undefined,
          context,
        ),
    ).toThrow(AuthVaultLogLevelsValidationError);
  });
});
