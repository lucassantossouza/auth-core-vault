import { AuthLogLevel, AuthLogLevelValue } from '../interfaces';
import {
  validateAndNormalizeLogLevels,
  AuthVaultLogLevelsValidationError,
  AUTH_VAULT_LOG_LEVELS_ERROR,
} from './log-levels.validator';

describe('log-levels.validator', () => {
  describe('validateAndNormalizeLogLevels', () => {
    it('retorna undefined quando value é undefined', () => {
      expect(validateAndNormalizeLogLevels(undefined)).toBeUndefined();
    });

    it('retorna undefined quando value é null', () => {
      expect(
        validateAndNormalizeLogLevels(
          null as unknown as
            | AuthLogLevelValue
            | AuthLogLevelValue[]
            | undefined,
        ),
      ).toBeUndefined();
    });

    it('retorna array com um elemento quando recebe valor único válido', () => {
      expect(validateAndNormalizeLogLevels('error')).toEqual(['error']);
      expect(validateAndNormalizeLogLevels(AuthLogLevel.WARN)).toEqual([
        'warn',
      ]);
    });

    it('retorna array único quando recebe array de valores válidos', () => {
      expect(validateAndNormalizeLogLevels(['error', 'warn', 'log'])).toEqual([
        'error',
        'warn',
        'log',
      ]);
    });

    it('remove duplicatas do array', () => {
      expect(
        validateAndNormalizeLogLevels(['error', 'warn', 'log', 'log', 'error']),
      ).toEqual(['error', 'warn', 'log']);
    });

    it('retorna undefined quando array válido fica vazio após normalização', () => {
      expect(validateAndNormalizeLogLevels([])).toBeUndefined();
    });

    it('lança AuthVaultLogLevelsValidationError quando há valor inválido', () => {
      expect(() =>
        validateAndNormalizeLogLevels(
          'invalid' as unknown as
            | AuthLogLevelValue
            | AuthLogLevelValue[]
            | undefined,
        ),
      ).toThrow(AuthVaultLogLevelsValidationError);
    });

    it('erro contém nome correto e propriedades invalidValues e allowedValues', () => {
      try {
        validateAndNormalizeLogLevels(
          'invalid' as unknown as
            | AuthLogLevelValue
            | AuthLogLevelValue[]
            | undefined,
        );
      } catch (e) {
        expect(e).toBeInstanceOf(AuthVaultLogLevelsValidationError);
        expect((e as AuthVaultLogLevelsValidationError).name).toBe(
          AUTH_VAULT_LOG_LEVELS_ERROR,
        );
        expect((e as AuthVaultLogLevelsValidationError).invalidValues).toEqual([
          'invalid',
        ]);
        expect((e as AuthVaultLogLevelsValidationError).allowedValues).toEqual(
          expect.arrayContaining([
            'silent',
            'error',
            'warn',
            'verbose',
            'debug',
            'log',
          ]),
        );
      }
    });

    it('mensagem do erro inclui valores inválidos e lista de permitidos', () => {
      try {
        validateAndNormalizeLogLevels(
          'typo' as unknown as
            | AuthLogLevelValue
            | AuthLogLevelValue[]
            | undefined,
        );
      } catch (e) {
        const msg = (e as Error).message;
        expect(msg).toContain('typo');
        expect(msg).toContain('Allowed:');
      }
    });

    it('lança quando array tem valor válido e inválido', () => {
      const invalidInput = ['error', 'invalido'] as unknown as
        | AuthLogLevelValue
        | AuthLogLevelValue[]
        | undefined;
      expect(() => validateAndNormalizeLogLevels(invalidInput)).toThrow(
        AuthVaultLogLevelsValidationError,
      );
      try {
        validateAndNormalizeLogLevels(invalidInput);
      } catch (e) {
        expect((e as AuthVaultLogLevelsValidationError).invalidValues).toEqual([
          'invalido',
        ]);
      }
    });
  });

  describe('AuthVaultLogLevelsValidationError', () => {
    it('herda de Error e expõe invalidValues e allowedValues', () => {
      const allowed = Object.values(AuthLogLevel) as string[];
      const err = new AuthVaultLogLevelsValidationError(
        'test message',
        ['bad' as AuthLogLevelValue],
        allowed as AuthLogLevelValue[],
      );
      expect(err).toBeInstanceOf(Error);
      expect(err.message).toBe('test message');
      expect(err.invalidValues).toEqual(['bad']);
      expect(err.allowedValues).toEqual(allowed);
    });
  });
});
