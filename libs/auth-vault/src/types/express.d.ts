/* eslint-disable @typescript-eslint/no-empty-object-type */
import type { ValidateResponseDto } from '../dto';

export interface AuthRequestFields {
  /**
   * Dados do usuário autenticado
   *
   * @example
   * {
   *   sub: '1234567890',
   *   name: 'John Doe',
   *   email: 'john.doe@example.com',
   *   email_verified: true,
   *   phone_number: '1234567890',
   *   phone_number_verified: true,
   *   role: 'admin',
   * }
   */
  readonly user?: ValidateResponseDto;
  /**
   * Payload do token JWT
   *
   * @example
   * {
   *   sub: '1234567890',
   *   name: 'John Doe',
   *   email: 'john.doe@example.com',
   *   email_verified: true,
   *   phone_number: '1234567890',
   *   phone_number_verified: true,
   *   role: 'admin',
   * }
   */
  readonly jwtPayload?: Record<string, unknown>;
  /**
   * Token JWT
   *
   * @example
   * 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
   */
  readonly accessToken?: string;
  /**
   * Escopos resolvidos para o recurso
   *
   * @example
   * ['scope1', 'scope2']
   */
  readonly scopes?: string[];
}

declare global {
  namespace Express {
    interface Request extends AuthRequestFields {}
  }
  interface Request extends AuthRequestFields {}
}
