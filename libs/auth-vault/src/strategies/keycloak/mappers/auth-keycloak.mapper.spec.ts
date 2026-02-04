import { getAuthErrorMessage } from './auth-keycloak.mapper';
import { AUTH_MESSAGES } from '../../../constants/auth-messages.const';

describe('auth-keycloak.mapper', () => {
  it('retorna mensagem para invalid_grant', () => {
    expect(getAuthErrorMessage('invalid_grant')).toBe(
      AUTH_MESSAGES.OAUTH_INVALID_GRANT,
    );
  });

  it('retorna mensagem para invalid_client', () => {
    expect(getAuthErrorMessage('invalid_client')).toBe(
      AUTH_MESSAGES.OAUTH_INVALID_CLIENT,
    );
  });

  it('retorna mensagem para invalid_token', () => {
    expect(getAuthErrorMessage('invalid_token')).toBe(
      AUTH_MESSAGES.OAUTH_INVALID_TOKEN,
    );
  });

  it('retorna mensagem para unknown_error', () => {
    expect(getAuthErrorMessage('unknown_error')).toBe(
      AUTH_MESSAGES.COMMON_DEFAULT_ERROR,
    );
  });

  it('retorna COMMON_DEFAULT_ERROR para erro desconhecido', () => {
    expect(getAuthErrorMessage('unknown_code')).toBe(
      AUTH_MESSAGES.COMMON_DEFAULT_ERROR,
    );
  });

  it('retorna COMMON_DEFAULT_ERROR para undefined', () => {
    expect(getAuthErrorMessage(undefined)).toBe(
      AUTH_MESSAGES.COMMON_DEFAULT_ERROR,
    );
  });
});
