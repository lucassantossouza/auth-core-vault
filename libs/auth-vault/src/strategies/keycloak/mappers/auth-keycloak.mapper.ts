import {
  AUTH_MESSAGES,
  AuthErrorMessage,
} from '../../../constants/auth-messages.const';

export function getAuthErrorMessage(
  error: string | undefined,
): AuthErrorMessage {
  const mapper: Record<string, AuthErrorMessage> = {
    invalid_grant: AUTH_MESSAGES.OAUTH_INVALID_GRANT,
    invalid_client: AUTH_MESSAGES.OAUTH_INVALID_CLIENT,
    invalid_request: AUTH_MESSAGES.OAUTH_INVALID_REQUEST,
    unauthorized_client: AUTH_MESSAGES.HTTP_UNAUTHORIZED,
    unsupported_grant_type: AUTH_MESSAGES.OAUTH_UNSUPPORTED_GRANT_TYPE,
    invalid_scope: AUTH_MESSAGES.OAUTH_INVALID_SCOPE,
    invalid_token: AUTH_MESSAGES.OAUTH_INVALID_TOKEN,
    unknown_error: AUTH_MESSAGES.COMMON_DEFAULT_ERROR,
  };
  return mapper[error ?? ''] || AUTH_MESSAGES.COMMON_DEFAULT_ERROR;
}
