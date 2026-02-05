export const AUTH_METHOD_HEADER = {
  BASIC: 'Basic',
  BEARER: 'Bearer',
} as const;

export type AuthMethodHeader = keyof typeof AUTH_METHOD_HEADER;
export type AuthMethodHeaderValue =
  (typeof AUTH_METHOD_HEADER)[AuthMethodHeader];
