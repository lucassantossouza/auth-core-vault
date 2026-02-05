import { RefreshTokenErrorResponseDto } from '../dto/refresh-token-error-response.dto';
import { RefreshTokenResponseDto } from '../dto/refresh-token-response.dto';

export type RefreshTokenSuccess = {
  readonly success: true;
  readonly data: RefreshTokenResponseDto;
};

export type RefreshTokenErrorResponse = {
  readonly success: false;
  readonly data: RefreshTokenErrorResponseDto;
};

export type RefreshTokenApiResponse = (
  | RefreshTokenSuccess
  | RefreshTokenErrorResponse
) & {};
