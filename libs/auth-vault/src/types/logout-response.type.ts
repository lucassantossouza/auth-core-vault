import { LogoutErrorResponseDto } from '../dto/logout-error-response.dto';
import { LogoutResponseDto } from '../dto/logout-response.dto';

export type LogoutResponse = {
  readonly success: true;
  readonly data: LogoutResponseDto;
};

export type LogoutErrorResponse = {
  readonly success: false;
  readonly data: LogoutErrorResponseDto;
};

export type LogoutApiResponse = (LogoutResponse | LogoutErrorResponse) & {};
