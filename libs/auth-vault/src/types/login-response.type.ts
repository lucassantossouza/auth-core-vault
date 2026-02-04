import { LoginResponseDto } from '../dto/login-response.dto';
import { LoginErrorResponseDto } from '../dto/login-error-response.dto';

export type LoginSuccess = {
  readonly success: true;
  readonly data: LoginResponseDto;
};

export type LoginErrorResponse = {
  readonly success: false;
  readonly data: LoginErrorResponseDto;
};

export type LoginApiResponse = LoginSuccess | LoginErrorResponse;
