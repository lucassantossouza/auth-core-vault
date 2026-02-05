import { AxiosRequestHeaders } from 'axios';
import { ValidateResponseDto } from '../dto/validate-response.dto';
import { CookieOptions } from 'express';

/** Request shape after AuthGuard: user, accessToken, optional headers/cookies. */
export interface IAuthRequest {
  user?: ValidateResponseDto;
  accessToken?: string;
  headers?: AxiosRequestHeaders;
  cookies?: CookieOptions;
}
