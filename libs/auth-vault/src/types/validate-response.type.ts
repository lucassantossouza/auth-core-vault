import { ValidateErrorResponseDto } from '../dto/validate-error-response.dto';
import { ValidateResponseDto } from '../dto/validate-response.dto';

export type ValidateResponse = {
  readonly success: true;
  readonly data: ValidateResponseDto;
};

export type ValidateErrorResponse = {
  readonly success: false;
  readonly data: ValidateErrorResponseDto;
};

export type ValidateApiResponse = (
  | ValidateResponse
  | ValidateErrorResponse
) & {};
