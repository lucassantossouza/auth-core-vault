import { UserInfoErrorResponseDto } from '../dto/user-info-error-response.dto';
import { UserInfoResponseDto } from '../dto/user-info-response.dto';

export type UserInfoResponse = {
  readonly success: true;
  readonly data: UserInfoResponseDto;
};

export type UserInfoErrorResponse = {
  readonly success: false;
  readonly data: UserInfoErrorResponseDto;
};

export type UserInfoApiResponse = (UserInfoResponse | UserInfoErrorResponse) & {
  readonly statusCode: number;
};
