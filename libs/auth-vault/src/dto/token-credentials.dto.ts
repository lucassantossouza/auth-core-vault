import { ApiProperty } from '@nestjs/swagger';
import { IsString } from 'class-validator';

/** Credentials for validate/getUserInfo: single access token. */
export class TokenCredentialsDto {
  @ApiProperty({
    description: 'Access token (Bearer)',
    example: 'access_token',
    required: true,
  })
  @IsString()
  token: string;
}
