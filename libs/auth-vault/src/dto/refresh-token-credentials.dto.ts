import { ApiProperty } from '@nestjs/swagger';
import { IsString } from 'class-validator';

export class RefreshTokenCredentialsDto {
  @ApiProperty({
    description: 'Refresh Token',
    example: 'refresh_token',
  })
  @IsString()
  refreshToken: string;
}
