import { IsNotEmpty, IsString, ValidateIf } from 'class-validator';
import { ApiPropertyOptional } from '@nestjs/swagger';

const LOGOUT_TOKEN_MESSAGE =
  'É necessário fornecer um refreshToken ou accessToken para realizar o logout.';

export class LogoutCredentialsDto {
  @ApiPropertyOptional({ description: 'Refresh token do usuário' })
  @ValidateIf((o: LogoutCredentialsDto) => !o.accessToken)
  @IsNotEmpty({ message: LOGOUT_TOKEN_MESSAGE })
  @IsString()
  refreshToken?: string;

  @ApiPropertyOptional({ description: 'Access token do usuário' })
  @ValidateIf((o: LogoutCredentialsDto) => !o.refreshToken)
  @IsNotEmpty({ message: LOGOUT_TOKEN_MESSAGE })
  @IsString()
  accessToken?: string;
}
