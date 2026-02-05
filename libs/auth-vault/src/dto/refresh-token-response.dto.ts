import { ApiProperty } from '@nestjs/swagger';
import { IsNumber, IsString } from 'class-validator';

export class RefreshTokenResponseDto {
  @ApiProperty({
    description: 'Token de acesso',
    example: '1234567890',
  })
  @IsString()
  accessToken: string;

  @ApiProperty({
    description: 'Tempo de expiração do token de acesso',
    example: 3600,
  })
  @IsNumber()
  expiresIn: number;

  @ApiProperty({
    description: 'Tempo de expiração do token de atualização',
    example: 3600,
  })
  @IsNumber()
  refreshTokenExpiresIn: number;

  @ApiProperty({
    description: 'Token de atualização',
    example: '1234567890',
  })
  @IsString()
  refreshToken: string;

  @ApiProperty({
    description: 'Tipo de token',
    example: 'Bearer',
  })
  @IsString()
  tokenType: string;

  @ApiProperty({
    description: 'Estado da sessão',
    example: '1234567890',
  })
  @IsString()
  sessionState: string;

  @ApiProperty({
    description: 'Escopo do token',
    example: 'openid profile email',
  })
  @IsString()
  scope: string;
}
