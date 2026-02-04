import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsNumber, IsOptional, IsString } from 'class-validator';

export class LoginResponseDto {
  @ApiProperty({
    description:
      'Token de acesso JWT utilizado no header Authorization (Bearer).',
    example: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...',
  })
  @IsString()
  accessToken: string;

  @ApiPropertyOptional({
    description: 'Validade do access token em segundos. Ex.: 300 = 5 minutos.',
    example: 300,
  })
  @IsOptional()
  @IsNumber()
  expiresIn?: number;

  @ApiPropertyOptional({
    description:
      'Validade do refresh token em segundos. Só presente quando o provedor devolve refresh token.',
    example: 1800,
  })
  @IsOptional()
  @IsNumber()
  refreshTokenExpiresIn?: number;

  @ApiPropertyOptional({
    description:
      'Token de atualização para obter novo access token sem novo login.',
    example: 'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9...',
  })
  @IsOptional()
  @IsString()
  refreshToken?: string;

  @ApiPropertyOptional({
    description: 'Tipo do token. Geralmente "Bearer" (padrão OAuth2).',
    example: 'Bearer',
  })
  @IsOptional()
  @IsString()
  tokenType?: string;

  @ApiPropertyOptional({
    description:
      'Identificador da sessão no provedor (ex.: Keycloak session_state).',
    example: 'b909feea-ed27-4390-8280-660730964dcc',
  })
  @IsOptional()
  @IsString()
  sessionState?: string;

  @ApiPropertyOptional({
    description: 'Escopos concedidos ao token (ex.: openid, profile, email).',
    example: 'email profile',
  })
  @IsOptional()
  @IsString()
  scope?: string;
}
