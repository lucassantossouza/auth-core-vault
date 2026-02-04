import {
  AUTH_MESSAGES,
  type AuthErrorMessage,
} from './../constants/auth-messages.const';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsOptional, IsString } from 'class-validator';

export class LoginErrorResponseDto {
  @ApiProperty({
    description:
      'Código estável do erro para tratamento no front (ex.: invalid_grant, invalid_credentials).',
    example: 'invalid_grant',
  })
  @IsString()
  error: string;

  @ApiProperty({
    description:
      'Mensagem do provedor de autenticação (ex.: error_description). Repassada para exibição ou log no front.',
    example: AUTH_MESSAGES.OAUTH_INVALID_CREDENTIALS,
  })
  @IsString()
  message: AuthErrorMessage;

  @ApiPropertyOptional({
    description:
      'Detalhe adicional do erro (opcional; em produção pode ser omitido ou sanitizado).',
    example: 'Account is disabled',
  })
  @IsOptional()
  @IsString()
  details?: string;
}
