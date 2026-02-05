import { ApiProperty } from '@nestjs/swagger';
import { IsOptional, IsString } from 'class-validator';

export class RefreshTokenErrorResponseDto {
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
    example: 'Invalid grant',
  })
  @IsString()
  message: string;

  @ApiProperty({
    description:
      'Detalhe adicional do erro (opcional; em produção pode ser omitido ou sanitizado).',
    example: 'Invalid grant',
  })
  @IsString()
  @IsOptional()
  details?: string;
}
