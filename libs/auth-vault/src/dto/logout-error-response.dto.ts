import { ApiProperty } from '@nestjs/swagger';
import { IsOptional, IsString } from 'class-validator';

export class LogoutErrorResponseDto {
  @ApiProperty({
    description: 'Mensagem de erro',
    example: 'Erro ao logout',
  })
  @IsString()
  message: string;

  @ApiProperty({
    description: 'Erro',
    example: 'Erro ao logout',
  })
  @IsString()
  error: string;

  @ApiProperty({
    description:
      'Detalhe adicional do erro (opcional; em produção pode ser omitido ou sanitizado).',
    example: 'Erro ao logout',
  })
  @IsString()
  @IsOptional()
  details?: string;
}
