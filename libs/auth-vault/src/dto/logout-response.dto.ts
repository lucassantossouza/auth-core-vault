import { ApiProperty } from '@nestjs/swagger';
import { IsString } from 'class-validator';

export class LogoutResponseDto {
  @ApiProperty({
    description: 'Mensagem de logout',
    example: 'Logout realizado com sucesso',
  })
  @IsString()
  message: string;
}
