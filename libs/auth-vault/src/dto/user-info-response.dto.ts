import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsBoolean, IsString } from 'class-validator';

export class UserInfoResponseDto {
  @ApiProperty({
    description: 'Sub do usuário',
    example: 'user_1234567890',
  })
  @IsString()
  sub: string;

  @ApiPropertyOptional({
    description: 'Email verificado do usuário',
    example: false,
  })
  @IsBoolean()
  email_verified?: boolean;

  @ApiPropertyOptional({
    description: 'Nome do usuário',
    example: 'John Doe',
  })
  @IsString()
  name?: string;

  @ApiPropertyOptional({
    description: 'Nome social do usuário',
    example: 'John Doe',
  })
  @IsString()
  preferred_username?: string;

  @ApiPropertyOptional({
    description: 'Primeiro nome do usuário',
    example: 'John',
  })
  @IsString()
  given_name?: string;

  @ApiPropertyOptional({
    description: 'Sobrenome do usuário',
    example: 'Doe',
  })
  @IsString()
  family_name?: string;

  @ApiPropertyOptional({
    description: 'Localização do usuário',
    example: 'pt-BR',
  })
  @IsString()
  locale?: string;

  @ApiPropertyOptional({
    description: 'Email do usuário',
    example: 'user@example.com',
  })
  @IsString()
  email?: string;

  [key: string]: unknown;
}
