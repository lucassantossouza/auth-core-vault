import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsArray, IsOptional, IsString } from 'class-validator';

/** Estrutura genérica de roles por recurso (ex.: Keycloak resource_access). */
export class ResourceAccessDto {
  @ApiPropertyOptional({
    description: 'Roles do recurso',
    example: ['manage-account', 'view-profile'],
  })
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  roles?: string[];
}
