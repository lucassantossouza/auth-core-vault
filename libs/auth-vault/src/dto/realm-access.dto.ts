import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsArray, IsOptional, IsString } from 'class-validator';

/** Estrutura genérica de roles por realm (ex.: Keycloak realm_access). */
export class RealmAccessDto {
  @ApiPropertyOptional({
    description: 'Roles do realm',
    example: ['offline_access', 'default-roles-orchestron-core'],
  })
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  roles?: string[];
}
