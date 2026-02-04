import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsArray,
  IsBoolean,
  IsNumber,
  IsObject,
  IsOptional,
  IsString,
  IsUrl,
} from 'class-validator';
import { RealmAccessDto, ResourceAccessDto } from '../dto';

/**
 * Payload returned by token validation (introspect/JWT claims). Standard OIDC/JWT fields plus identity and roles; strategies map as needed.
 * Attached to request.user by AuthGuard after successful validate().
 */
export class ValidateResponseDto {
  @ApiProperty({
    description: 'Subject - user identifier (OIDC)',
    example: 'c29e18b3-8ad4-4bcd-b5ab-b075e0d6f6ef',
  })
  @IsString()
  sub: string;

  @ApiProperty({
    description: 'Token expiration (seconds since Unix epoch)',
    example: 1769963193,
  })
  @IsNumber()
  exp: number;

  @ApiProperty({
    description: 'Token issued at (seconds since Unix epoch)',
    example: 1769962893,
  })
  @IsNumber()
  iat: number;

  @ApiProperty({
    description: 'JWT ID',
    example: 'b2a88ebe-a4bf-4620-842d-3c031834757d',
  })
  @IsString()
  jti: string;

  @ApiPropertyOptional({
    description: 'Issuer',
    example: 'https://auth.tiwiki.com.br/realms/orchestron-core',
  })
  @IsOptional()
  @IsUrl()
  iss?: string;

  @ApiPropertyOptional({
    description: 'Audience',
    example: 'account',
  })
  @IsOptional()
  @IsString()
  aud?: string;

  @ApiPropertyOptional({
    description: 'Tipo do token',
    example: 'Bearer',
  })
  @IsOptional()
  @IsString()
  typ?: string;

  @ApiPropertyOptional({
    description: 'Scopes (OAuth2/OIDC)',
    example: 'email profile openid',
  })
  @IsOptional()
  @IsString()
  scope?: string;

  @ApiPropertyOptional({
    description: 'User email',
    example: 'test@test.com',
  })
  @IsOptional()
  @IsString()
  email?: string;

  @ApiPropertyOptional({
    description: 'Email verified',
    example: false,
  })
  @IsOptional()
  @IsBoolean()
  email_verified?: boolean;

  @ApiPropertyOptional({
    description: 'Full name',
    example: 'Teste Silva',
  })
  @IsOptional()
  @IsString()
  name?: string;

  @ApiPropertyOptional({
    description: 'Preferred username',
    example: 'test',
  })
  @IsOptional()
  @IsString()
  preferred_username?: string;

  @ApiPropertyOptional({
    description: 'Given name',
    example: 'Teste',
  })
  @IsOptional()
  @IsString()
  given_name?: string;

  @ApiPropertyOptional({
    description: 'Family name',
    example: 'Silva',
  })
  @IsOptional()
  @IsString()
  family_name?: string;

  @ApiPropertyOptional({
    description: 'User locale',
    example: 'pt-BR',
  })
  @IsOptional()
  @IsString()
  locale?: string;

  @ApiPropertyOptional({
    description: 'Roles list (each strategy maps as needed)',
    example: [
      'offline_access',
      'default-roles-orchestron-core',
      'manage-account',
    ],
  })
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  roles?: string[];

  @ApiPropertyOptional({
    description: 'Realm roles (e.g. Keycloak realm_access)',
    type: RealmAccessDto,
  })
  @IsOptional()
  @IsObject()
  realm_access?: RealmAccessDto;

  @ApiPropertyOptional({
    description: 'Roles per resource (e.g. Keycloak resource_access)',
    example: { account: { roles: ['manage-account', 'view-profile'] } },
  })
  @IsOptional()
  @IsObject()
  resource_access?: Record<string, ResourceAccessDto>;

  @ApiPropertyOptional({
    description: 'Additional strategy-specific claims (azp, sid, acr, etc.)',
    example: {
      azp: 'orchestron-core',
      sid: '9641f0fa-ab1e-40f8-b093-f4c32ae163c2',
    },
  })
  @IsOptional()
  @IsObject()
  additionalClaims?: Record<string, unknown>;
}
