import {
  IsBoolean,
  IsNotEmpty,
  IsNumber,
  IsOptional,
  IsString,
  IsUrl,
  Min,
} from 'class-validator';

/**
 * Keycloak strategy config. Pass as strategyConfig.keycloak when using AuthVaultModule with name: 'keycloak'.
 */
export class KeycloakConfigDto {
  @IsString()
  @IsNotEmpty()
  clientId: string;

  @IsString()
  @IsNotEmpty()
  clientSecret: string;

  @IsString()
  @IsNotEmpty()
  realm: string;

  @IsString()
  @IsNotEmpty()
  @IsUrl()
  url: string;

  /** Alias for url (auth-server-url). */
  @IsOptional()
  @IsUrl()
  authServerUrl?: string;

  /** Bearer-only app (no direct login). */
  @IsOptional()
  @IsBoolean()
  bearerOnly?: boolean;

  /** Realm public key (for offline validation). */
  @IsOptional()
  @IsString()
  realmPublicKey?: string;

  /** Minutes between JWKS requests. */
  @IsOptional()
  @IsNumber()
  @Min(0)
  minTimeBetweenJwksRequests?: number;

  /** Verify token audience. */
  @IsOptional()
  @IsBoolean()
  verifyTokenAudience?: boolean;

  /** Public client (no secret for some flows). */
  @IsOptional()
  @IsBoolean()
  public?: boolean;
}
