import { AuthLogLevel, AuthVaultModule } from '@app/auth-vault';
import { Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { KeycloakController } from './keycloak.controller';

@Module({
  imports: [
    AuthVaultModule.forFeatureAsync({
      useFactory: (configService: ConfigService) => ({
        logLevels: [AuthLogLevel.ERROR, AuthLogLevel.WARN, AuthLogLevel.LOG],
        strategyConfig: {
          name: 'keycloak',
          url: configService.get('AUTH_KEYCLOAK_URL', ''),
          realm: configService.get('AUTH_KEYCLOAK_REALM', ''),
          clientId: configService.get('AUTH_KEYCLOAK_CLIENT_ID', ''),
          clientSecret: configService.get('AUTH_KEYCLOAK_CLIENT_SECRET', ''),
        },
      }),
      inject: [ConfigService],
    }),
  ],
  controllers: [KeycloakController],
})
export class KeycloakModule {}
