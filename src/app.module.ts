import { Module } from '@nestjs/common';
import { SwaggerModule } from './swagger/swagger.module';
import { ConfigModule } from '@nestjs/config';
import { KeycloakModule } from './modules/keycloak/keycloak.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    SwaggerModule,
    KeycloakModule,
  ],
  controllers: [],
  providers: [],
})
export class AppModule {}
