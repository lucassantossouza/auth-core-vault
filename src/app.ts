import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { INestApplication, VersioningType } from '@nestjs/common';
import { SwaggerService } from './swagger/swagger.service';

export async function app(): Promise<INestApplication> {
  // bufferLogs: true garante que logs iniciais sejam processados pelo logger customizado
  const nestApp = await NestFactory.create(AppModule, {
    bufferLogs: true,
  });

  nestApp.enableVersioning({
    type: VersioningType.URI,
    prefix: 'v',
    defaultVersion: '1',
  });

  const swaggerService = nestApp.get(SwaggerService);
  swaggerService.setupSwagger(nestApp);

  return nestApp;
}
