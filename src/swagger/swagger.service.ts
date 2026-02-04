import { INestApplication, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  DocumentBuilder,
  SwaggerDocumentOptions,
  SwaggerModule as NestSwaggerModule,
} from '@nestjs/swagger';

@Injectable()
export class SwaggerService {
  constructor(private readonly configService: ConfigService) {}

  setupSwagger(app: INestApplication) {
    const options = new DocumentBuilder()
      .setTitle(
        this.configService.get<string>(
          'npm_package_name',
          'Orchestron Core API',
        ),
      )
      .setDescription(
        this.configService.get<string>(
          'npm_package_description',
          'Orchestron Core API Documentation',
        ),
      )
      .setVersion(
        this.configService.get<string>('npm_package_version', '0.0.0'),
      )
      .addBearerAuth()
      .addSecurityRequirements('bearer', [])
      .build();

    const documentOptions: SwaggerDocumentOptions = {
      ignoreGlobalPrefix: true,
      operationIdFactory: (controllerKey: string, methodKey: string) =>
        methodKey,
      extraModels: [],
    };

    const document = NestSwaggerModule.createDocument(
      app,
      options,
      documentOptions,
    );

    const pathSwagger = this.configService.get<string>(
      'PATH_SWAGGER',
      'swagger',
    );

    NestSwaggerModule.setup(pathSwagger, app, document, {
      swaggerOptions: {
        filter: true,
      },
    });
  }
}
