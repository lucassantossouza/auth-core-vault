import {
  AuthUser,
  type AuthUserType,
  AuthVaultService,
  LoginCredentialsDto,
  Public,
} from '@app/auth-vault';
import { Controller, Body, Post, Get } from '@nestjs/common';

@Controller('keycloak')
export class KeycloakController {
  constructor(private readonly authVaultService: AuthVaultService) {}

  @Post('login')
  @Public()
  async login(@Body() body: LoginCredentialsDto) {
    return this.authVaultService.login(body);
  }

  @Get('user-info')
  userInfo(@AuthUser() user: AuthUserType) {
    return user;
  }
}
