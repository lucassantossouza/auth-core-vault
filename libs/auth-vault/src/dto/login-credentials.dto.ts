import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

/** Credentials for login (e.g. password grant). */
export class LoginCredentialsDto {
  @ApiProperty({
    description: 'Username',
    example: 'john.doe',
  })
  @IsString()
  @IsNotEmpty()
  username: string;

  @ApiProperty({
    description: 'Password',
    example: 'password',
  })
  @IsString()
  @IsNotEmpty()
  password: string;
}
