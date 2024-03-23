import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsString, MinLength } from 'class-validator';

export class ResetPasswordDTO {
  @ApiProperty({ example: '123456', description: 'Reset password token' })
  @IsString()
  token!: string;

  @ApiProperty({ example: 'email@gmail.com', description: 'User email' })
  @IsNotEmpty()
  @IsEmail()
  email!: string;

  @ApiProperty({ example: 'password', description: 'New password' })
  @IsNotEmpty()
  @MinLength(8)
  newPassword!: string;
}
