import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty } from 'class-validator';

export class ForgotPasswordDTO {
  @ApiProperty({ description: 'User email', example: 'example@gmail.com' })
  @IsEmail()
  @IsNotEmpty()
  email!: string;
}
