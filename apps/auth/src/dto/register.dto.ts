import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, MinLength } from 'class-validator';

export class RegisterDTO {
  @ApiProperty({
    example: 'example@gmail.com',
    description: 'The email of the user',
  })
  @IsNotEmpty()
  @IsEmail()
  email!: string;

  @ApiProperty({ example: 'password' })
  @IsNotEmpty()
  //   TODO: Add IsStrongPassword validator
  @MinLength(8)
  password!: string;
}
