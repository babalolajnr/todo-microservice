import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, MinLength } from 'class-validator';
import { IsUnique } from '../../../../libs/common/src/validation/is-unique.validator';
import { Match } from '../../../../libs/common/src/validation/match.validator';

export class RegisterDTO {
  @ApiProperty({
    example: 'example@gmail.com',
    description: 'The email of the user',
  })
  @IsNotEmpty()
  @IsEmail()
  @IsUnique('User', {
    message: 'email already exists',
  })
  email!: string;

  @ApiProperty({ example: 'password' })
  @IsNotEmpty()
  //   TODO: Add IsStrongPassword validator
  @MinLength(8)
  password!: string;

  @ApiProperty({
    example: 'password',
    description: 'Must be the same as `password` field',
  })
  @Match('password')
  @IsNotEmpty()
  confirm_password!: string;
}
