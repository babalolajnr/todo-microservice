import { ApiProperty } from '@nestjs/swagger';
import {
  IsEmail,
  IsNotEmpty,
  IsOptional,
  IsPhoneNumber,
  MinLength,
} from 'class-validator';
import { IsUnique } from '../../utilities/validators/is-unique.validator';
import { Match } from '../../utilities/validators/match.validator';
import { UUID } from 'crypto';
import { Exists } from '../../utilities/validators/exists.validator';

export class RegisterDTO {
  @ApiProperty({ example: 'John', description: 'The first name of the user' })
  @IsNotEmpty()
  firstName!: string;

  @ApiProperty({ example: 'Doe', description: 'The last name of the user' })
  @IsNotEmpty()
  lastName!: string;

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

  @ApiProperty({
    example: '1234567890',
    description: 'The phone number of the user',
  })
  @IsNotEmpty()
  @IsPhoneNumber()
  @IsUnique('User', {
    message: 'phone already exists',
  })
  phone!: string;

  @ApiProperty({ example: '123 Main St Anytown, USA 12345' })
  @IsOptional()
  address?: string;

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

  @ApiProperty({
    example: '123 Main St',
    required: false,
    description: 'The first line of the address',
  })
  @IsOptional()
  firstLineAddress?: string;

  @ApiProperty({
    example: 'House Name',
    required: false,
    description: 'The name of the house',
  })
  @IsOptional()
  houseName?: string;

  @ApiProperty({
    example: '123 Main St',
    required: false,
    description: 'The second line of the address',
  })
  @IsOptional()
  secondLineAddress?: string;

  @ApiProperty({
    example: 'Anytown',
    required: false,
    description: 'The town of the address',
  })
  @IsOptional()
  town?: string;

  @ApiProperty({
    required: false,
    description: 'The id of the country of the address',
    type: String,
  })
  @IsOptional()
  @Exists({
    model: 'Country',
    field: 'id',
    validationOptions: {
      message: 'country does not exist',
    },
  })
  countryId?: UUID;

  @ApiProperty({
    example: '12345',
    required: false,
    description: 'The post code of the address',
  })
  @IsOptional()
  postCode?: string;
}
