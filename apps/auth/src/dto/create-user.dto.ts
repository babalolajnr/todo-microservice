import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsEnum } from 'class-validator';
import { Role } from '@prisma/client';
import { WrapperType } from '../../utilities/wrapper';
import { RegisterDTO } from './register.dto';

export class CreateUserDTO extends RegisterDTO {
  @ApiProperty({ example: 'ADMIN', description: 'The role of the user' })
  @IsNotEmpty()
  @IsEnum(Role)
  role!: WrapperType<Role>;
}
