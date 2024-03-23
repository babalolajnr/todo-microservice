import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

export class VerifyPhoneDTO {
  @ApiProperty({ example: '123456', description: 'The verification code' })
  @IsNotEmpty()
  @IsString()
  code!: string;
}
