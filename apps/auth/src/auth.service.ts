import { Injectable, UnprocessableEntityException } from '@nestjs/common';
import { RegisterDTO } from './dto/register.dto';
import { PrismaService } from '@app/prisma';
import * as argon2 from 'argon2';

@Injectable()
export class AuthService {
  constructor(private readonly prismaService: PrismaService) {}

  async register(data: RegisterDTO) {
    const { email, password } = data;

    // Check if email is unique
    const user = await this.prismaService.user.findUnique({
      where: { email },
    });

    if (user) {
      throw new UnprocessableEntityException('Email already exists');
    }

    // Hash password
    const hashedPassword = await argon2.hash(password);

    return this.prismaService.user.create({
      data: {
        email,
        password: hashedPassword,
      },
    });
  }
}
