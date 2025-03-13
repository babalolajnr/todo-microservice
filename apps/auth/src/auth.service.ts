import {
  Injectable,
  Logger,
  UnprocessableEntityException,
} from '@nestjs/common';
import { RegisterDTO } from './dto/register.dto';
import { PrismaService } from '@app/prisma';
import * as argon2 from 'argon2';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(private readonly prismaService: PrismaService) {}

  async register(data: RegisterDTO) {
    this.logger.debug(`Processing registration: ${JSON.stringify(data)}`);

    const { email, password } = data;

    try {
      // Check if email is unique
      const user = await this.prismaService.user.findUnique({
        where: { email },
      });

      if (user) {
        throw new UnprocessableEntityException('Email already exists');
      }

      // Hash password
      const hashedPassword = await argon2.hash(password);

      // Create user
      const newUser = await this.prismaService.user.create({
        data: {
          email,
          password: hashedPassword,
        },
      });

      this.logger.log(`User registered successfully: ${newUser.email}`);
      return {
        id: newUser.id,
        email: newUser.email,
        created: true,
      };
    } catch (error: any) {
      this.logger.error(`Registration failed: ${error.message}`);
      throw error;
    }
  }
}
