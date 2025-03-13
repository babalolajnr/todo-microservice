import { Body, Controller, Inject, Post, Logger } from '@nestjs/common';
import { ClientProxy } from '@nestjs/microservices';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { RegisterDTO } from 'apps/auth/src/dto/register.dto';
import { firstValueFrom } from 'rxjs';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  private readonly logger = new Logger(AuthController.name);

  constructor(@Inject('AUTH_SERVICE') private readonly client: ClientProxy) {}

  @Post('register')
  @ApiOperation({ summary: 'register', description: 'Register a new user' })
  async register(@Body() data: RegisterDTO) {
    this.logger.log(`Sending registration request: ${JSON.stringify(data)}`);
    try {
      // Using firstValueFrom for better async/await handling with observables
      return await firstValueFrom(this.client.send({ cmd: 'register' }, data));
    } catch (error: any) {
      this.logger.error(`Registration error: ${error.message}`);
      throw error;
    }
  }
}
