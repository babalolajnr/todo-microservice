import { Controller, Logger } from '@nestjs/common';
import { MessagePattern } from '@nestjs/microservices';
import { RegisterDTO } from './dto/register.dto';
import { AuthService } from './auth.service';

@Controller()
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @MessagePattern({ cmd: 'register' })
  async register(data: RegisterDTO) {
    Logger.log(`Registering user: ${JSON.stringify(data)}`);
    return this.authService.register(data);
  }
}
