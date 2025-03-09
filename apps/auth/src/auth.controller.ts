import { Controller } from '@nestjs/common';
import { MessagePattern } from '@nestjs/microservices';

@Controller()
export class AuthController {
    constructor () { }

    @MessagePattern('register')

    async register() { }
}
