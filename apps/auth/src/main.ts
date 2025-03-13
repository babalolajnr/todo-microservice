import { NestFactory } from '@nestjs/core';
import { AuthModule } from './auth.module';
import { MicroserviceOptions, Transport } from '@nestjs/microservices';
import { Logger } from '@nestjs/common';

async function bootstrap() {
  const logger = new Logger('Auth Microservice');

  try {
    const app = await NestFactory.createMicroservice<MicroserviceOptions>(
      AuthModule,
      {
        transport: Transport.RMQ,
        options: {
          urls: ['amqp://localhost:5672'],
          queue: 'auth_queue',
          queueOptions: {
            durable: true,
          },
        },
      },
    );

    await app.listen();
    logger.log('Auth microservice is listening');
  } catch (error) {
    logger.error(
      `Failed to start auth microservice: ${(error as Error).message}`,
    );
  }
}

bootstrap();
