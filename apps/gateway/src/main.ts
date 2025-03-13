import { NestFactory } from '@nestjs/core';
import { GatewayModule } from './gateway.module';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { apiReference } from '@scalar/nestjs-api-reference';

async function bootstrap() {
  const app = await NestFactory.create(GatewayModule);

  // app.connectMicroservice({
  //   transport: Transport.RMQ,
  //   options: {
  //     urls: ['amqp://localhost:5672'],
  //     queue: 'auth_queue',
  //     queueOptions: {
  //       durable: true,
  //     },
  //   },
  // });

  const config = new DocumentBuilder()
    .setTitle('Todo App')
    .setDescription('Api documentation for the todo app')
    .setVersion('1.0')
    .build();

  const document = SwaggerModule.createDocument(app, config);

  app.use(
    '/reference',
    apiReference({
      spec: {
        content: document,
      },
    }),
  );

  // await app.startAllMicroservices();
  await app.listen(3000);
}
bootstrap();
