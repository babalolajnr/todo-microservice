import { Injectable } from '@nestjs/common';
import { FileLogger } from '../../../logger/file.logger';
import { StripeService } from '../../../payment/stripe/stripe.service';
import { OnEvent } from '@nestjs/event-emitter';
import UserRegisteredEvent from '../user-registered.event';
import { EMAIL_VERIFIED } from '../events';

@Injectable()
export class CreateStripeCustomerListener {
  constructor(
    private readonly stripeService: StripeService,
    private readonly logger: FileLogger,
  ) {}

  @OnEvent(EMAIL_VERIFIED)
  async handle(event: UserRegisteredEvent) {
    try {
      await this.stripeService.createCustomer(event.user);
    } catch (error: any) {
      this.logger.error(
        error.message,
        error.stack,
        'CreateStripeCustomerListener.handle',
      );
      throw error;
    }
  }
}
