import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { PassportModule } from '@nestjs/passport';
import { LocalStrategy } from './strategies/local.strategy';
import { RefreshTokenStrategy } from './strategies/refresh-token.strategy';
import MailBuilder from '../mail/mail.builder';
import { MailService } from '../mail/mail.service';
import { BullModule } from '@nestjs/bull';
import SendEmailVerificationMailListener from './events/listeners/send-email-verification-mail.listener';
import ForgotPasswordTokenRequestedListener from './events/listeners/forgot-password-token-requested.listener';
import { UserService } from '../user/user.service';
import { GoogleStrategy } from './strategies/google.strategy';
import { CreateStripeCustomerListener } from './events/listeners/create-stripe-customer.listener';
import { StripeService } from '../payment/stripe/stripe.service';

@Module({
  controllers: [AuthController],
  providers: [
    AuthService,
    LocalStrategy,
    RefreshTokenStrategy,
    MailBuilder,
    MailService,
    SendEmailVerificationMailListener,
    CreateStripeCustomerListener,
    ForgotPasswordTokenRequestedListener,
    UserService,
    GoogleStrategy,
    StripeService,
  ],
  imports: [PassportModule, BullModule.registerQueue({ name: 'mail' })],
})
export class AuthModule {}
