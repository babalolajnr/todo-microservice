import { Injectable } from '@nestjs/common';
import { OnEvent } from '@nestjs/event-emitter';
import { PrismaService } from '../../../prisma/prisma.service';
import ForgotPasswordTokenRequestedEvent from '../forgot-password-token-requested.event';
import MailBuilder from '../../../mail/mail.builder';
import { randomString } from '../../../utilities/string/string.utilities';
import { FileLogger } from '../../../logger/file.logger';
import { FORGOT_PASSWORD_TOKEN_REQUESTED } from '../events';

@Injectable()
export default class ForgotPasswordTokenRequestedListener {
  constructor(
    private readonly prismaService: PrismaService,
    private readonly mailBuilder: MailBuilder,
    private readonly logger: FileLogger,
  ) {}

  @OnEvent(FORGOT_PASSWORD_TOKEN_REQUESTED)
  async handleForgotPasswordTokenRequestedEvent(
    event: ForgotPasswordTokenRequestedEvent,
  ) {
    try {
      //  update all the previous tokens for the user and mark them as expired
      await this.prismaService.passwordReset.updateMany({
        where: {
          userId: event.user.id,
          expiresAt: { gte: new Date() },
        },
        data: {
          expiresAt: new Date(),
        },
      });

      const token = randomString(6, 'numeric');

      //   Expires in 15 minutes
      const tokenExpiresAt = new Date(Date.now() + 1000 * 60 * 15);

      await this.prismaService.passwordReset.create({
        data: {
          userId: event.user.id,
          token,
          expiresAt: tokenExpiresAt,
        },
      });

      await (
        await this.mailBuilder
          .to(event.user.email)
          .subject('PrimeTic | Password Reset Token')
          .buildTemplate('forgot-password-mail', {
            token,
          })
      ).send();
    } catch (error: any) {
      this.logger.error(error);
      throw error;
    }
  }
}
