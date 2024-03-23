import { Inject, Injectable } from '@nestjs/common';
import { OnEvent } from '@nestjs/event-emitter';
import UserRegisteredEvent from '../user-registered.event';
import { PrismaService } from '../../../prisma/prisma.service';
import { v4 as uuidv4 } from 'uuid';
import { ConfigType } from '@nestjs/config';
import MailBuilder from '../../../mail/mail.builder';
import appConfiguration from '../../../config/app.config';
import { FileLogger } from '../../../logger/file.logger';
import { User } from '@prisma/client';
import { SEND_VERIFY_EMAIL, USER_REGISTERED } from '../events';

@Injectable()
export default class SendEmailVerificationMailListener {
  constructor(
    private readonly prismaService: PrismaService,
    @Inject(appConfiguration.KEY)
    private readonly appConfig: ConfigType<typeof appConfiguration>,
    private readonly mailBuilder: MailBuilder,
    private readonly logger: FileLogger,
  ) {}

  @OnEvent(USER_REGISTERED)
  async handleUserRegisteredEvent(event: UserRegisteredEvent) {
    try {
      await this.sendEmailVerificationMail(event.user);
    } catch (error: any) {
      this.logger.error(error);
      throw error;
    }
  }

  @OnEvent(SEND_VERIFY_EMAIL)
  async handleSendVerifyEmailEvent(event: UserRegisteredEvent) {
    try {
      await this.sendEmailVerificationMail(event.user);
    } catch (error: any) {
      this.logger.error(error);
      throw error;
    }
  }

  /**
   * Sends an email verification mail to the specified user.
   * @param user - The user to send the email verification mail to.
   * @returns A Promise that resolves when the email is sent.
   */
  private async sendEmailVerificationMail(user: User) {
    const emailVerification = await this.prismaService.emailVerification.create(
      {
        data: {
          token: uuidv4(),
          expiresAt: new Date(new Date().getTime() + 30 * 60000), // 30min from now ,
          user: {
            connect: {
              email: user.email,
            },
          },
        },
        select: {
          token: true,
        },
      },
    );

    const verificationLink = `${this.appConfig.frontendUrl}/auth/verify-email/${emailVerification.token}`;

    await (
      await this.mailBuilder
        .to(user.email)
        .subject('PrimeTic | Verify email address')
        .buildTemplate('verify-mail', {
          name: user.name,
          verificationLink,
        })
    ).queue();
  }
}
