import {
  BadGatewayException,
  BadRequestException,
  ForbiddenException,
  Inject,
  Injectable,
  InternalServerErrorException,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { RegisterDTO } from './dto/register.dto';
import * as argon2 from 'argon2';
import { UUID } from 'crypto';
import { JwtService } from '@nestjs/jwt';
import { Role, User } from '@prisma/client';
import { LoginDTO } from './dto/login.dto';
import { ConfigType } from '@nestjs/config';
import jwtConfiguration from '../config/jwt.config';
import { FileLogger } from '../logger/file.logger';
import { EventEmitter2 } from '@nestjs/event-emitter';
import UserRegisteredEvent from './events/user-registered.event';
import ForgotPasswordTokenRequestedEvent from './events/forgot-password-token-requested.event';
import { UserEntity } from '../user/entities/user.entity';
import EmailVerifiedEvent from './events/email-verified.event';
import {
  EMAIL_VERIFIED,
  FORGOT_PASSWORD_TOKEN_REQUESTED,
  SEND_VERIFY_EMAIL,
  USER_REGISTERED,
} from './events/events';
import SendVerifyEmailEvent from './events/send-verify-email.event';
import twilioConfiguration from '../config/twilio.config';
import twilio, { Twilio } from 'twilio';
import { AppConfigService } from '../app-config/app-config.service';
import { TWILIO_PHONE_VERIFICATION_SERVICE } from '../app-config/app-config';
import { UserService } from '../user/user.service';

/**
 * Service responsible for handling authentication-related operations.
 */
@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UserService,
    private readonly appConfigService: AppConfigService,
    private readonly prismaService: PrismaService,
    private readonly jwtService: JwtService,
    @Inject(jwtConfiguration.KEY)
    private readonly jwtConfig: ConfigType<typeof jwtConfiguration>,
    private readonly logger: FileLogger,
    private readonly eventEmitter: EventEmitter2,
    @Inject(twilioConfiguration.KEY)
    private readonly twilioConfig: ConfigType<typeof twilioConfiguration>,
  ) {}

  /**
   * Registers a new user with the provided information.
   * @param dto - The registration information for the new user.
   * @returns The newly created user.
   */
  async register(dto: RegisterDTO) {
    try {
      const {
        password,
        countryId,
        firstName,
        lastName,
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        confirm_password,
        ...rest
      } = dto;

      const hashedPassword = await argon2.hash(password);

      const user = await this.prismaService.user.create({
        data: {
          ...rest,
          firstName,
          lastName,
          name: `${firstName} ${lastName}`,
          password: hashedPassword,
          country: {
            connect: {
              id: countryId,
            },
          },
        },
      });

      const tokens = await this.generateTokens(user.id as UUID, user.email);

      await this.updateRefreshToken(user.id as UUID, tokens.refreshToken);

      //   Emit user registered event
      this.eventEmitter.emit(USER_REGISTERED, new UserRegisteredEvent(user));

      return { ...new UserEntity(user), ...tokens };
    } catch (error: any) {
      this.logger.error(error.message, error.stack, 'AuthService.register');
      throw error;
    }
  }

  /**
   * Generates a JWT token and a refresh token for the given user ID and email.
   * @param user_id - The ID of the user.
   * @param email - The email of the user.
   * @returns An object containing the JWT token and the refresh token.
   */
  async generateTokens(user_id: UUID, email: string) {
    try {
      const [jwtToken, refreshToken] = await Promise.all([
        this.jwtService.signAsync(
          { email: email, sub: user_id },
          {
            secret: this.jwtConfig.secret,
            expiresIn: this.jwtConfig.expiration,
          },
        ),
        this.jwtService.signAsync(
          { email: email, sub: user_id },
          {
            secret: this.jwtConfig.refreshSecret,
            expiresIn: this.jwtConfig.refreshExpiration,
          },
        ),
      ]);

      return { jwtToken, refreshToken };
    } catch (error: any) {
      this.logger.error(
        error.message,
        error.stack,
        'AuthService.generateTokens',
      );
      throw error;
    }
  }

  /**
   * Updates the refresh token for a given user.
   * @param userId The ID of the user to update the refresh token for.
   * @param refreshToken The new refresh token to set for the user.
   * @returns A Promise that resolves when the refresh token has been updated.
   */
  async updateRefreshToken(userId: UUID, refreshToken: string): Promise<void> {
    try {
      await this.prismaService.user.update({
        where: {
          id: userId,
        },
        data: {
          refreshToken: await argon2.hash(refreshToken),
        },
      });
    } catch (error: any) {
      this.logger.error(
        error.message,
        error.stack,
        'AuthService.updateRefreshToken',
      );
      throw error;
    }
  }

  /**
   * Refreshes the access and refresh tokens for the given user.
   * @param userId The ID of the user to refresh tokens for.
   * @param refreshToken The refresh token to use for generating new tokens.
   * @returns An object containing the new JWT token and refresh token.
   * @throws ForbiddenException if the user or their refresh token cannot be found, or if the provided refresh token does not match the user's refresh token.
   */
  async refreshTokens(
    userId: UUID,
    refreshToken: string,
  ): Promise<{
    jwtToken: string;
    refreshToken: string;
  }> {
    try {
      const user = await this.prismaService.user.findFirst({
        where: { id: userId, deletedAt: null },
      });

      if (!user || !user.refreshToken) {
        throw new ForbiddenException('Access Denied');
      }

      // Check if the token matches the user's refresh token
      const refreshTokenMatches = await argon2.verify(
        user.refreshToken,
        refreshToken,
      );

      if (!refreshTokenMatches) {
        throw new ForbiddenException('Access Denied');
      }

      const tokens = await this.generateTokens(user.id as UUID, user.email);

      await this.updateRefreshToken(user.id as UUID, tokens.refreshToken);

      return tokens;
    } catch (error: any) {
      this.logger.error(
        error.message,
        error.stack,
        'AuthService.refreshTokens',
      );
      throw error;
    }
  }

  /**
   * Validates a user's login credentials.
   * @param dto - The LoginDTO containing the user's email and password.
   * @returns A Promise that resolves to the User object if the credentials are valid.
   * @throws BadRequestException if the email or password is invalid.
   */
  async validateUser(dto: LoginDTO): Promise<User> {
    try {
      const { email, password } = dto;

      const user = await this.prismaService.user.findFirst({
        where: { email, deletedAt: null },
      });

      if (!user) throw new UnauthorizedException('Invalid credentials');

      const match = await argon2.verify(user.password, password);

      if (!match) throw new UnauthorizedException('Invalid credentials');

      return user;
    } catch (error: any) {
      this.logger.error(error.message, error.stack, 'AuthService.validateUser');
      throw error;
    }
  }

  /**
   * Logs in a user and generates access and refresh tokens.
   * @param user - The user to log in.
   * @returns An object containing the generated access and refresh tokens.
   * @throws If an error occurs while generating tokens or updating the refresh token.
   */
  async login(user: User) {
    try {
      const tokens = await this.generateTokens(user.id as UUID, user.email);

      await this.updateRefreshToken(user.id as UUID, tokens.refreshToken);

      return tokens;
    } catch (error: any) {
      this.logger.error(error.message, error.stack, 'AuthService.login');
      throw error;
    }
  }

  /**
   * Verifies the email of a user using a token.
   * @param token - The token to use for email verification.
   * @throws BadRequestException if the token is invalid.
   * @throws Error if an unexpected error occurs while verifying the email.
   */
  async verifyEmail(token: string) {
    try {
      // Check if token is valid
      const verification = await this.prismaService.emailVerification.findFirst(
        {
          where: {
            token,
            expiresAt: { gte: new Date() },
          },
          include: {
            user: true,
          },
        },
      );

      if (!verification) throw new BadRequestException('Invalid Token');

      await this.prismaService.user.update({
        where: {
          id: verification.userId,
        },
        data: {
          emailVerifiedAt: new Date(),
        },
      });

      // Mark the token as expired so as to prevent re-use.
      await this.prismaService.emailVerification.update({
        where: {
          id: verification.id,
        },
        data: {
          expiresAt: new Date(),
        },
      });

      //  Emit email verified event
      this.eventEmitter.emit(
        EMAIL_VERIFIED,
        new EmailVerifiedEvent(verification.user),
      );
    } catch (error: any) {
      if (error instanceof BadRequestException) {
        throw error;
      }

      this.logger.error(error.message, error.stack, 'AuthService.verifyEmail');
      throw new Error('Unexpected error verifying email');
    }
  }

  /**
   * Sends a forgot password email to the user with the specified email address.
   * @param email The email address of the user who forgot their password.
   * @throws BadRequestException if the email address is invalid.
   */
  async forgotPassword(email: string) {
    try {
      const user = await this.prismaService.user.findFirst({
        where: { email, deletedAt: null, isBlocked: false },
      });

      if (!user) throw new BadRequestException('Invalid email');

      //   Emit forgot password token requested event
      this.eventEmitter.emit(
        FORGOT_PASSWORD_TOKEN_REQUESTED,
        new ForgotPasswordTokenRequestedEvent(user),
      );

      return;
    } catch (error: any) {
      this.logger.error(
        error.message,
        error.stack,
        'AuthService.forgotPassword',
      );
      throw error;
    }
  }

  /**
   * Resets the password for a user with the given token.
   * @param token - The token associated with the password reset request.
   * @param newPassword - The new password to set for the user.
   * @throws NotFoundException if the user is not found.
   * @throws BadRequestException if the token is invalid or the associated user is not found.
   */
  async resetPassword(token: string, newPassword: string, email: string) {
    try {
      const user = await this.prismaService.user.findUnique({
        where: {
          email,
          deletedAt: null,
          isBlocked: false,
        },
      });

      if (!user) {
        throw new NotFoundException('User not found');
      }

      const passwordReset = await this.prismaService.passwordReset.findFirst({
        where: {
          userId: user.id,
          token,
          expiresAt: { gte: new Date() },
        },
      });

      if (!passwordReset) throw new BadRequestException('Invalid token');

      await this.prismaService.user.update({
        where: {
          id: user.id,
        },
        data: {
          password: await argon2.hash(newPassword),
        },
      });

      await this.prismaService.passwordReset.update({
        where: {
          id: passwordReset.id,
        },
        data: {
          expiresAt: new Date(),
        },
      });
    } catch (error: any) {
      this.logger.error(
        error.message,
        error.stack,
        'AuthService.resetPassword',
      );
      throw error;
    }
  }

  /**
   * Creates a new user with the provided data and role.
   * @param dto - The registration data for the user.
   * @param role - The role of the user.
   * @returns The created user.
   * @throws If an error occurs during the user creation process.
   */
  async createUser(dto: Omit<RegisterDTO, 'confirm_password'>, role: Role) {
    try {
      const { firstName, lastName, email, address, password, phone } = dto;
      const hashedPassword = await argon2.hash(password);

      const user = await this.prismaService.user.create({
        data: {
          name: `${firstName} ${lastName}`,
          firstName,
          lastName,
          email,
          address: address === '' ? null : address,
          password: hashedPassword,
          role,
          phone,
        },
      });

      // Emit user registered event
      this.eventEmitter.emit('user.registered', new UserRegisteredEvent(user));

      return user;
    } catch (error: any) {
      this.logger.error(error.message, error.stack, 'AuthService.createUser');
      throw error;
    }
  }

  /**
   * Creates a verified user with the provided data and role.
   *
   * @param dto - The user registration data, excluding the confirm_password field.
   * @param role - The role of the user.
   * @returns The created user.
   * @throws If an error occurs during the user creation process.
   */
  async createVerifiedUser(
    dto: Omit<RegisterDTO, 'confirm_password'>,
    role: Role,
  ) {
    try {
      const { firstName, lastName, email, address, password, phone } = dto;
      const hashedPassword = await argon2.hash(password);

      const user = await this.prismaService.user.create({
        data: {
          name: `${firstName} ${lastName}`,
          firstName,
          lastName,
          email,
          address: address === '' ? null : address,
          phone,
          password: hashedPassword,
          role,
          emailVerifiedAt: new Date(),
        },
      });

      return user;
    } catch (error: any) {
      this.logger.error(error.message, error.stack, 'AuthService.createUser');
      throw error;
    }
  }

  /**
   * Authenticates a user using Google login.
   *
   * @param req - The request object containing user data from Google.
   * @returns A Promise that resolves to an object containing authentication tokens.
   */
  async googleLogin(req: any) {
    // Create user with the provided data from Google
    const { email, firstName, lastName, picture, accessToken } = req;

    const user = await this.prismaService.user.findFirst({
      where: {
        email,
      },
    });

    if (user) {
      const tokens = await this.generateTokens(user.id as UUID, user.email);

      await this.updateRefreshToken(user.id as UUID, tokens.refreshToken);

      return tokens;
    }

    const newUser = await this.prismaService.user.create({
      data: {
        email,
        name: firstName + ' ' + lastName,
        avatar: picture,
        password: await argon2.hash(accessToken),
        emailVerifiedAt: new Date(),
      },
    });

    return await this.generateTokens(newUser.id as UUID, newUser.email);
  }

  /**
   * Resend a verification email to the specified email address.
   *
   * @param email - The email address to which the verification email will be sent.
   * @throws {BadRequestException} If the email address is invalid.
   * @throws {BadRequestException} If the email address is already verified.
   */
  async resendVerificationEmail(email: string) {
    try {
      const user = await this.prismaService.user.findFirst({
        where: { email, deletedAt: null, isBlocked: false },
      });

      if (!user) throw new BadRequestException('Invalid email');

      if (user.emailVerifiedAt) {
        throw new BadRequestException('Email already verified');
      }

      //   Emit send verify email event
      this.eventEmitter.emit(SEND_VERIFY_EMAIL, new SendVerifyEmailEvent(user));

      return;
    } catch (error: any) {
      this.logger.error(
        error.message,
        error.stack,
        'AuthService.resendVerificationEmail',
      );
      throw error;
    }
  }

  /**
   * Creates a Twilio phone verification service.
   *
   * @param client - The Twilio client.
   * @returns The created Twilio phone verification service.
   */
  private async createTwilioPhoneVerificationService(client: Twilio) {
    const service = await client.verify.v2.services.create({
      friendlyName: TWILIO_PHONE_VERIFICATION_SERVICE,
      codeLength: 6,
    });

    return service;
  }

  /**
   * Fetches or creates a Twilio phone verification service.
   * If the service already exists, it returns the service SID.
   * If the service does not exist, it creates a new service and returns the newly created service SID.
   * @param client - The Twilio client.
   * @returns The Twilio phone verification service SID.
   */
  private async fetchOrCreateTwilioPhoneVerificationService(client: Twilio) {
    const service = await this.appConfigService.getConfig(
      TWILIO_PHONE_VERIFICATION_SERVICE,
    );

    if (service) {
      return service.value;
    }

    const createdService =
      await this.createTwilioPhoneVerificationService(client);

    await this.appConfigService.createConfig(
      TWILIO_PHONE_VERIFICATION_SERVICE,
      createdService.sid,
    );

    return createdService.sid;
  }

  /**
   * Sends a phone verification code to the user with the specified userId.
   *
   * @param userId - The ID of the user.
   * @returns A promise that resolves to the verification object.
   * @throws BadRequestException if the user does not have a phone number or if the phone is already verified.
   */
  async sendPhoneVerificationCode(userId: UUID) {
    try {
      const user = await this.userService.findById(userId);

      if (!user.phone) {
        throw new BadRequestException('User does not have a phone number');
      }

      if (user.phoneVerifiedAt) {
        throw new BadRequestException('Phone already verified');
      }

      const [authToken, accountSid] = [
        this.twilioConfig.authToken,
        this.twilioConfig.accountSid,
      ];

      const client = twilio(accountSid, authToken);

      const serviceSid =
        await this.fetchOrCreateTwilioPhoneVerificationService(client);

      if (!accountSid) {
        this.logger.log('No Twilio account SID found');
        throw new InternalServerErrorException('Error creating verification');
      }

      if (!authToken) {
        this.logger.log('No Twilio authToken found');
        throw new InternalServerErrorException('Error creating verification');
      }

      await this.createTwilioVerificationCode(
        serviceSid,
        accountSid,
        authToken,
        user.phone,
      );
    } catch (error: any) {
      this.logger.error(
        error.message,
        error.stack,
        'AuthService.sendPhoneVerificationCode',
      );
      throw error;
    }
  }

  /**
   * Creates a Twilio verification code.
   *
   * @param serviceSid - The Twilio service SID.
   * @param accountSid - The Twilio account SID.
   * @param authToken - The Twilio authentication token.
   * @param phone - The phone number to send the verification code to.
   * @returns A promise that resolves to the verification object.
   * @throws {BadGatewayException} If there is an error creating the verification code.
   */
  private async createTwilioVerificationCode(
    serviceSid: string,
    accountSid: string,
    authToken: string,
    phone: string,
  ) {
    try {
      const url = `https://verify.twilio.com/v2/Services/${serviceSid}/Verifications`;

      const headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization:
          'Basic ' +
          Buffer.from(accountSid + ':' + authToken).toString('base64'),
      };

      const body = new URLSearchParams({
        To: phone,
        Channel: 'sms',
      }).toString();

      const response = await fetch(url, {
        method: 'POST',
        headers,
        body,
      });

      if (!response.ok) {
        this.logger.error(await response.json());
        throw new BadGatewayException('Error creating verification code');
      }

      const verification = await response.json();
      return verification;
    } catch (error: any) {
      throw error;
    }
  }

  /**
   * Verifies the phone code for a user.
   * @param userId - The ID of the user.
   * @param code - The phone verification code.
   * @throws {BadRequestException} If the user does not have a phone number or if the code is invalid.
   * @returns {Promise<void>} A promise that resolves when the phone code is verified.
   */
  async verifyPhoneCode(userId: UUID, code: string): Promise<void> {
    try {
      const client = twilio(
        this.twilioConfig.accountSid,
        this.twilioConfig.authToken,
      );

      const serviceSid =
        await this.fetchOrCreateTwilioPhoneVerificationService(client);

      const user = await this.userService.findById(userId);

      if (!user.phone) {
        throw new BadRequestException('User does not have a phone number');
      }

      const verification = await this.verifyCodeWithTwilio(
        client,
        serviceSid,
        user.phone,
        code,
      );

      if (verification.status === 'approved') {
        await this.markPhoneAsVerified(userId);
        return;
      }

      throw new BadRequestException('Invalid code');
    } catch (error: any) {
      this.logger.error(
        error.message,
        error.stack,
        'AuthService.verifyPhoneCode',
      );

      throw error;
    }
  }

  /**
   * Verifies a code with Twilio.
   *
   * @param client - The Twilio client.
   * @param serviceSid - The Twilio service SID.
   * @param phone - The phone number to verify.
   * @param code - The verification code.
   * @returns A promise that resolves to the verification result.
   * @throws BadRequestException if the code is invalid.
   */
  private async verifyCodeWithTwilio(
    client: Twilio,
    serviceSid: string,
    phone: string,
    code: string,
  ) {
    try {
      return await client.verify.v2
        .services(serviceSid)
        .verificationChecks.create({
          to: phone,
          code,
        });
    } catch (error: any) {
      if (error.status === 404) {
        throw new BadRequestException('Invalid code');
      }

      throw error;
    }
  }

  /**
   * Marks the phone of a user as verified.
   * @param userId The ID of the user.
   * @throws Throws an error if there was an issue updating the user's phone verification status.
   */
  private async markPhoneAsVerified(userId: UUID) {
    try {
      await this.prismaService.user.update({
        where: {
          id: userId,
        },
        data: {
          phoneVerifiedAt: new Date(),
        },
      });
    } catch (error: any) {
      this.logger.error(
        error.message,
        error.stack,
        'AuthService.markPhoneAsVerified',
      );
      throw error;
    }
  }
}
