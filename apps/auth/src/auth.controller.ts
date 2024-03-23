import {
  Body,
  Controller,
  Post,
  UseGuards,
  Request,
  InternalServerErrorException,
  Get,
  Req,
  Param,
  Version,
  VERSION_NEUTRAL,
  Patch,
  ForbiddenException,
  Res,
  UseInterceptors,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDTO } from './dto/register.dto';
import { response } from '../utilities/response';
import {
  ApiOperation,
  ApiResponse,
  ApiBadRequestResponse,
  ApiInternalServerErrorResponse,
  ApiTags,
  ApiCreatedResponse,
  ApiUnauthorizedResponse,
  ApiBearerAuth,
  ApiForbiddenResponse,
  ApiOkResponse,
  ApiParam,
  ApiHeader,
} from '@nestjs/swagger';
import { LoginDTO } from './dto/login.dto';
import { LocalAuthGuard } from './guards/local.auth.guard';
import { UUID } from 'crypto';
import { RefreshTokenGuard } from './guards/refresh-token.auth.guard';
import { RequestWithUser } from '../utilities/request';
import { Public } from './decorators/public.decorator';
import { ForgotPasswordDTO } from './dto/forgot-password.dto';
import { ResetPasswordDTO } from './dto/reset-password.dto';
import { Roles } from './decorators/roles.decorator';
import { Role } from '@prisma/client';
import { Verified } from './decorators/verified.decorator';
import { CreateUserDTO } from './dto/create-user.dto';
import { GoogleOAuthGuard } from './guards/google-oauth.guard';
import { UserEntity } from '../user/entities/user.entity';
import { FastifyReply } from 'fastify';
import { EmailVerificationDto } from './dto/email-verification.dto';
import { User } from '../user/user.decorator';
import { User as UserModel } from '@prisma/client';
import { VerifyPhoneDTO } from './dto/verify-phone.dto';
import { HideFieldsInterceptor } from '../utilities/hide-fields/hide-fields.interceptor';
import { USER_GUARDED_FIELDS } from '../user/guarded-fields';
import { UserService } from '../user/user.service';

@ApiHeader({
  name: 'X-API-Version',
  description: 'The version of the API',
})
@ApiTags('auth')
@ApiInternalServerErrorResponse({ description: 'Internal server error' })
@Controller({ path: 'auth', version: '0' })
export class AuthController {
  constructor(
    private readonly service: AuthService,
    private readonly userService: UserService,
  ) {}

  @Public()
  @ApiOperation({ summary: 'Register a new user' })
  @ApiResponse({ status: 201, description: 'User registered successfully' })
  @ApiBadRequestResponse({
    description: 'Validation failed',
  })
  @UseInterceptors(new HideFieldsInterceptor(USER_GUARDED_FIELDS))
  @Post('register')
  async register(@Body() dto: RegisterDTO) {
    try {
      return response(
        'User registered successfully',
        await this.service.register(dto),
      );
    } catch (error: any) {
      throw new InternalServerErrorException('Error registering user');
    }
  }

  /**
   * Log in a user. This endpoint returns a JWT token which can be used to
   * access protected endpoints.
   */
  @Public()
  @ApiOperation({ summary: 'Login a user' })
  @ApiCreatedResponse({ description: 'Login successful' })
  @ApiBadRequestResponse({ description: 'Invalid credentials' })
  @ApiUnauthorizedResponse({ description: 'Invalid credentials' })
  @UseGuards(LocalAuthGuard)
  @Post('login')
  async login(@Body() dto: LoginDTO, @Request() req: any) {
    try {
      return response('Login successful', await this.service.login(req.user));
    } catch (error: any) {
      throw new InternalServerErrorException('Error logging in user');
    }
  }

  @Public()
  @ApiOperation({
    summary: 'Refresh authentication tokens',
    responses: { default: { description: 'Success' } },
  })
  @ApiOkResponse({ description: 'Tokens refreshed successfully' })
  @ApiForbiddenResponse({ description: 'Access Denied' })
  @ApiUnauthorizedResponse({ description: 'Unauthorized' })
  @ApiBearerAuth()
  @UseGuards(RefreshTokenGuard)
  @Get('refresh-tokens')
  async refreshTokens(@Req() req: RequestWithUser) {
    try {
      const { sub, refreshToken } = req.user;

      return response(
        'Tokens refreshed successfully',
        await this.service.refreshTokens(sub as UUID, refreshToken as string),
      );
    } catch (error: any) {
      throw error;
    }
  }

  /**
   * Verify a user email. This endpoint is used to verify a user email. It
   * expects a token as a parameter. The token is sent to the user email after
   * registration.
   * @param token
   * @param response
   * @returns
   */
  @Public()
  @ApiOperation({ summary: 'Verify a user email' })
  @ApiOkResponse({ description: 'Email verified successfully' })
  @ApiBadRequestResponse({ description: 'Invalid token' })
  @ApiParam({ name: 'token', type: 'string' })
  @Version(VERSION_NEUTRAL)
  @Get('/verify-email/:token')
  async verifyEmail(@Param('token') token: string) {
    try {
      await this.service.verifyEmail(token);

      return response('Email verified successfully');
    } catch (error: any) {
      throw error;
    }
  }

  @Public()
  @ApiOperation({ summary: 'Get forgot password reset token.' })
  @ApiOkResponse({ description: 'Password reset token sent successfully' })
  @ApiBadRequestResponse({ description: 'Invalid email' })
  @Post('forgot-password')
  async forgotPassword(@Body() dto: ForgotPasswordDTO) {
    return response(
      'Password reset token sent successfully',
      await this.service.forgotPassword(dto.email),
    );
  }

  @Public()
  @ApiOperation({ summary: 'Reset user password' })
  @ApiOkResponse({ description: 'Password reset successfully' })
  @ApiBadRequestResponse({ description: 'Invalid token' })
  @Patch('reset-password')
  async resetPassword(@Body() dto: ResetPasswordDTO) {
    return response(
      'Password reset successfully',
      await this.service.resetPassword(dto.token, dto.newPassword, dto.email),
    );
  }

  @ApiOperation({ summary: 'Get authenticated user' })
  @ApiOkResponse({ description: 'User retrieved successfully' })
  @ApiUnauthorizedResponse({ description: 'Unauthorized' })
  @UseInterceptors(new HideFieldsInterceptor(USER_GUARDED_FIELDS))
  @Get('authenticated-user')
  async authenticatedUser(@Req() req: RequestWithUser) {
    return response(
      'User retrieved successfully',
      await this.userService.findById(req.user.id as UUID),
    );
  }

  @ApiOperation({ summary: 'Register a new admin' })
  @ApiCreatedResponse({ description: 'Admin registered successfully' })
  @ApiBadRequestResponse({
    description: 'Validation failed',
  })
  @Roles(Role.SUPER_ADMIN)
  @Verified()
  @Post('register-admin')
  async registerAdmin(@Body() dto: RegisterDTO) {
    return response(
      'User registered successfully',
      await this.service.createUser(dto, 'ADMIN'),
    );
  }

  @ApiOperation({ summary: 'Get Roles' })
  @ApiOkResponse({ description: 'Roles retrieved successfully' })
  @ApiUnauthorizedResponse({ description: 'Unauthorized' })
  @Verified()
  @Roles(Role.SUPER_ADMIN, Role.ADMIN)
  @Get('roles')
  getRoles() {
    return response(
      'Roles retrieved successfully',
      Object.values(Role).filter((role) => role !== Role.SUPER_ADMIN),
    );
  }

  @ApiOperation({ summary: 'Register a new user by role' })
  @ApiCreatedResponse({ description: 'User registered successfully' })
  @ApiBadRequestResponse({
    description: 'Validation failed',
  })
  @ApiUnauthorizedResponse({ description: 'Unauthorized' })
  @Verified()
  @Roles(Role.SUPER_ADMIN, Role.ADMIN)
  @Post('register-user')
  async registerUser(@Body() dto: CreateUserDTO) {
    if (dto.role === Role.SUPER_ADMIN) {
      throw new ForbiddenException('Cannot create a super admin');
    }
    const user = await this.service.createUser(dto, dto.role);

    return response('User registered successfully', new UserEntity(user));
  }

  @Public()
  @ApiOperation({ summary: 'Authenticate a user by Google OAuth' })
  @Version(VERSION_NEUTRAL)
  @Get('google')
  @UseGuards(GoogleOAuthGuard)
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  async googleAuth(@Request() req: any) {}

  @Public()
  @Version(VERSION_NEUTRAL)
  @Get('google-redirect')
  @UseGuards(GoogleOAuthGuard)
  async googleAuthRedirect(
    @Req() req: RequestWithUser,
    @Res() res: FastifyReply,
  ) {
    const tokens = await this.service.googleLogin(req.user);

    await res
      .status(302)
      .redirect(
        `${process.env.FRONTEND_OAUTH_REDIRECT_URL}?jwt=${tokens.jwtToken}&refreshToken=${tokens.refreshToken}`,
      );
  }

  @Public()
  @ApiOperation({ summary: 'Resend verification email' })
  @Post('resend-verification-email')
  async resendVerificationEmail(@Body() dto: EmailVerificationDto) {
    return response(
      'Verification email sent successfully',
      await this.service.resendVerificationEmail(dto.email),
    );
  }

  @ApiOperation({ summary: 'Send phone verification code' })
  @ApiOkResponse({ description: 'Verification code sent successfully' })
  @ApiUnauthorizedResponse({ description: 'Unauthorized' })
  @Roles(Role.SUPER_ADMIN, Role.ADMIN, Role.USER, Role.SUPPORT)
  @Get('send-phone-verification-code')
  async sendPhoneVerificationCode(@User() user: UserModel) {
    return response(
      'Verification code sent successfully',
      await this.service.sendPhoneVerificationCode(user.id as UUID),
    );
  }

  @ApiOperation({ summary: 'Verify phone number' })
  @ApiOkResponse({ description: 'Phone number verified successfully' })
  @ApiUnauthorizedResponse({ description: 'Unauthorized' })
  @Roles(Role.SUPER_ADMIN, Role.ADMIN, Role.USER, Role.SUPPORT)
  @Post('verify-phone')
  async verifyPhoneCode(@Body() dto: VerifyPhoneDTO, @User() user: UserModel) {
    return response(
      'Phone number verified successfully',
      await this.service.verifyPhoneCode(user.id as UUID, dto.code),
    );
  }
}
