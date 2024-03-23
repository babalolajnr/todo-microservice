import {
  ForbiddenException,
  Inject,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { RegisterDTO } from './dto/register.dto';
import * as argon2 from 'argon2';
import { UUID } from 'crypto';
import { User } from '@prisma/client';
import { LoginDTO } from './dto/login.dto';
import { PrismaService } from '../../../libs/prisma/src';
import { JwtService } from '@nestjs/jwt';
import { ConfigType } from '@nestjs/config';
import jwtConfiguration from './config/jwt.config';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,

    @Inject(jwtConfiguration.KEY)
    private readonly jwtConfig: ConfigType<typeof jwtConfiguration>,
  ) {}

  /**
   * Registers a new user with the provided information.
   * @param dto - The registration information for the new user.
   * @returns The newly created user.
   */
  async register(dto: RegisterDTO) {
    const { password, email } = dto;

    const hashedPassword = await argon2.hash(password);

    const user = await this.prisma.user.create({
      data: {
        password: hashedPassword,
        email,
      },
    });

    const tokens = await this.generateTokens(user.id as UUID, user.email);

    await this.updateRefreshToken(user.id as UUID, tokens.refreshToken);

    return { user, ...tokens };
  }

  /**
   * Generates a JWT token and a refresh token for the given user ID and email.
   * @param user_id - The ID of the user.
   * @param email - The email of the user.
   * @returns An object containing the JWT token and the refresh token.
   */
  async generateTokens(user_id: UUID, email: string) {
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
  }

  /**
   * Updates the refresh token for a given user.
   * @param userId The ID of the user to update the refresh token for.
   * @param refreshToken The new refresh token to set for the user.
   * @returns A Promise that resolves when the refresh token has been updated.
   */
  async updateRefreshToken(userId: UUID, refreshToken: string): Promise<void> {
    await this.prisma.user.update({
      where: {
        id: userId,
      },
      data: {
        refreshToken: await argon2.hash(refreshToken),
      },
    });
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
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
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
  }

  /**
   * Validates a user's login credentials.
   * @param dto - The LoginDTO containing the user's email and password.
   * @returns A Promise that resolves to the User object if the credentials are valid.
   * @throws BadRequestException if the email or password is invalid.
   */
  async validateUser(dto: LoginDTO): Promise<User> {
    const { email, password } = dto;

    const user = await this.prisma.user.findFirst({
      where: { email },
    });

    if (!user) throw new UnauthorizedException('Invalid credentials');

    const match = await argon2.verify(user.password, password);

    if (!match) throw new UnauthorizedException('Invalid credentials');

    return user;
  }

  /**
   * Logs in a user and generates access and refresh tokens.
   * @param user - The user to log in.
   * @returns An object containing the generated access and refresh tokens.
   * @throws If an error occurs while generating tokens or updating the refresh token.
   */
  async login(user: User) {
    const tokens = await this.generateTokens(user.id as UUID, user.email);

    await this.updateRefreshToken(user.id as UUID, tokens.refreshToken);

    return tokens;
  }
}
