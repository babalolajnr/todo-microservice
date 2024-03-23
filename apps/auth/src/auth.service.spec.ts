import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { PrismaService } from '../prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';
import jwtConfiguration from '../config/jwt.config';
import { ConfigType } from '@nestjs/config';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { FileLogger } from '../logger/file.logger';
import { RegisterDTO } from './dto/register.dto';
import { UUID, randomUUID } from 'crypto';
import { EmailVerification, Role } from '@prisma/client';
import * as argon2 from 'argon2';
import { LoginDTO } from './dto/login.dto';
import { BadRequestException } from '@nestjs/common';

describe('AuthService', () => {
  let service: AuthService;
  let prismaService: PrismaService;
  let jwtService: JwtService;
  let jwtConfig: ConfigType<typeof jwtConfiguration>;
  let logger: FileLogger;
  let eventEmitter: EventEmitter2;

  /**
   * Generates a random string of characters.
   */
  const randomString = (): string =>
    Math.random().toString(36).substring(2, 15) +
    Math.random().toString(36).substring(2, 15);

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        PrismaService,
        JwtService,
        {
          provide: jwtConfiguration.KEY,
          useValue: jwtConfiguration,
        },
        FileLogger,
        EventEmitter2,
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    prismaService = module.get<PrismaService>(PrismaService);
    jwtService = module.get<JwtService>(JwtService);
    jwtConfig = module.get<ConfigType<typeof jwtConfiguration>>(
      jwtConfiguration.KEY,
    );
    logger = module.get<FileLogger>(FileLogger);
    eventEmitter = module.get<EventEmitter2>(EventEmitter2);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('register', () => {
    const dto: RegisterDTO = {
      name: 'Test User',
      email: 'test@gmail.com',
      address: 'Test Address',
      password: 'password',
      confirm_password: 'password',
    };

    const now = new Date();

    const mockUser = {
      id: randomUUID(),
      name: 'Test User',
      email: dto.email,
      address: dto.address,
      password: 'hashedPassword',
      isBlocked: false,
      createdAt: now,
      updatedAt: now,
      deletedAt: null,
      role: Role.USER,
      emailVerifiedAt: null,
      refreshToken: null,
    };

    it('should create a new user', async () => {
      const mockTokens = {
        jwtToken: randomString(),
        refreshToken: randomString(),
      };

      // Mock internal function calls
      jest.spyOn(argon2, 'hash').mockResolvedValue('hashedPassword');
      jest.spyOn(prismaService.user, 'create').mockResolvedValue(mockUser);
      jest.spyOn(service, 'generateTokens').mockResolvedValue(mockTokens);
      jest.spyOn(service, 'updateRefreshToken').mockResolvedValue();
      jest.spyOn(eventEmitter, 'emit').mockResolvedValue({} as never);

      const returnedUser = { ...mockUser, ...mockTokens };
      //   Remove deletedAt and password fields from returned user because they are not part of the returned object
      delete returnedUser.deletedAt;
      delete returnedUser.password;

      const user = await service.register(dto);

      expect(user).toEqual(returnedUser);
      expect(argon2.hash).toHaveBeenCalled();
      expect(argon2.hash).toHaveBeenCalledWith(dto.password);
      expect(prismaService.user.create).toHaveBeenCalledWith({
        data: {
          name: dto.name,
          email: dto.email,
          address: dto.address,
          password: 'hashedPassword',
        },
      });
      expect(service.generateTokens).toHaveBeenCalledWith(
        mockUser.id,
        mockUser.email,
      );
      expect(service.updateRefreshToken).toHaveBeenCalledWith(
        mockUser.id,
        mockTokens.refreshToken,
      );
      //   Expect event emitter to have been called with the event name and the event object
      expect(eventEmitter.emit).toHaveBeenCalledWith(
        'user.registered',
        expect.anything(),
      );
    });

    it('should throw an error if the user cannot be created', async () => {
      const error = new Error('Test Error');
      jest.spyOn(prismaService.user, 'create').mockRejectedValue(error);
      jest.spyOn(logger, 'error').mockResolvedValue({} as never);

      await expect(service.register(dto)).rejects.toThrow(error);
      expect(prismaService.user.create).toHaveBeenCalledWith({
        data: {
          name: dto.name,
          email: dto.email,
          address: dto.address,
          password: expect.any(String),
        },
      });
      expect(logger.error).toHaveBeenCalledWith(
        error.message,
        error.stack,
        'AuthService.register',
      );
    });

    it('should throw an error if the tokens cannot be generated', async () => {
      const error = new Error('Test Error');
      jest.spyOn(argon2, 'hash').mockResolvedValue('hashedPassword');
      jest.spyOn(prismaService.user, 'create').mockResolvedValue(mockUser);
      jest.spyOn(service, 'generateTokens').mockRejectedValue(error);
      jest.spyOn(logger, 'error').mockResolvedValue({} as never);

      await expect(service.register(dto)).rejects.toThrow(error);
      expect(argon2.hash).toHaveBeenCalled();
      expect(argon2.hash).toHaveBeenCalledWith(dto.password);
      expect(prismaService.user.create).toHaveBeenCalledWith({
        data: {
          name: dto.name,
          email: dto.email,
          address: dto.address,
          password: 'hashedPassword',
        },
      });
      expect(service.generateTokens).toHaveBeenCalledWith(
        mockUser.id,
        mockUser.email,
      );
      expect(logger.error).toHaveBeenCalledWith(
        error.message,
        error.stack,
        'AuthService.register',
      );
    });
  });

  describe('generateTokens', () => {
    const userId = randomUUID();
    const email = 'test@gmail.com';

    it('should generate a JWT token and a refresh token', async () => {
      const mockTokens = {
        jwtToken: randomString(),
        refreshToken: randomString(),
      };

      jest
        .spyOn(jwtService, 'signAsync')
        .mockResolvedValue(mockTokens.jwtToken);
      jest
        .spyOn(jwtService, 'signAsync')
        .mockResolvedValue(mockTokens.refreshToken);

      await service.generateTokens(userId, email);

      //   expect(tokens).toEqual(mockTokens);
      expect(jwtService.signAsync).toHaveBeenCalled();
      expect(jwtService.signAsync).toHaveBeenCalledWith(
        { email: email, sub: userId },
        {
          secret: jwtConfig.secret,
          expiresIn: jwtConfig.expiration,
        },
      );
      expect(jwtService.signAsync).toHaveBeenCalledWith(
        { email: email, sub: userId },
        {
          secret: jwtConfig.refreshSecret,
          expiresIn: jwtConfig.refreshExpiration,
        },
      );
    });
  });

  describe('updateRefreshToken', () => {
    const userId = randomUUID();
    const refreshToken = randomString();

    it('should update the refresh token', async () => {
      jest.spyOn(prismaService.user, 'update').mockResolvedValue({} as never);
      jest.spyOn(argon2, 'hash').mockResolvedValue(refreshToken);

      await service.updateRefreshToken(userId, refreshToken);

      expect(prismaService.user.update).toHaveBeenCalled();
      expect(prismaService.user.update).toHaveBeenCalledWith({
        where: { id: userId },
        data: { refreshToken },
      });
    });

    it('should throw an error if the refresh token cannot be updated', async () => {
      const error = new Error('Test Error');
      jest.spyOn(prismaService.user, 'update').mockRejectedValue(error);
      jest.spyOn(logger, 'error').mockResolvedValue({} as never);

      await expect(
        service.updateRefreshToken(userId, refreshToken),
      ).rejects.toThrow(error);
      expect(prismaService.user.update).toHaveBeenCalled();
      expect(prismaService.user.update).toHaveBeenCalledWith({
        where: { id: userId },
        data: { refreshToken: refreshToken },
      });
      expect(logger.error).toHaveBeenCalledWith(
        error.message,
        error.stack,
        'AuthService.updateRefreshToken',
      );
    });
  });

  describe('refreshTokens', () => {
    const now = new Date();
    const mockUser = {
      id: randomUUID(),
      name: 'Test User',
      email: 'test@gmail.com',
      address: 'Test address',
      password: 'hashedPassword',
      isBlocked: false,
      createdAt: now,
      updatedAt: now,
      deletedAt: null,
      role: Role.USER,
      emailVerifiedAt: null,
      refreshToken: null,
    };

    it('should refresh the tokens', async () => {
      const mockTokens = {
        jwtToken: randomString(),
        refreshToken: randomString(),
      };
      jest.spyOn(argon2, 'verify').mockResolvedValue(true);
      jest.spyOn(prismaService.user, 'findFirst').mockResolvedValue({
        ...mockUser,
        refreshToken: mockTokens.refreshToken,
      });
      jest.spyOn(service, 'generateTokens').mockResolvedValue(mockTokens);
      jest.spyOn(service, 'updateRefreshToken').mockResolvedValue();

      const tokens = await service.refreshTokens(
        mockUser.id,
        mockTokens.refreshToken,
      );

      expect(tokens).toEqual(mockTokens);
      expect(argon2.verify).toHaveBeenCalled();
      expect(argon2.verify).toHaveBeenCalledWith(
        mockTokens.refreshToken,
        mockTokens.refreshToken,
      );
      expect(prismaService.user.findFirst).toHaveBeenCalled();
      expect(prismaService.user.findFirst).toHaveBeenCalledWith({
        where: { id: mockUser.id, deletedAt: null },
      });
      expect(service.generateTokens).toHaveBeenCalled();
    });

    it('should throw an error if the user cannot be found', async () => {
      const error = new Error('Test Error');
      jest.spyOn(argon2, 'verify').mockResolvedValue(true);
      jest.spyOn(prismaService.user, 'findFirst').mockRejectedValue(error);
      jest.spyOn(logger, 'error').mockResolvedValue({} as never);

      await expect(
        service.refreshTokens(mockUser.id, randomString()),
      ).rejects.toThrow(error);
      expect(argon2.verify).toHaveBeenCalled();
      expect(argon2.verify).toHaveBeenCalledWith(
        expect.any(String),
        expect.any(String),
      );
      expect(prismaService.user.findFirst).toHaveBeenCalled();
      expect(prismaService.user.findFirst).toHaveBeenCalledWith({
        where: { id: mockUser.id, deletedAt: null },
      });
      expect(logger.error).toHaveBeenCalledWith(
        error.message,
        error.stack,
        'AuthService.refreshTokens',
      );
    });
  });

  describe('validateUser', () => {
    const now = new Date();
    const mockUser = {
      id: randomUUID(),
      name: 'Test User',
      email: 'test@gmail.com',
      address: 'Test address',
      password: 'hashedPassword',
      isBlocked: false,
      createdAt: now,
      updatedAt: now,
      deletedAt: null,
      role: Role.USER,
      emailVerifiedAt: null,
      refreshToken: null,
    };

    it('should validate the user', async () => {
      const mockTokens = {
        jwtToken: randomString(),
        refreshToken: randomString(),
      };
      jest.spyOn(argon2, 'verify').mockResolvedValue(true);
      jest.spyOn(prismaService.user, 'findFirst').mockResolvedValue({
        ...mockUser,
        refreshToken: mockTokens.refreshToken,
      });

      const dto: LoginDTO = {
        email: mockUser.email,
        password: mockUser.password,
      };

      const user = await service.validateUser(dto);

      expect(user).toEqual({
        ...mockUser,
        refreshToken: mockTokens.refreshToken,
      });
      expect(argon2.verify).toHaveBeenCalled();
      expect(argon2.verify).toHaveBeenCalledWith(
        mockUser.password,
        mockUser.password,
      );
      expect(prismaService.user.findFirst).toHaveBeenCalled();
      expect(prismaService.user.findFirst).toHaveBeenCalledWith({
        where: { email: mockUser.email, deletedAt: null },
      });
    });

    it('should throw an error if the user cannot be found', async () => {
      const error = new Error('Test Error');
      jest.spyOn(argon2, 'verify').mockResolvedValue(true);
      jest.spyOn(prismaService.user, 'findFirst').mockRejectedValue(error);
      jest.spyOn(logger, 'error').mockResolvedValue({} as never);

      const dto: LoginDTO = {
        email: mockUser.email,
        password: mockUser.password,
      };

      await expect(service.validateUser(dto)).rejects.toThrow(error);
      expect(argon2.verify).toHaveBeenCalled();
      expect(argon2.verify).toHaveBeenCalledWith(
        mockUser.password,
        mockUser.password,
      );
      expect(prismaService.user.findFirst).toHaveBeenCalled();
      expect(prismaService.user.findFirst).toHaveBeenCalledWith({
        where: { email: mockUser.email, deletedAt: null },
      });
      expect(logger.error).toHaveBeenCalledWith(
        error.message,
        error.stack,
        'AuthService.validateUser',
      );
    });
  });

  describe('login', () => {
    const now = new Date();
    const mockUser = {
      id: randomUUID(),
      name: 'Test User',
      email: 'test@gmail.com',
      address: 'Test address',
      password: 'hashedPassword',
      isBlocked: false,
      createdAt: now,
      updatedAt: now,
      deletedAt: null,
      role: Role.USER,
      emailVerifiedAt: null,
      refreshToken: null,
    };

    it('should login the user', async () => {
      const mockTokens = {
        jwtToken: randomString(),
        refreshToken: randomString(),
      };
      jest.spyOn(service, 'generateTokens').mockResolvedValue(mockTokens);
      jest.spyOn(service, 'updateRefreshToken').mockResolvedValue();

      const tokens = await service.login(mockUser);

      expect(tokens).toEqual(mockTokens);
      expect(service.generateTokens).toHaveBeenCalled();
      expect(service.generateTokens).toHaveBeenCalledWith(
        mockUser.id,
        mockUser.email,
      );
      expect(service.updateRefreshToken).toHaveBeenCalled();
      expect(service.updateRefreshToken).toHaveBeenCalledWith(
        mockUser.id,
        mockTokens.refreshToken,
      );
    });

    it('should throw an error if the tokens cannot be generated', async () => {
      const error = new Error('Test Error');
      jest.spyOn(service, 'generateTokens').mockRejectedValue(error);
      jest.spyOn(logger, 'error').mockResolvedValue({} as never);

      await expect(service.login(mockUser)).rejects.toThrow(error);
      expect(service.generateTokens).toHaveBeenCalled();
      expect(service.generateTokens).toHaveBeenCalledWith(
        mockUser.id,
        mockUser.email,
      );
      expect(logger.error).toHaveBeenCalledWith(
        error.message,
        error.stack,
        'AuthService.login',
      );
    });
  });

  describe('verifyEmail', () => {
    const now = new Date();
    const mockUser = {
      id: randomUUID(),
      name: 'Test User',
      email: 'test@gmail.com',
      address: 'Test address',
      password: 'hashedPassword',
      isBlocked: false,
      createdAt: now,
      updatedAt: now,
      deletedAt: null,
      role: Role.USER,
      emailVerifiedAt: null,
      refreshToken: null,
    };

    it('should verify the email', async () => {
      const mockVerification: EmailVerification = {
        id: randomUUID() as UUID,
        userId: mockUser.id,
        token: randomString(),
        expiresAt: new Date(),
        createdAt: now,
        updatedAt: now,
        deletedAt: null,
      };
      jest
        .spyOn(prismaService.emailVerification, 'findFirst')
        .mockResolvedValue(mockVerification);
      jest.spyOn(prismaService.user, 'update').mockResolvedValue(mockUser);
      jest
        .spyOn(prismaService.emailVerification, 'update')
        .mockResolvedValue({} as never);

      await service.verifyEmail(mockVerification.token);

      expect(prismaService.emailVerification.findFirst).toHaveBeenCalled();
      expect(prismaService.emailVerification.findFirst).toHaveBeenCalledWith({
        where: {
          token: mockVerification.token,
          expiresAt: { gte: expect.any(Date) },
        },
      });
      expect(prismaService.user.update).toHaveBeenCalled();
      expect(prismaService.user.update).toHaveBeenCalledWith({
        where: { id: mockUser.id },
        data: { emailVerifiedAt: expect.any(Date) },
      });
    });

    it('should throw an error if the token is invalid', async () => {
      const error = new BadRequestException('Invalid Token');
      jest
        .spyOn(prismaService.emailVerification, 'findFirst')
        .mockResolvedValue(null);
      jest.spyOn(logger, 'error').mockResolvedValue({} as never);

      await expect(service.verifyEmail(randomString())).rejects.toThrow(error);
      expect(prismaService.emailVerification.findFirst).toHaveBeenCalled();
      expect(prismaService.emailVerification.findFirst).toHaveBeenCalledWith({
        where: {
          token: expect.any(String),
          expiresAt: { gte: expect.any(Date) },
        },
      });
    });
  });
});
