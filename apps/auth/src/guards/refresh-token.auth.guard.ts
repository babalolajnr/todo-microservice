import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

/**
 * This guard extends the built-in AuthGuard and is used to protect routes that require a valid refresh token.
 * If the user has a valid refresh token, the route is allowed. Otherwise, the user is redirected to the login page.
 */
@Injectable()
export class RefreshTokenGuard extends AuthGuard('refresh-token') {}
