import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { User } from '@prisma/client';

/**
 * A guard that checks if the user's email has been verified.
 */
@Injectable()
export class VerifiedGuard implements CanActivate {
  constructor() {}

  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    const { user } = context.switchToHttp().getRequest();

    // Skip is there is no authenticated user
    if (!user) {
      return true;
    }

    const verified = (user as User).emailVerifiedAt !== null;
    if (!verified) {
      throw new ForbiddenException('Email not verified');
    }

    return verified;
  }
}
