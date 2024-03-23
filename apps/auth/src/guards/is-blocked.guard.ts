import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { User } from '@prisma/client';
import { Observable } from 'rxjs';

@Injectable()
export class IsBlockedGuard implements CanActivate {
  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    const { user } = context.switchToHttp().getRequest();

    // Skip is there is no authenticated user
    if (!user) {
      return true;
    }

    const blocked = (user as User).isBlocked;

    if (blocked) {
      throw new ForbiddenException('Account is suspended.');
    }

    return true;
  }
}
