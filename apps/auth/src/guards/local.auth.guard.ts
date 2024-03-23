import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

/**
 * This guard is used to protect routes that require local authentication.
 * It extends the built-in AuthGuard and specifies the 'local' strategy.
 */
@Injectable()
export class LocalAuthGuard extends AuthGuard('local') {}
