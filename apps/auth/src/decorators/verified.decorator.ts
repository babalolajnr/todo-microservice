import { SetMetadata } from '@nestjs/common';

export const VERIFIED_KEY = 'verified';

/**
 * Marks a route handler or controller method as requiring verification.
 * This decorator can be used to enforce that only verified users can access the decorated route.
 */
export const Verified = () => SetMetadata(VERIFIED_KEY, true);
