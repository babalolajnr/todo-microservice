import { SetMetadata } from '@nestjs/common';
import { Role } from '@prisma/client';

export const ROLE_KEY = 'role';
/**
 * Marks a route handler or controller method as requiring a role.
 * @param {...Role[]} role - The roles to be assigned to the resource or endpoint.
 */
export const Roles = (...role: Role[]) => SetMetadata(ROLE_KEY, role);
