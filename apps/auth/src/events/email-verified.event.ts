import { User } from '@prisma/client';

export default class EmailVerifiedEvent {
  constructor(public readonly user: User) {}
}
