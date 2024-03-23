import { User } from '@prisma/client';

export default class UserRegisteredEvent {
  constructor(public readonly user: User) {}
}
