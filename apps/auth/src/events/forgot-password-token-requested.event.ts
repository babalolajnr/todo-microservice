import { User } from '@prisma/client';

export default class ForgotPasswordTokenRequestedEvent {
  constructor(public readonly user: User) {}
}
