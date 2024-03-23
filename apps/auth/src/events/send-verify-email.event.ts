import { User } from '@prisma/client';

export default class SendVerifyEmailEvent {
  constructor(public readonly user: User) {}
}
