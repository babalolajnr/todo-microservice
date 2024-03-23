import { Prisma, PrismaClient } from '@prisma/client';
import { registerDecorator, ValidationOptions } from 'class-validator';

/**
 * Check if the value is unique for the given model
 * @param model
 * @param validationOptions
 * @returns
 */
export function IsUnique(
  model: Prisma.ModelName,
  validationOptions?: ValidationOptions,
) {
  return function (object: object, propertyName: string) {
    registerDecorator({
      name: 'IsUnique',
      target: object.constructor,
      propertyName: propertyName,
      constraints: [model],
      options: validationOptions,
      validator: {
        async validate(value: any): Promise<boolean> {
          try {
            const prismaClient = new PrismaClient();

            // eslint-disable-next-line @typescript-eslint/ban-ts-comment
            // @ts-ignore
            const prismaModel = prismaClient[model];

            const record = await prismaModel.findFirst({
              where: { [propertyName]: value },
            });

            return record === null ? true : false;
          } catch (error: any) {
            return false;
          }
        },
      },
    });
  };
}
