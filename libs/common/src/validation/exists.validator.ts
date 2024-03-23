import { Prisma, PrismaClient } from '@prisma/client';
import { registerDecorator, ValidationOptions } from 'class-validator';

/**
 * Check if value exists on the given model
 * @param model
 * @param validationOptions
 * @returns
 */
export function Exists({
  model,
  field,
  validationOptions,
}: {
  model: Prisma.ModelName;
  field?: string;
  validationOptions?: ValidationOptions;
}) {
  return function (object: object, propertyName: string) {
    registerDecorator({
      name: 'Exists',
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

            const column = field ?? propertyName;

            const record = await prismaModel.findFirst({
              where: { [column]: value },
            });

            return record ? true : false;
          } catch (error: any) {
            return false;
          }
        },
      },
    });
  };
}
