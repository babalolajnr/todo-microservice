import {
  ValidationArguments,
  ValidationOptions,
  ValidatorConstraint,
  ValidatorConstraintInterface,
  equals,
  registerDecorator,
} from 'class-validator';

/**
 * Decorator that checks if the value of the given property matches the value of the property with the same name in the object.
 * @param property - The name of the property to match against.
 * @param options - Validation options.
 * @returns A decorator function that registers the `MatchConstraint` validator.
 */
export function Match<T>(property: keyof T, options?: ValidationOptions) {
  return (object: unknown, propertyName: string) =>
    registerDecorator({
      // eslint-disable-next-line @typescript-eslint/ban-types
      target: object?.constructor as Function,
      propertyName,
      options,
      constraints: [property],
      validator: MatchConstraint,
    });
}

/**
 * Validates if the given value matches the specified constraint.
 * @param value The value to be validated.
 * @param validationArguments The validation arguments.
 * @returns A boolean indicating whether the value matches the constraint or not.
 */
@ValidatorConstraint({ name: 'Match' })
export class MatchConstraint implements ValidatorConstraintInterface {
  validate(
    value: any,
    validationArguments?: ValidationArguments,
  ): boolean | Promise<boolean> {
    const matchFieldName = validationArguments?.constraints[0];
    const matchFieldValue = (validationArguments?.object as any)[
      matchFieldName
    ];

    if (!matchFieldValue) {
      throw new Error(`No matching field found for ${matchFieldName}`);
    }

    return equals(matchFieldValue, value);
  }

  defaultMessage?(validationArguments?: ValidationArguments): string {
    return `${validationArguments?.constraints[0]} and ${validationArguments?.property} does not match`;
  }
}
