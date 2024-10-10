import { PipeTransform, Injectable, ArgumentMetadata } from '@nestjs/common';
import { plainToClass } from 'class-transformer';
import { validate } from 'class-validator';
import { ValidationException } from '../exceptions/validation.exceptions';

@Injectable()
export class ValidationPipe implements PipeTransform<unknown> {
  async transform(
    value: unknown,
    metadata: ArgumentMetadata,
  ): Promise<unknown> {
    if (!metadata.metatype || !this.toValidate(metadata.metatype)) {
      return value; // Якщо тип не потребує валідації, просто повертаємо значення
    }
    const obj = plainToClass(metadata.metatype, value);

    const errors = await validate(obj);

    if (errors.length) {
      const messages = errors.map(
        (err) =>
          `${err.property} - ${Object.values(err.constraints).join(', ')}`,
      );

      throw new ValidationException(messages);
    }
    return value;
  }
  private toValidate(metatype: unknown): boolean {
    const types: (new (...args: any[]) => any)[] = [
      String,
      Boolean,
      Number,
      Array,
      Object,
    ];
    return !types.includes(metatype as new (...args: any[]) => any);
  }
}
