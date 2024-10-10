import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  InternalServerErrorException,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';

interface FormatExceptionMessage {
  status?: 'Failed';
  message: string;
  statusCode?: number;
}
interface Exceptions {
  BAD_REQUEST_EXCEPTION(data: FormatExceptionMessage): void;
  NOT_FOUND_EXCEPTION(data: FormatExceptionMessage): void;
  UNAUTHORIZED_EXCEPTION(data: FormatExceptionMessage): void;
  INTERNAL_ERROR_EXCEPTION(data: FormatExceptionMessage): void;
  FORBIDDEN_EXCEPTION(data: FormatExceptionMessage): void;
  CONFLICT_EXCEPTION(data: FormatExceptionMessage): void;
  INTERNAL_ERROR_EXCEPTION(data: FormatExceptionMessage): void;
}
@Injectable()
export class ExceptionsService implements Exceptions {
  constructor() {}
  // 400
  BAD_REQUEST_EXCEPTION(data: FormatExceptionMessage): void {
    throw new BadRequestException({
      status: 'Failed',
      statusCode: 400,
      ...data,
    });
  }
  // 404
  NOT_FOUND_EXCEPTION(data: FormatExceptionMessage): void {
    throw new NotFoundException({ status: 'Failed', statusCode: 404, ...data });
  }
  // 401
  UNAUTHORIZED_EXCEPTION(data: FormatExceptionMessage): void {
    throw new UnauthorizedException({
      status: 'Failed',
      statusCode: 401,
      ...data,
    });
  }
  // 403
  FORBIDDEN_EXCEPTION(data: FormatExceptionMessage): void {
    throw new ForbiddenException({
      status: 'Failed',
      statusCode: 403,
      ...data,
    });
  }
  // 409
  CONFLICT_EXCEPTION(data: FormatExceptionMessage): void {
    throw new ConflictException({ status: 'Failed', statusCode: 409, ...data });
  }
  // 500
  INTERNAL_ERROR_EXCEPTION(data: FormatExceptionMessage): void {
    throw new InternalServerErrorException({
      status: 'Failed',
      statusCode: 500,
      ...data,
    });
  }
}
