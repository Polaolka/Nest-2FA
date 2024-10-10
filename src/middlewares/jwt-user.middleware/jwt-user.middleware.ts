import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import * as jwt from 'jsonwebtoken';

interface ExtendedRequest extends Request {
  user?: any; // Тип даних користувача
}

@Injectable()
export class JwtUserMiddleware implements NestMiddleware {
  use(req: ExtendedRequest, res: Response, next: NextFunction) {
    // Використовуємо розширений тип Request
    const token = req.headers.authorization?.split(' ')[1];
    if (token) {
      try {
        const decoded: any = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded; // Додаємо дані користувача до об'єкта запиту
      } catch (err) {
        // Обробляємо помилку розшифровки токену
        console.error(err);
      }
    }
    next();
  }
}
