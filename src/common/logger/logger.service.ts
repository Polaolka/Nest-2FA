import { Injectable, Logger, Scope } from '@nestjs/common';
import * as chalk from 'chalk';
@Injectable({ scope: Scope.TRANSIENT })
export class LoggerService extends Logger {
  debug(context: string, message: string) {
    if (process.env.NODE_ENV !== 'production') {
      super.debug(`[DEBUG]: ${message}`, context);
    }
  }

  log(context: string, message: string) {
    super.log(chalk.blueBright(`[INFO]: ${message}`), context);
  }
  error(context: string, message: string) {
    super.error(`[ERROR]: ${message}`, context);
  }
  warn(context: string, message: string) {
    super.warn(chalk.bgYellowBright(`[WARN]: ${message}`), context);
  }
  verbose(context: string, message: string) {
    if (process.env.NODE_ENV !== 'production') {
      super.verbose(`[VERBOSE]: ${message}`, context);
    }
  }
}
