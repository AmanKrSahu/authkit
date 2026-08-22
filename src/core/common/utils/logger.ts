import 'winston-daily-rotate-file';

import { createLogger, format, type transport, transports } from 'winston';

import { config } from '../../config/app.config';

const { combine, timestamp, printf, colorize, errors, splat, json } = format;

// Helper log format for console in non-production environments
const devLogFormat = printf(({ level, message, timestamp, stack, ...metadata }) => {
  let msg = `${timestamp} [${level}] : ${stack ?? message} `;

  // Avoid unnecessary JSON.stringify overhead if no metadata is present
  if (Object.keys(metadata).length > 0) {
    msg += JSON.stringify(metadata);
  }
  return msg;
});

const isProd = config.NODE_ENV === 'production';
const isTest = config.NODE_ENV === 'test' || process.env.VITEST === 'true';
const logFilename = isTest ? '%DATE%-tests.log' : '%DATE%-app.log';

const activeTransports: transport[] = [];

if (isProd) {
  // In production, log to stdout only to let the container orchestrator collect it
  activeTransports.push(
    new transports.Console({
      format: combine(
        timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        errors({ stack: true }),
        splat(),
        json()
      ),
    })
  );
} else if (isTest) {
  // In test mode, write strictly to logs/%DATE%-tests.log to keep the terminal console clean
  activeTransports.push(
    new transports.DailyRotateFile({
      dirname: 'logs',
      filename: logFilename,
      datePattern: 'YYYY-MM-DD',
      maxSize: '20m',
      maxFiles: '14d',
      format: combine(
        timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        errors({ stack: true }),
        splat(),
        devLogFormat
      ),
    })
  );
} else {
  // In development, log to both console and daily rotating file for local debugging
  activeTransports.push(
    new transports.Console({
      format: combine(
        timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        colorize(),
        errors({ stack: true }),
        splat(),
        devLogFormat
      ),
    }),
    new transports.DailyRotateFile({
      dirname: 'logs',
      filename: logFilename,
      datePattern: 'YYYY-MM-DD',
      maxSize: '20m',
      maxFiles: '14d',
      format: combine(
        timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        errors({ stack: true }),
        splat(),
        devLogFormat
      ),
    })
  );
}

export const logger = createLogger({
  level: isProd ? 'info' : 'debug',
  transports: activeTransports,
});
