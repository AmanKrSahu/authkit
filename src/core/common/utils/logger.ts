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

// Configure active transports dynamically based on the environment
const activeTransports: transport[] = isProd
  ? [
      // In production, log to stdout only to let the container orchestrator collect it
      // Output clean, non-colorized structured JSON to avoid parsing overhead and escape pollution
      new transports.Console({
        format: combine(
          timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
          errors({ stack: true }),
          splat(),
          json()
        ),
      }),
    ]
  : [
      // In development, log to both console and daily rotating file for local debugging
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
        filename: '%DATE%-app.log',
        datePattern: 'YYYY-MM-DD',
        maxSize: '20m',
        maxFiles: '14d',
        format: combine(
          timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
          errors({ stack: true }),
          splat(),
          devLogFormat
        ),
      }),
    ];

export const logger = createLogger({
  level: isProd ? 'info' : 'debug',
  transports: activeTransports,
});
