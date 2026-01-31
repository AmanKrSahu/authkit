import 'dotenv/config';

import { logger } from '@core/common/utils/logger';
import { config } from '@core/config/app.config';
import { swaggerSpec } from '@core/config/swagger.config';
import redis from '@core/database/redis';
import compression from 'compression';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import express from 'express';
import helmet from 'helmet';
import swaggerUi from 'swagger-ui-express';

import { errorHandler } from './v1/middlewares/error-handler.middleware';
import passport from './v1/middlewares/passport.middleware';
import { globalRateLimiter } from './v1/middlewares/rate-limiter.middleware';
import routes from './v1/routes';

const app = express();
const BASE_PATH = config.BASE_PATH;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(helmet());
app.use(compression());
app.use(globalRateLimiter);

app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (like mobile apps or curl requests)
      if (!origin) return callback(null, true);

      // Check if the origin is in the allowed list
      if (
        config.FRONTEND_ORIGINS.includes(origin) ||
        origin.includes(config.DOMAIN_URL) ||
        origin.includes(`http://localhost:${config.PORT}`)
      ) {
        return callback(null, true);
      }

      return callback(new Error('Not allowed by CORS'));
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'X-Requested-With',
      'Accept',
      'Origin',
      'x-csrf-token',
    ],
    exposedHeaders: ['X-Total-Count', 'X-Page-Count'],
  })
);

app.use(cookieParser());
app.use(passport.initialize());

app.use(BASE_PATH, routes);

app.use('/docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

app.use(errorHandler);

app.listen(config.PORT, async () => {
  logger.info(`Server listening on port ${config.PORT} in ${config.NODE_ENV}`);

  try {
    await redis.ping();
    logger.info(`Redis connected on port ${config.REDIS.PORT} in ${config.NODE_ENV}`);
  } catch (error) {
    logger.error('Redis connection failed:', error as Error);
  }
});
