import 'dotenv/config';

import { isAllowedOrigin } from '@core/common/utils/url.util';
import { config } from '@core/config/app.config';
import { swaggerSpec } from '@core/config/swagger.config';
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

if (config.TRUST_PROXY === 'true') {
  app.set('trust proxy', true);
} else if (config.TRUST_PROXY === 'false') {
  app.set('trust proxy', false);
} else if (config.TRUST_PROXY) {
  const hops = Number(config.TRUST_PROXY);
  app.set('trust proxy', Number.isNaN(hops) ? config.TRUST_PROXY : hops);
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        ...helmet.contentSecurityPolicy.getDefaultDirectives(),
        'script-src': ["'self'"],
        'style-src': ["'self'"],
      },
    },
  })
);
app.use(compression({ threshold: 1024 }));
app.use(globalRateLimiter);

app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (like mobile apps or curl requests)
      if (!origin) return callback(null, true);

      // Check if the origin is allowed by the security policy
      if (isAllowedOrigin(origin)) {
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

if (config.NODE_ENV !== 'production') {
  app.use(
    '/docs',
    helmet({
      contentSecurityPolicy: {
        directives: {
          ...helmet.contentSecurityPolicy.getDefaultDirectives(),
          'script-src': ["'self'", "'unsafe-inline'"],
          'style-src': ["'self'", "'unsafe-inline'"],
        },
      },
    }),
    swaggerUi.serve,
    swaggerUi.setup(swaggerSpec)
  );
}

app.use(errorHandler);

export { app };
