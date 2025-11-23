import 'dotenv/config';

import { config } from '@core/config/app.config';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import express from 'express';

import { errorHandler } from './v1/middlewares/error-handler.middleware';
import passport from './v1/middlewares/passport.middleware';
import routes from './v1/routes';

const app = express();
const BASE_PATH = config.BASE_PATH;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (like mobile apps or curl requests)
      if (!origin) return callback(null, true);

      // Check if the origin is in the allowed list
      if (config.FRONTEND_ORIGINS.includes(origin)) {
        return callback(null, true);
      }

      return callback(new Error('Not allowed by CORS'));
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin'],
    exposedHeaders: ['X-Total-Count', 'X-Page-Count'],
  })
);

app.use(cookieParser());
app.use(passport.initialize());

app.use(BASE_PATH, routes);

app.use(errorHandler);

app.listen(config.PORT, async () => {
  // eslint-disable-next-line no-console
  console.log(`Server listening on port ${config.PORT} in ${config.NODE_ENV}.`);
});
