import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { config } from '@core/config/app.config';
import swaggerJsdoc from 'swagger-jsdoc';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Pre-define the static spec path (generated at build time)
const staticSpecPath = path.resolve(__dirname, '../../../dist/swagger.json');

const options: swaggerJsdoc.Options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'AuthKit APIs Documentation',
      version: '1.0.0',
      description: 'API documentation for AuthKit authentication and authorization.',
    },
    servers: [
      {
        url: `${config.BASE_PATH}`,
        description: `API Server (${config.NODE_ENV})`,
      },
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
        },
        csrfAuth: {
          type: 'apiKey',
          in: 'header',
          name: 'x-csrf-token',
        },
        basicAuth: {
          type: 'http',
          scheme: 'basic',
        },
        googleOAuth: {
          type: 'oauth2',
          flows: {
            authorizationCode: {
              authorizationUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
              tokenUrl: 'https://oauth2.googleapis.com/token',
              scopes: {
                openid: 'OpenID Connect',
                profile: 'User profile Information',
                email: 'User Email Information',
              },
            },
          },
        },
      },
    },
    security: [
      {
        bearerAuth: [],
        csrfAuth: [],
      },
    ],
  },
  apis: ['./src/swagger/*.ts', './src/api/v1/routes/*.ts'],
};

export const swaggerSpec =
  config.NODE_ENV === 'production' && fs.existsSync(staticSpecPath)
    ? JSON.parse(fs.readFileSync(staticSpecPath, 'utf8'))
    : swaggerJsdoc(options);
