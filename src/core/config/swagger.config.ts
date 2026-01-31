import { config } from '@core/config/app.config';
import swaggerJsdoc from 'swagger-jsdoc';

const options: swaggerJsdoc.Options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'AuthKit API Documentation',
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
      },
    },
    security: [
      {
        bearerAuth: [],
        csrfAuth: [],
      },
    ],
  },
  apis: ['./src/api/v1/controllers/*.ts', './src/api/v1/routes/*.ts'],
};

export const swaggerSpec = swaggerJsdoc(options);
