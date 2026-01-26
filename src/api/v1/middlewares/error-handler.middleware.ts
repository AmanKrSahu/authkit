import { ErrorCodeEnum } from '@core/common/enums/error-code.enum.js';
import { AppError } from '@core/common/utils/app-error.js';
import { HTTPSTATUS } from '@core/config/http.config.js';
import type { ErrorRequestHandler, Response } from 'express';
import { ZodError } from 'zod';

const formatZodError = (response: Response, error: ZodError) => {
  const errors = error?.issues?.map(error_ => ({
    field: error_.path.join('.'),
    message: error_.message,
  }));
  return response.status(HTTPSTATUS.BAD_REQUEST).json({
    message: 'Validation failed',
    errors: errors,
    errorCode: ErrorCodeEnum.VALIDATION_ERROR,
  });
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const errorHandler: ErrorRequestHandler = (error, request, response, _next): any => {
  // eslint-disable-next-line no-console
  console.error(`Error Occured on PATH: ${request.path}`, error);

  if (error instanceof SyntaxError) {
    return response.status(HTTPSTATUS.BAD_REQUEST).json({
      message: 'Invalid JSON format. Please check your request body.',
    });
  }

  if (error instanceof AppError) {
    return response.status(error.statusCode).json({
      message: error.message,
      errorCode: error.errorCode,
    });
  }

  if (error instanceof ZodError) {
    return formatZodError(response, error);
  }

  return response.status(HTTPSTATUS.INTERNAL_SERVER_ERROR).json({
    message: 'Internal Server Error',
    error: error?.message ?? 'Unknow error occurred',
  });
};
