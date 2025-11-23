import type { NextFunction, Request, Response } from 'express';

function isPromise(value: unknown): value is Promise<unknown> {
  return (
    value !== null &&
    typeof value === 'object' &&
    'then' in value &&
    typeof (value as Promise<unknown>).then === 'function' &&
    'catch' in value &&
    typeof (value as Promise<unknown>).catch === 'function'
  );
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function AsyncHandler(_target: any, propertyKey: string) {
  const originalDescriptor = Object.getOwnPropertyDescriptor(_target, propertyKey);

  if (originalDescriptor && typeof originalDescriptor.value === 'function') {
    const originalMethod = originalDescriptor.value;

    Object.defineProperty(_target, propertyKey, {
      value: function (req: Request, res: Response, next: NextFunction) {
        try {
          const result = Reflect.apply(originalMethod, this, [req, res, next]);

          if (isPromise(result)) {
            return result.catch((error: unknown) => next(error));
          }

          return result;
        } catch (error) {
          return next(error);
        }
      },
      writable: true,
      configurable: true,
      enumerable: true,
    });
  }
}
