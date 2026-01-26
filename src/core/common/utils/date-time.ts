import { add } from 'date-fns';

export const sevenDaysFromNow = (): Date => new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

export const calculateExpirationDate = (expiresIn: string = '15m'): Date => {
  // Match number + unit (m = minutes, h = hours, d = days)
  const match = expiresIn.match(/^(\d+)([mhd])$/);

  if (!match) throw new Error('Invalid format. Use "15m", "1h", or "2d".');

  const [, value, unit] = match;
  const expirationDate = new Date();

  // Check the unit and apply accordingly
  switch (unit) {
    case 'm': {
      // minutes
      return add(expirationDate, { minutes: Number.parseInt(value) });
    }
    case 'h': {
      // hours
      return add(expirationDate, { hours: Number.parseInt(value) });
    }
    case 'd': {
      // days
      return add(expirationDate, { days: Number.parseInt(value) });
    }
    default: {
      throw new Error('Invalid unit. Use "m", "h", or "d".');
    }
  }
};

export const formatDate = (date: Date): string => {
  return date.toLocaleString('en-US', {
    weekday: 'long',
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    timeZoneName: 'short',
  });
};

// Seconds
export const ONE_MINUTE = 60;
export const FIVE_MINUTES = 60 * 5;
export const ONE_HOUR = 60 * 60;
export const ONE_DAY = 60 * 60 * 24;
export const SEVEN_DAYS = 60 * 60 * 24 * 7;
export const THIRTY_DAYS = 60 * 60 * 24 * 30;

// Milliseconds
export const ONE_SECOND_IN_MS = 1000;
export const ONE_MINUTE_IN_MS = 60 * 1000;
export const FIFTEEN_MINUTES_IN_MS = 15 * 60 * 1000;
export const ONE_HOUR_IN_MS = 60 * 60 * 1000;
