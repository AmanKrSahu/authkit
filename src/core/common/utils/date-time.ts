import { add } from 'date-fns';

export const fiveMinutesFromNow = (): Date => new Date(Date.now() + 5 * 60 * 1000);

export const oneHourFromNow = (): Date => new Date(Date.now() + 60 * 60 * 1000);

export const oneDayFromNow = (): Date => new Date(Date.now() + 1 * 24 * 60 * 60 * 1000);

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
