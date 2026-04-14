import { add } from 'date-fns';

export const calculateExpirationDate = (expiresInSeconds: number = FIFTEEN_MINUTES): Date => {
  return add(new Date(), { seconds: expiresInSeconds });
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
export const TEN_MINUTES = 60 * 10;
export const FIFTEEN_MINUTES = 60 * 15;
export const ONE_HOUR = 60 * 60;
export const ONE_DAY = 60 * 60 * 24;
export const SEVEN_DAYS = 60 * 60 * 24 * 7;
export const THIRTY_DAYS = 60 * 60 * 24 * 30;

// Milliseconds
export const ONE_SECOND_IN_MS = 1000;
export const ONE_MINUTE_IN_MS = 60 * 1000;
export const TEN_MINUTES_IN_MS = 10 * 60 * 1000;
export const FIFTEEN_MINUTES_IN_MS = 15 * 60 * 1000;
export const ONE_HOUR_IN_MS = 60 * 60 * 1000;
