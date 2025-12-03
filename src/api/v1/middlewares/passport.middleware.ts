import { setupGoogleStrategy } from '@core/common/strategies/google.strategy';
import { setupJwtStrategy } from '@core/common/strategies/jwt.strategy';
import passport from 'passport';

const intializePassport = () => {
  setupJwtStrategy(passport);
  setupGoogleStrategy(passport);
};

intializePassport();

export { default } from 'passport';
