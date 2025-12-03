import { config } from '@core/config/app.config';
import type { PassportStatic } from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';

export const setupGoogleStrategy = (passport: PassportStatic) => {
  passport.use(
    new GoogleStrategy(
      {
        clientID: config.GOOGLE_CLIENT_ID,
        clientSecret: config.GOOGLE_CLIENT_SECRET,
        callbackURL: config.GOOGLE_CALLBACK_URL,
      },
      async (_accessToken, _refreshToken, profile, done) => {
        try {
          return done(null, profile);
        } catch (error) {
          return done(error, false);
        }
      }
    )
  );
};
