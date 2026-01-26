import type { PassportStatic } from 'passport';
import passport from 'passport';
import type { StrategyOptionsWithRequest } from 'passport-jwt';
import { ExtractJwt, Strategy as JwtStrategy } from 'passport-jwt';

import { config } from '../../config/app.config';
import prisma from '../../database/prisma';
import { ErrorCodeEnum } from '../enums/error-code.enum';
import { UnauthorizedException } from '../utils/app-error';
import { ONE_DAY } from '../utils/date-time';
import { getCache, setCache } from '../utils/redis-helpers';

interface JwtPayload {
  userId: string;
  sessionId: string;
}

const options: StrategyOptionsWithRequest = {
  jwtFromRequest: ExtractJwt.fromExtractors([
    req => {
      const accessToken = req.cookies.accessToken;

      if (!accessToken) {
        throw new UnauthorizedException(
          'Unauthorized access token',
          ErrorCodeEnum.AUTH_TOKEN_NOT_FOUND
        );
      }

      return accessToken;
    },
  ]),
  secretOrKey: config.JWT.SECRET,
  audience: ['user'],
  algorithms: ['HS256'],
  passReqToCallback: true,
};

export const setupJwtStrategy = (passport: PassportStatic) => {
  passport.use(
    new JwtStrategy(options, async (req, payload: JwtPayload, done) => {
      try {
        // 1. Check Redis Cache
        const cachedUser = await getCache(`session:${payload.sessionId}`);
        if (cachedUser) {
          req.sessionId = payload.sessionId;
          return done(null, JSON.parse(cachedUser));
        }

        // 2. Fallback to DB
        const user = await prisma.user.findUnique({
          where: { id: payload.userId },
          include: { sessions: true },
        });

        if (!user) {
          return done(null, false);
        }

        const session = user.sessions.find(s => s.id === payload.sessionId);
        if (!session || session.expiresAt < new Date() || session.isRevoked) {
          return done(null, false);
        }

        req.sessionId = payload.sessionId;

        // 3. Cache the result (User object)
        // We sanitize/optimize what we cache to avoid sensitive data leaks if possible,
        // but current implementation returns full user object. Structure should match.
        // We will cache for 1 day or session expiry, whichever is less/appropriate.
        // For simplicity, 1 day sliding window.
        await setCache(`session:${payload.sessionId}`, JSON.stringify(user), ONE_DAY);

        return done(null, user);
      } catch (error) {
        return done(error, false);
      }
    })
  );
};

export const authenticateJWT = passport.authenticate('jwt', { session: false });
