import type { PassportStatic } from 'passport';
import passport from 'passport';
import type { StrategyOptionsWithRequest } from 'passport-jwt';
import { ExtractJwt, Strategy as JwtStrategy } from 'passport-jwt';

import { config } from '../../config/app.config';
import prisma from '../../database/prisma';
import { ONE_DAY } from '../utils/date-time';
import { deleteCache, getCache, setCache } from '../utils/redis-helpers';

interface JwtPayload {
  userId: string;
  sessionId: string;
}

const options: StrategyOptionsWithRequest = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
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
        const cachedSession = await getCache(`session:${payload.sessionId}`);
        if (cachedSession) {
          const session = JSON.parse(cachedSession);
          const isExpired = new Date(session.expiresAt).getTime() < Date.now();

          if (session && !session.isRevoked && !isExpired && session.userId === payload.userId) {
            req.sessionId = payload.sessionId;
            return done(null, session.user);
          }

          // Cache is invalid or expired, clear it
          await deleteCache(`session:${payload.sessionId}`);
        }

        // 2. Fallback to DB
        const session = await prisma.session.findUnique({
          where: { id: payload.sessionId },
          include: {
            user: {
              select: {
                id: true,
                email: true,
                role: true,
                name: true,
                enable2FA: true,
              },
            },
          },
        });

        if (
          !session ||
          session.userId !== payload.userId ||
          session.isRevoked ||
          session.expiresAt < new Date()
        ) {
          return done(null, false);
        }

        req.sessionId = payload.sessionId;

        // 3. Cache the result (Sanitized minimal session object to save Redis memory)
        const remainingTimeMs = new Date(session.expiresAt).getTime() - Date.now();
        const ttlSeconds = Math.max(Math.floor(remainingTimeMs / 1000), 0);
        const cacheTtl = Math.min(ttlSeconds, ONE_DAY);

        const minimizedSession = {
          userId: session.userId,
          expiresAt: session.expiresAt,
          isRevoked: session.isRevoked,
          user: session.user,
        };

        await setCache(`session:${payload.sessionId}`, JSON.stringify(minimizedSession), cacheTtl);

        return done(null, session.user);
      } catch (error) {
        return done(error, false);
      }
    })
  );
};

export const authenticateJWT = passport.authenticate('jwt', { session: false });
