# =========================================
# Stage 1: Base
# =========================================
FROM node:22-alpine AS base
ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"
RUN corepack enable

# =========================================
# Stage 2: Dependencies
# =========================================
FROM base AS deps
WORKDIR /app

# System deps for native modules
RUN apk add --no-cache libc6-compat

COPY package.json pnpm-lock.yaml* ./
RUN pnpm install --frozen-lockfile

# =========================================
# Stage 3: Builder
# =========================================
FROM base AS builder
WORKDIR /app

COPY package.json pnpm-lock.yaml* ./
COPY --from=deps /app/node_modules ./node_modules

# Database setup
COPY prisma ./prisma
COPY prisma.config.ts ./

RUN pnpm db:generate

# Build application
COPY tsconfig.json tsup.config.ts ./
COPY src ./src
RUN pnpm build

# Cleanup dev dependencies
RUN pnpm prune --prod --ignore-scripts

# =========================================
# Stage 4: Production
# =========================================
FROM node:22-alpine AS runner
WORKDIR /app

RUN apk add --no-cache dumb-init
ENV NODE_ENV=production

# Create non-root user
RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 nodejs

# Copy build artifacts
COPY --from=builder /app/package.json ./
COPY --from=builder --chown=nodejs:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=nodejs:nodejs /app/dist ./dist

# Copy Prisma files for migrations and runtime
COPY --from=builder --chown=nodejs:nodejs /app/prisma ./prisma

# Create logs directory
RUN mkdir -p logs && chown nodejs:nodejs logs

USER nodejs
EXPOSE 8000

ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "dist/api/index.js"]