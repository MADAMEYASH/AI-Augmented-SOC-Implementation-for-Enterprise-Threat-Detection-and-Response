# Multi-stage production build for AegisSOC Enterprise
FROM node:22-alpine AS builder

WORKDIR /app

# Copy package descriptors
COPY package*.json tsconfig.json ./

# Install all dependencies
RUN npm ci

# Copy source code and assets
COPY . .

# Compile frontend static bundles
RUN npm run build

# Production runtime stage
FROM node:22-alpine AS runner

WORKDIR /app
ENV NODE_ENV=production
ENV PORT=3000

# Install tsx runtime and production dependencies
COPY package*.json ./
RUN npm ci --only=production && npm install -g tsx

# Copy compiled frontend and backend code
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/src ./src
COPY --from=builder /app/server.ts ./
COPY --from=builder /app/firebase-applet-config.json ./
COPY --from=builder /app/tsconfig.json ./

EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/api/health || exit 1

CMD ["tsx", "server.ts"]
