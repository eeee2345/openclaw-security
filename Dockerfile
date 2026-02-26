FROM node:22-slim AS base
RUN npm install -g pnpm@9

WORKDIR /app

# Install dependencies - copy all package.json files for proper resolution
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY packages/core/package.json packages/core/
COPY packages/panguard/package.json packages/panguard/
COPY packages/panguard-auth/package.json packages/panguard-auth/
COPY packages/panguard-guard/package.json packages/panguard-guard/
COPY packages/panguard-scan/package.json packages/panguard-scan/
COPY packages/panguard-chat/package.json packages/panguard-chat/
COPY packages/panguard-report/package.json packages/panguard-report/
COPY packages/panguard-trap/package.json packages/panguard-trap/
COPY packages/panguard-web/package.json packages/panguard-web/
COPY packages/web/package.json packages/web/
COPY packages/threat-cloud/package.json packages/threat-cloud/
COPY openclaw-fork/package.json openclaw-fork/

RUN pnpm install --frozen-lockfile --prod=false

# Copy source
COPY packages/ packages/
COPY openclaw-fork/ openclaw-fork/
COPY config/ config/
COPY tsconfig.json ./

# Build all packages
RUN pnpm -r run build

# Production image
FROM node:22-slim AS production

RUN groupadd -r panguard && useradd -r -g panguard panguard

WORKDIR /app

# Copy node_modules and built packages
COPY --from=base /app/node_modules ./node_modules
COPY --from=base /app/package.json ./
COPY --from=base /app/pnpm-workspace.yaml ./

# Core
COPY --from=base /app/packages/core/dist ./packages/core/dist
COPY --from=base /app/packages/core/package.json ./packages/core/

# Panguard CLI + Server
COPY --from=base /app/packages/panguard/dist ./packages/panguard/dist
COPY --from=base /app/packages/panguard/package.json ./packages/panguard/

# Auth (SQLite + OAuth + sessions)
COPY --from=base /app/packages/panguard-auth/dist ./packages/panguard-auth/dist
COPY --from=base /app/packages/panguard-auth/package.json ./packages/panguard-auth/

# Web frontend (built static files)
COPY --from=base /app/packages/web/dist ./packages/web/dist
COPY --from=base /app/packages/web/package.json ./packages/web/

# Scan, Guard, Chat, Report, Trap, Threat Cloud
COPY --from=base /app/packages/panguard-scan/dist ./packages/panguard-scan/dist
COPY --from=base /app/packages/panguard-scan/package.json ./packages/panguard-scan/
COPY --from=base /app/packages/panguard-guard/dist ./packages/panguard-guard/dist
COPY --from=base /app/packages/panguard-guard/package.json ./packages/panguard-guard/
COPY --from=base /app/packages/panguard-chat/dist ./packages/panguard-chat/dist
COPY --from=base /app/packages/panguard-chat/package.json ./packages/panguard-chat/
COPY --from=base /app/packages/panguard-report/dist ./packages/panguard-report/dist
COPY --from=base /app/packages/panguard-report/package.json ./packages/panguard-report/
COPY --from=base /app/packages/panguard-trap/dist ./packages/panguard-trap/dist
COPY --from=base /app/packages/panguard-trap/package.json ./packages/panguard-trap/
COPY --from=base /app/packages/threat-cloud/dist ./packages/threat-cloud/dist
COPY --from=base /app/packages/threat-cloud/package.json ./packages/threat-cloud/
COPY --from=base /app/packages/panguard-web/dist ./packages/panguard-web/dist
COPY --from=base /app/packages/panguard-web/package.json ./packages/panguard-web/

# Config files (Sigma rules, YARA rules)
COPY --from=base /app/config ./config

# Data directories
RUN mkdir -p /data && chown panguard:panguard /data

USER panguard

ENV NODE_ENV=production
ENV PANGUARD_DATA_DIR=/data
ENV PANGUARD_PORT=3000

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3000/api/status').then(r => r.ok ? process.exit(0) : process.exit(1)).catch(() => process.exit(1))"

ENTRYPOINT ["node", "packages/panguard/dist/cli/index.js"]
CMD ["dashboard", "--port", "3000", "--no-open"]
