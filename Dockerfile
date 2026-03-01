# -------------------------------------------------------
# Panguard API - Production Image
#
# Multi-stage build:
#   Stage 1: pnpm workspace build
#   Stage 2: Manual standalone bundle with npm (no pnpm symlinks)
#
# Build:  docker build -t panguard-api .
# Run:    docker run -p 3000:3000 -v pg-data:/data panguard-api
# -------------------------------------------------------

# Stage 1: Build everything with pnpm workspace
FROM node:22-slim AS builder

# Build tools for native modules (better-sqlite3)
RUN apt-get update && \
    apt-get install -y --no-install-recommends python3 make g++ && \
    rm -rf /var/lib/apt/lists/*

ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"
ENV CI=true
RUN corepack enable

WORKDIR /build

# Copy workspace config + all package.json files for dependency resolution
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.json ./
COPY packages/core/package.json packages/core/
COPY packages/panguard/package.json packages/panguard/
COPY packages/panguard-auth/package.json packages/panguard-auth/
COPY packages/panguard-guard/package.json packages/panguard-guard/
COPY packages/panguard-scan/package.json packages/panguard-scan/
COPY packages/panguard-chat/package.json packages/panguard-chat/
COPY packages/panguard-report/package.json packages/panguard-report/
COPY packages/panguard-trap/package.json packages/panguard-trap/
COPY packages/panguard-web/package.json packages/panguard-web/
COPY packages/threat-cloud/package.json packages/threat-cloud/
COPY security-hardening/package.json security-hardening/

# Install all dependencies (including dev for TypeScript compilation)
RUN pnpm install --frozen-lockfile --prod=false

# Copy source code (website excluded by .dockerignore)
COPY packages/core/ packages/core/
COPY packages/panguard/ packages/panguard/
COPY packages/panguard-auth/ packages/panguard-auth/
COPY packages/panguard-guard/ packages/panguard-guard/
COPY packages/panguard-scan/ packages/panguard-scan/
COPY packages/panguard-chat/ packages/panguard-chat/
COPY packages/panguard-report/ packages/panguard-report/
COPY packages/panguard-trap/ packages/panguard-trap/
COPY packages/panguard-web/ packages/panguard-web/
COPY packages/threat-cloud/ packages/threat-cloud/
COPY security-hardening/ security-hardening/
COPY config/ config/

# Build all backend packages (skip website)
RUN pnpm --filter '!@panguard-ai/website' -r run build

# ---- Create standalone bundle (no pnpm symlinks) ----

# Copy main CLI entry point
RUN mkdir -p /standalone && \
    cp -r packages/panguard/dist /standalone/dist

# Copy each workspace package as a regular node_modules entry
RUN mkdir -p /standalone/node_modules/@panguard-ai && \
    for pkg in core panguard-auth panguard-guard panguard-scan panguard-chat panguard-report panguard-trap panguard-web; do \
      mkdir -p /standalone/node_modules/@panguard-ai/$pkg && \
      cp -r packages/$pkg/dist /standalone/node_modules/@panguard-ai/$pkg/dist && \
      cp packages/$pkg/package.json /standalone/node_modules/@panguard-ai/$pkg/; \
    done && \
    mkdir -p /standalone/node_modules/@panguard-ai/security-hardening && \
    cp -r security-hardening/dist /standalone/node_modules/@panguard-ai/security-hardening/dist && \
    cp security-hardening/package.json /standalone/node_modules/@panguard-ai/security-hardening/ && \
    mkdir -p /standalone/node_modules/@panguard-ai/threat-cloud && \
    cp -r packages/threat-cloud/dist /standalone/node_modules/@panguard-ai/threat-cloud/dist && \
    cp packages/threat-cloud/package.json /standalone/node_modules/@panguard-ai/threat-cloud/

# Generate bundle package.json with all external (non-workspace) dependencies
RUN node -e " \
  const fs = require('fs'); \
  const pkgPaths = [ \
    'packages/core/package.json', \
    'packages/panguard/package.json', \
    'packages/panguard-auth/package.json', \
    'packages/panguard-guard/package.json', \
    'packages/panguard-scan/package.json', \
    'packages/panguard-chat/package.json', \
    'packages/panguard-report/package.json', \
    'packages/panguard-trap/package.json', \
    'packages/panguard-web/package.json', \
    'packages/threat-cloud/package.json', \
    'security-hardening/package.json', \
  ]; \
  const deps = {}; \
  const optDeps = {}; \
  for (const p of pkgPaths) { \
    const pkg = JSON.parse(fs.readFileSync(p, 'utf8')); \
    for (const [n, v] of Object.entries(pkg.dependencies || {})) { \
      if (!n.startsWith('@panguard-ai/')) deps[n] = v; \
    } \
    for (const [n, v] of Object.entries(pkg.optionalDependencies || {})) { \
      if (!n.startsWith('@panguard-ai/')) optDeps[n] = v; \
    } \
  } \
  const bundle = { \
    name: 'panguard-api', \
    version: '0.1.0', \
    private: true, \
    type: 'module', \
    dependencies: deps, \
    optionalDependencies: optDeps, \
  }; \
  fs.writeFileSync('/standalone/package.json', JSON.stringify(bundle, null, 2)); \
  console.log('External deps:', Object.keys(deps).join(', ')); \
  console.log('Optional deps:', Object.keys(optDeps).join(', ')); \
"

# Install external production dependencies with npm (flat node_modules, no symlinks)
RUN cd /standalone && npm install --production

# Verify the entry point
RUN node -e "require('fs').accessSync('/standalone/dist/cli/index.js')" && \
    echo 'Entry point OK: /standalone/dist/cli/index.js'

# -------------------------------------------------------
# Stage 2: Production
FROM node:22-slim

# tini: proper PID 1 init (signal handling, zombie reaping)
# curl: healthcheck probe
RUN apt-get update && \
    apt-get install -y --no-install-recommends tini curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy standalone bundle (flat node_modules, no pnpm symlinks)
COPY --from=builder /standalone .

# Copy config directory (YARA rules etc., lives at monorepo root)
COPY --from=builder /build/config ./config

# Persistent data directory
RUN mkdir -p /data

ENV NODE_ENV=production
ENV PANGUARD_DATA_DIR=/data

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD curl -f http://127.0.0.1:${PORT:-3000}/health || exit 1

ENTRYPOINT ["tini", "--"]
CMD ["sh", "-c", "exec node dist/cli/index.js serve --port ${PORT:-3000} --host 0.0.0.0 --db /data/auth.db"]
