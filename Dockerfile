# -------------------------------------------------------
# Panguard API - Production Image
#
# Multi-stage build:
#   Stage 1: pnpm workspace build
#   Stage 2: Standalone bundle with npm (no pnpm symlinks)
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
COPY packages/panguard-manager/package.json packages/panguard-manager/
COPY packages/panguard-mcp/package.json packages/panguard-mcp/
COPY packages/panguard-skill-auditor/package.json packages/panguard-skill-auditor/
COPY packages/threat-cloud/package.json packages/threat-cloud/
COPY packages/atr/package.json packages/atr/
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
COPY packages/panguard-manager/ packages/panguard-manager/
COPY packages/panguard-mcp/ packages/panguard-mcp/
COPY packages/panguard-skill-auditor/ packages/panguard-skill-auditor/
COPY packages/threat-cloud/ packages/threat-cloud/
COPY packages/atr/ packages/atr/
COPY security-hardening/ security-hardening/
COPY config/ config/
COPY packages/admin/ packages/admin/

# Build all backend packages (skip website)
RUN pnpm --filter '!@panguard-ai/website' -r run build

# ---- Create standalone bundle (no pnpm symlinks) ----
RUN mkdir -p /standalone

# Step 1: Copy main CLI entry point
RUN cp -r packages/panguard/dist /standalone/dist

# Step 2: Install external deps with npm FIRST (before workspace packages)
# NOTE: Update these versions if workspace package.json deps change
RUN printf '{"name":"panguard-api","version":"0.1.0","private":true,"type":"module","dependencies":{"commander":"12.1.0","better-sqlite3":"11.10.0","i18next":"24.2.3","js-yaml":"4.1.1","zod":"3.25.76","pdfkit":"0.15.2"},"optionalDependencies":{"ssh2":"1.17.0"}}' > /standalone/package.json && \
    cd /standalone && npm install --production

# Step 3: Copy workspace packages into node_modules AFTER npm install
RUN mkdir -p /standalone/node_modules/@panguard-ai && \
    for pkg in core panguard-auth panguard-guard panguard-scan panguard-chat panguard-report panguard-trap panguard-web panguard-mcp panguard-skill-auditor; do \
      mkdir -p /standalone/node_modules/@panguard-ai/$pkg && \
      cp -r packages/$pkg/dist /standalone/node_modules/@panguard-ai/$pkg/dist && \
      cp packages/$pkg/package.json /standalone/node_modules/@panguard-ai/$pkg/; \
    done && \
    mkdir -p /standalone/node_modules/@panguard-ai/manager && \
    cp -r packages/panguard-manager/dist /standalone/node_modules/@panguard-ai/manager/dist && \
    cp packages/panguard-manager/package.json /standalone/node_modules/@panguard-ai/manager/ && \
    mkdir -p /standalone/node_modules/@panguard-ai/security-hardening && \
    cp -r security-hardening/dist /standalone/node_modules/@panguard-ai/security-hardening/dist && \
    cp security-hardening/package.json /standalone/node_modules/@panguard-ai/security-hardening/ && \
    mkdir -p /standalone/node_modules/@panguard-ai/threat-cloud && \
    cp -r packages/threat-cloud/dist /standalone/node_modules/@panguard-ai/threat-cloud/dist && \
    cp packages/threat-cloud/package.json /standalone/node_modules/@panguard-ai/threat-cloud/ && \
    mkdir -p /standalone/node_modules/agent-threat-rules && \
    cp -r packages/atr/dist /standalone/node_modules/agent-threat-rules/dist && \
    cp packages/atr/package.json /standalone/node_modules/agent-threat-rules/ && \
    cp -r packages/atr/rules /standalone/node_modules/agent-threat-rules/rules && \
    cp -r packages/atr/spec /standalone/node_modules/agent-threat-rules/spec

# Verify entry point exists
RUN ls -la /standalone/dist/cli/index.js

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

# Copy config directory (YARA rules etc., at monorepo root)
COPY --from=builder /build/config ./config

# Copy admin dashboard static files (served by panguard serve at /admin)
COPY --from=builder /build/packages/admin ./packages/admin

# Persistent data directory
RUN mkdir -p /data

# Run as non-root user
RUN groupadd --system --gid 1001 panguard && \
    useradd --system --uid 1001 --gid 1001 panguard && \
    chown -R panguard:panguard /app /data
USER panguard

ENV NODE_ENV=production
ENV PANGUARD_DATA_DIR=/data

EXPOSE 3000

# No Dockerfile HEALTHCHECK - let Railway manage it after container starts
ENTRYPOINT ["tini", "--"]
CMD ["node", "dist/cli/index.js", "serve", "--port", "3000", "--host", "0.0.0.0", "--db", "/data/auth.db"]
