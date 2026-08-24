# syntax=docker/dockerfile:1
# Build context is the repository root (the service imports ../../../shared).

FROM node:24-alpine AS deps
WORKDIR /app/services/auth-service
COPY services/auth-service/package.json ./
RUN npm install --omit=dev --no-audit --no-fund && npm cache clean --force

FROM node:24-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY --chown=node:node shared ./shared
COPY --from=deps --chown=node:node /app/services/auth-service/node_modules ./services/auth-service/node_modules
COPY --chown=node:node services/auth-service/package.json ./services/auth-service/
COPY --chown=node:node services/auth-service/src ./services/auth-service/src
# /data is the volume mount point; pre-creating it gives the volume non-root ownership.
RUN mkdir -p /data && chown node:node /data
USER node
WORKDIR /app/services/auth-service
EXPOSE 4001
HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:4001/ready').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "--disable-warning=ExperimentalWarning", "src/index.js"]
