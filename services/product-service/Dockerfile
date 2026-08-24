# syntax=docker/dockerfile:1
# Build context is the repository root (the service imports ../../../shared).

FROM node:24-alpine AS deps
WORKDIR /app/services/product-service
COPY services/product-service/package.json ./
RUN npm install --omit=dev --no-audit --no-fund && npm cache clean --force

FROM node:24-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY --chown=node:node shared ./shared
COPY --from=deps --chown=node:node /app/services/product-service/node_modules ./services/product-service/node_modules
COPY --chown=node:node services/product-service/package.json ./services/product-service/
COPY --chown=node:node services/product-service/src ./services/product-service/src
# /data is the volume mount point; pre-creating it gives the volume non-root ownership.
RUN mkdir -p /data && chown node:node /data
USER node
WORKDIR /app/services/product-service
EXPOSE 4002
HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:4002/ready').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "--disable-warning=ExperimentalWarning", "src/index.js"]
