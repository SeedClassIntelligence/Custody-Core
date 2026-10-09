# Custody Core: one container serving the API and the built browser app.
#
#   docker build \
#     --build-arg VITE_SUPABASE_URL=https://<ref>.supabase.co \
#     --build-arg VITE_SUPABASE_ANON_KEY=<anon / publishable key> \
#     -t custody-core .
#
# The two VITE_ values are public and are baked into the browser bundle here, so they are build arguments.
# Everything secret (DATABASE_URL, APP_DB_PASSWORD, MFA_ENCRYPTION_KEY) is given only when the container runs,
# never at build time, so it is never stored in an image layer.

FROM node:22-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
# Playwright is only for the local browser check; skip its browser download.
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
RUN npm ci --no-audit --no-fund
COPY . .
ARG VITE_SUPABASE_URL
ARG VITE_SUPABASE_ANON_KEY
RUN test -n "$VITE_SUPABASE_URL" && test -n "$VITE_SUPABASE_ANON_KEY" \
  || (echo "Build arguments VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY are required." >&2; exit 1)
RUN npm run build
# The git gateway's secret scanner: a pinned gitleaks release, checked against its published SHA-256.
RUN npm run tools:gitleaks

FROM node:22-bookworm-slim
WORKDIR /app
ENV NODE_ENV=production PORT=3000 GATEWAY_DATA_DIR=/tmp/custody-core-gateway
# The git gateway runs git itself (git http-backend, fetch, push).
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund && npm cache clean --force
COPY --from=build /app/.tools/gitleaks ./.tools/gitleaks
COPY --from=build /app/dist ./dist
COPY server.ts ./
COPY server ./server
COPY shared ./shared
USER node
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s \
  CMD node -e "fetch('http://127.0.0.1:'+process.env.PORT+'/api/v1/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node_modules/.bin/tsx", "server.ts"]
