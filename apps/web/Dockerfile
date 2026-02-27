FROM node:24-alpine AS builder

WORKDIR /workspace

COPY apps/web ./apps/web
COPY apps/api ./apps/api

RUN rm -rf apps/web/node_modules \
  && npm --prefix apps/web install --no-package-lock \
  && node apps/web/scripts/sync-permission-catalog.cjs \
  && cd apps/web \
  && node node_modules/vite/bin/vite.js build --config vite.config.js

FROM node:24-alpine

WORKDIR /workspace

COPY apps/web/server.js ./apps/web/server.js
COPY apps/web/src ./apps/web/src
COPY --from=builder /workspace/dist ./dist

EXPOSE 4173

CMD ["node", "apps/web/server.js"]
