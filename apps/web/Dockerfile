FROM node:24-alpine

WORKDIR /workspace

COPY node_modules ./node_modules
COPY apps/web ./apps/web
COPY dist ./dist

EXPOSE 4173

CMD ["node", "apps/web/server.js"]
