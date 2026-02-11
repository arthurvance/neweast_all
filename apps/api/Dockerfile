FROM node:24-alpine

WORKDIR /workspace

COPY node_modules ./node_modules
COPY apps/api ./apps/api
COPY package.json ./package.json
COPY nx.json ./nx.json
COPY pnpm-workspace.yaml ./pnpm-workspace.yaml
COPY tsconfig.base.json ./tsconfig.base.json

EXPOSE 3000

CMD ["node", "apps/api/src/main.js"]
