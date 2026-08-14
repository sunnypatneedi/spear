FROM node:20-alpine
WORKDIR /app
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml tsconfig.base.json ./
COPY packages ./packages
COPY examples ./examples
RUN corepack enable && pnpm install --frozen-lockfile --filter @spear-secure/api...
RUN pnpm --filter @spear-secure/core build && pnpm --filter @spear-secure/api build
ENV PORT=7700
EXPOSE 7700
CMD ["node", "packages/api/dist/index.js"]
