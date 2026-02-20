# RootSigil production image
#
# Uses Debian (glibc) to avoid native module issues with better-sqlite3.

FROM node:20-bookworm-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

FROM deps AS build
WORKDIR /app
COPY tsconfig.json eslint.config.js ./
COPY src ./src
COPY scripts ./scripts
COPY migrations ./migrations
COPY policy ./policy
COPY openapi ./openapi
COPY README.md CHANGELOG.md LICENSE ./
RUN npm run build
RUN npm prune --omit=dev

FROM node:20-bookworm-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY --from=build /app/scripts ./scripts
COPY --from=build /app/migrations ./migrations
COPY --from=build /app/policy ./policy
COPY --from=build /app/openapi ./openapi
COPY package.json package-lock.json ./

RUN useradd -m -u 10001 rootsigil && chown -R rootsigil:rootsigil /app
USER rootsigil

EXPOSE 8080
CMD ["node", "dist/index.js"]
