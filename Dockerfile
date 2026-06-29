FROM node:22.21-alpine

ENV NODE_ENV=production
WORKDIR /opt/openremote

COPY package.json ./
COPY src ./src
COPY public ./public

RUN mkdir -p /opt/openremote/data \
    && chown -R node:node /opt/openremote

USER node
EXPOSE 17880

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:17880/api/health || exit 1

CMD ["node", "src/server.mjs"]
