ARG NODE_IMAGE=node:22-alpine@sha256:16e22a550f3863206a3f701448c45f7912c6896a62de43add43bb9c86130c3e2
ARG NGINX_IMAGE=nginxinc/nginx-unprivileged:1.29-alpine@sha256:0c79d56aee561a1d81c63f00eee5fb5fe29279560cdc55e91425133104c7fbe6
FROM ${NODE_IMAGE} AS build
WORKDIR /app
COPY apps/web/package.json apps/web/package-lock.json* ./
RUN npm ci --no-audit --no-fund
COPY apps/web/ ./
ARG VITE_DEMO_MODE=false
ENV VITE_DEMO_MODE=${VITE_DEMO_MODE}
RUN npm run build \
    && mkdir -p dist/legal \
    && cp node_modules/react/LICENSE dist/legal/React-MIT.txt \
    && cp node_modules/react-dom/LICENSE dist/legal/ReactDOM-MIT.txt \
    && cp node_modules/scheduler/LICENSE dist/legal/Scheduler-MIT.txt \
    && cp node_modules/vite/LICENSE.md dist/legal/Vite-MIT-and-third-party.txt \
    && cp node_modules/@vitejs/plugin-react/LICENSE dist/legal/Vite-React-Plugin-MIT.txt \
    && cp node_modules/pretendard/dist/LICENSE.txt dist/legal/Pretendard-OFL-1.1.txt
COPY LICENSE NOTICE THIRD_PARTY_NOTICES.md /app/dist/legal/

FROM ${NGINX_IMAGE}
ARG KODA_IMAGE_CREATED=unknown
ARG KODA_IMAGE_REVISION=unknown
ARG KODA_IMAGE_VERSION=dev
LABEL org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.created="$KODA_IMAGE_CREATED" \
      org.opencontainers.image.revision="$KODA_IMAGE_REVISION" \
      org.opencontainers.image.version="$KODA_IMAGE_VERSION"
USER root
# Compose may provide the standard nginx image as well as nginx-unprivileged.
# Keep runtime non-root in either case, including cache creation and PID writes.
RUN mkdir -p /var/cache/nginx /var/log/nginx \
    && chown -R nginx:nginx /var/cache/nginx /var/log/nginx \
    && sed -i -e '/^[[:space:]]*user[[:space:]]/d' \
              -e 's#^[[:space:]]*pid[[:space:]].*;#pid /tmp/nginx.pid;#' /etc/nginx/nginx.conf
COPY --from=build /app/dist /usr/share/nginx/html
COPY apps/web/nginx.conf /etc/nginx/conf.d/default.conf
USER nginx
EXPOSE 8080
HEALTHCHECK CMD wget -q -O /dev/null http://127.0.0.1:8080/ || exit 1
