ARG NODE_IMAGE=node:22-alpine@sha256:16e22a550f3863206a3f701448c45f7912c6896a62de43add43bb9c86130c3e2
ARG NGINX_IMAGE=nginx:1.29-alpine@sha256:5616878291a2eed594aee8db4dade5878cf7edcb475e59193904b198d9b830de
FROM ${NODE_IMAGE} AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --no-audit --no-fund
COPY . .
ARG VITE_DEMO_MODE=false
ENV VITE_DEMO_MODE=${VITE_DEMO_MODE}
RUN npm run build

FROM ${NGINX_IMAGE}
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 8080
HEALTHCHECK CMD wget -q -O /dev/null http://127.0.0.1:8080/ || exit 1
