FROM node:20-alpine AS build
WORKDIR /app
ARG VITE_BUILD_SHA=dev
ARG VITE_BUILD_TIME=
ENV VITE_BUILD_SHA=$VITE_BUILD_SHA
ENV VITE_BUILD_TIME=$VITE_BUILD_TIME
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html
# The nginx image runs envsubst over /etc/nginx/templates/*.template at startup, which is how
# HOMEATLAS_PORT reaches the config -- with network_mode host a compose `ports:` mapping is
# ignored, so the listen port has to be baked into nginx itself.
COPY nginx.conf.template /etc/nginx/templates/default.conf.template
ENV HOMEATLAS_PORT=8280
