# Build the Vite SPA and serve the static dist/ via nginx, proxying /v1 to the
# control plane (see web/nginx.conf). Build context is web/.

# --- build stage ------------------------------------------------------------
FROM node:20-bookworm AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

# --- serve stage ------------------------------------------------------------
FROM nginx:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
