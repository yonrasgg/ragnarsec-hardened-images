# ragnarsec-plane-admin
# Static React Admin Dashboard for Plane
ARG BASE_TAG=latest

# --- Builder Stage ---
FROM ghcr.io/yonrasgg/ragnarsec-builder:${BASE_TAG} AS builder

USER root
WORKDIR /build

# Clone specific version of Plane
ARG PLANE_VERSION=v0.24.0
RUN git clone --depth 1 --branch ${PLANE_VERSION} https://github.com/makeplane/plane.git .

# Install dependencies (monorepo root)
RUN npm install -g pnpm && \
    pnpm install --frozen-lockfile

# Build admin
WORKDIR /build/admin
# Usually Vite or CRA build
ENV VITE_API_BASE_URL=http://api:8000
RUN pnpm build

# --- Runtime Stage ---
FROM ghcr.io/yonrasgg/ragnarsec-nginx:${BASE_TAG} AS runtime

USER root
WORKDIR /var/www/html

# Copy dist files
COPY --from=builder /build/admin/dist .

# Custom Nginx config
# Remove default ragnarsec config
RUN rm -rf /etc/nginx/conf.d/*
COPY plane/admin/default.conf /etc/nginx/conf.d/default.conf

COPY --from=builder /build/admin/dist /usr/share/nginx/html
# Copy to both locations for safety if unsure about base conf
RUN cp -r /usr/share/nginx/html/* /var/www/html/

USER nginx

EXPOSE 8080

CMD ["nginx", "-g", "daemon off;"]
