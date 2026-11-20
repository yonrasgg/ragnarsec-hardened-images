# syntax=docker/dockerfile:1

FROM alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a AS sources
RUN apk add --no-cache ca-certificates=20261020-r0 curl=8.23.0-r0 gnupg=2.4.9-r1
WORKDIR /materials
COPY fetch-sources.sh openresty-release-key.asc ./
RUN sh fetch-sources.sh

FROM docker.io/library/node:26.13.1-alpine@sha256:6bd9ab43c0ec0190ca7b2d193906cb8b7edf6e7f4afa43ddeccd6452710bffb5 AS node-build
RUN apk add --no-cache python3=3.14.10-r1 make=4.4.1-r4 g++=15.2.0-r5 patch=2.8.1-r0
COPY --from=sources /materials/yarn.tgz /tmp/yarn.tgz
RUN mkdir -p /opt/yarn && tar -xzf /tmp/yarn.tgz --strip-components=1 -C /opt/yarn
WORKDIR /src
COPY --from=sources /materials/npm/backend /src/backend
COPY backend-lock.patch /tmp/backend-lock.patch
RUN patch --batch --fuzz=0 -p1 -i /tmp/backend-lock.patch
WORKDIR /src/backend
RUN npm_config_nodedir=/usr/local npm_config_build_from_source=true \
      node /opt/yarn/bin/yarn.js install --production --frozen-lockfile --non-interactive \
    && rm node_modules/bcrypt/Dockerfile

FROM node-build AS application
RUN apk add --no-cache bash=5.3.9-r1 jq=1.8.2-r0
COPY --from=sources /materials/npm/frontend /src/frontend
WORKDIR /src/frontend
RUN CI=true node /opt/yarn/bin/yarn.js install --frozen-lockfile --non-interactive \
    && node /opt/yarn/bin/yarn.js lint \
    && node /opt/yarn/bin/yarn.js locale-compile \
    && CI=true node /opt/yarn/bin/yarn.js vitest run --no-color \
    && node /opt/yarn/bin/yarn.js build \
    && test -s dist/index.html
COPY --from=sources /materials/npm/docker/rootfs /src/rootfs
COPY layout.cjs /tmp/layout.cjs
RUN node /tmp/layout.cjs /src /pkg

FROM alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a AS openresty
RUN apk add --no-cache build-base=0.5-r4 git=2.54.1-r0 perl=5.42.3-r0 \
      pcre2-dev=10.49-r0 openssl-dev=3.5.9-r1 zlib-dev=1.4-r0 \
      libmaxminddb-dev=1.13.3-r0 linux-headers=7.0.0-r1
COPY --from=sources /materials/openresty /source/openresty
COPY --from=sources /materials/geoip2 /source/geoip2
COPY --from=sources /materials/patches /source/patches
WORKDIR /source/openresty/bundle/nginx-1.31.8
RUN for patch in http2-data-frame-queue.patch CVE-2026-123633.patch CVE-2026-123007.patch; do \
      git apply --check "/source/patches/$patch" && git apply "/source/patches/$patch" || exit 1; \
    done
WORKDIR /source/openresty
RUN ./configure --prefix=/etc/nginx --sbin-path=/usr/sbin/nginx \
      --modules-path=/usr/lib/nginx/modules --conf-path=/etc/nginx/nginx.conf \
      --error-log-path=/dev/stderr --http-log-path=/dev/stdout --pid-path=/tmp/nginx.pid \
      --user=npm --group=npm --with-compat --with-threads \
      --with-http_addition_module --with-http_auth_request_module --with-http_dav_module \
      --with-http_flv_module --with-http_gunzip_module --with-http_gzip_static_module \
      --with-http_mp4_module --with-http_realip_module --with-http_secure_link_module \
      --with-http_slice_module --with-http_ssl_module --with-http_stub_status_module \
      --with-http_sub_module --with-http_v2_module --with-http_v3_module \
      --with-mail --with-mail_ssl_module --with-stream --with-stream_realip_module \
      --with-stream_ssl_module --with-stream_ssl_preread_module \
      --add-dynamic-module=/source/geoip2 \
    && make -j4 \
    && make install DESTDIR=/stage \
    && find /stage/etc/nginx/luajit/lib -type f -name '*.a' -delete

FROM alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a AS certbot
RUN apk add --no-cache python3=3.14.10-r1 py3-pip=26.1.2-r0 ca-certificates=20261020-r0
COPY certbot-requirements.txt /tmp/requirements.txt
RUN python3 -m pip --isolated install --only-binary=:all: --no-cache-dir --require-hashes \
      --index-url https://pypi.org/simple --target /opt/certbot -r /tmp/requirements.txt \
    && test ! -d /opt/certbot/pip

FROM alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
RUN apk add --no-cache libstdc++=15.2.0-r5 libgcc=15.2.0-r5 libatomic=15.2.0-r5 \
      pcre2=10.49-r0 openssl=3.5.9-r1 libssl3=3.5.9-r1 libcrypto3=3.5.9-r1 \
      zlib=1.4-r0 libmaxminddb=1.13.3-r0 python3=3.14.10-r1 ca-certificates=20261020-r0 \
      tini=0.19.0-r3 logrotate=3.22.0-r0 \
    && addgroup -g 1000 npm && adduser -D -H -u 1000 -G npm npm \
    && mkdir -p /data /etc/letsencrypt && chown 1000:1000 /data /etc/letsencrypt
COPY --from=node-build /usr/local/bin/node /usr/local/bin/node
COPY --from=application /pkg/ /
COPY --from=openresty /stage/usr/sbin/nginx /usr/sbin/nginx
COPY --from=openresty /stage/usr/lib/nginx/modules/ngx_http_geoip2_module.so /usr/lib/nginx/modules/
COPY --from=openresty /stage/etc/nginx/luajit/lib/ /etc/nginx/luajit/lib/
COPY --from=openresty /stage/etc/nginx/lualib/ /etc/nginx/lualib/
COPY --from=certbot /opt/certbot /opt/certbot
COPY --chmod=0755 start.sh /usr/local/bin/npm-start

ARG BUILD_DATE=1970-01-01T00:00:00Z
ARG VCS_REF=local
ARG VERSION=dev
LABEL org.opencontainers.image.source="https://github.com/yonrasgg/ragnarsec-hardened-images" \
      org.opencontainers.image.description="Hardened Nginx Proxy Manager" \
      org.opencontainers.image.licenses="GPL-3.0" \
      org.opencontainers.image.url="https://github.com/yonrasgg/ragnarsec-hardened-images/tree/main/nginx-proxy-manager" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.vendor="RagnarSec"

ENV NODE_ENV=production IP_RANGES_FETCH_ENABLED=false DISABLE_IPV6=true HOME=/tmp \
    NPM_BUILD_VERSION=2.17.1 NPM_BUILD_COMMIT=89c43f564422a78bd0732046b636cbcd5e566b03 \
    PYTHONPATH=/opt/certbot PYTHONDONTWRITEBYTECODE=1 CERTBOT_VERSION=5.10.0 \
    PATH=/opt/certbot/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
WORKDIR /app
USER 1000:1000
EXPOSE 80 8181 443
HEALTHCHECK --interval=5s --timeout=2s --start-period=20s --retries=3 \
  CMD ["wget", "-qO", "/dev/null", "http://127.0.0.1:8181/api/"]
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/npm-start"]
