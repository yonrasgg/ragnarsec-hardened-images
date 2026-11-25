# syntax=docker/dockerfile:1
#
# ragnarsec-wgdashboard — O1 native HTTPS image.
# HTTPS is served by Gunicorn itself on 0.0.0.0:10086; there is no sidecar,
# no plaintext listener and no TLS termination outside this container.
# The inherited AmneziaWG Go binary is NOT rebuilt: the build proxy forbids
# proxy.golang.org. It stays covered by the scoped VEX in
# vex/ragnarsec-wgdashboard.openvex.json.

# Base digest is pinned and inherited across amd64/arm64. It is the same
# multi-arch snapshot used by the release-25 lineage (EVD-PRJ-191).
FROM ghcr.io/wgdashboard/wgdashboard@sha256:8c5b550db4fda04eff06e96af801499be485c73e0912fcf0c1031babca0f7e7b

ARG BUILD_DATE=1970-01-01T00:00:00Z
ARG VCS_REF=local
ARG VERSION=dev

LABEL org.opencontainers.image.source="https://github.com/yonrasgg/ragnarsec-hardened-images" \
      org.opencontainers.image.description="Hardened WGDashboard wrapper (native HTTPS, read-only deployment contract)" \
      org.opencontainers.image.licenses="GPL-3.0" \
      org.opencontainers.image.url="https://github.com/yonrasgg/ragnarsec-hardened-images/tree/main/wgdashboard" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.vendor="RagnarSec"

# Remediation of Python dependencies with corrected versions already available
# offline. Use the ABSOLUTE interpreter of the inherited venv; Trivy reads two
# static pip/_vendor/vendor.txt files and two setuptools vendored dist-info
# directories, so pip is removed from both interpreters and those two metadata
# directories are removed. python-jose, ecdsa and golang.org/x/net stay under
# scoped VEX. No Go rebuild and no new network source.
RUN set -eu; \
    VENV=/opt/wgdashboard/src/venv; \
    "$VENV/bin/python" -m pip install --no-cache-dir --upgrade \
        jaraco.context==6.1.0 \
        msgpack==1.2.3 \
        setuptools==78.1.1 \
        urllib3==2.8.0 \
        wheel==0.46.2; \
    rm -rf "$VENV"/lib/python*/site-packages/setuptools/_vendor/jaraco.context-*.dist-info \
           "$VENV"/lib/python*/site-packages/setuptools/_vendor/wheel-*.dist-info; \
    "$VENV/bin/python" -m pip uninstall -y pip; \
    /usr/local/bin/python3 -m pip uninstall -y pip

# Reviewed read-only guard and fail-closed keyless preflight. These four byte
# inputs were exercised in the isolated rehearsal of EVD-PRJ-192; the diagnostic
# overlays there are now canonical image content instead of runtime mounts.
COPY --chown=1000:1000 --chmod=0444 src/dashboard.py /opt/wgdashboard/src/dashboard.py
COPY --chown=1000:1000 --chmod=0444 src/readonly_mode.py /opt/wgdashboard/src/readonly_mode.py
COPY --chown=1000:1000 --chmod=0444 src/readonly_preflight.py /opt/wgdashboard/src/readonly_preflight.py
COPY --chown=1000:1000 --chmod=0555 docker/entrypoint.sh /usr/local/bin/wgdashboard-entrypoint
COPY --chown=1000:1000 --chmod=0555 docker/healthcheck.sh /usr/local/bin/wgdashboard-healthcheck

# TLS material is supplied at runtime as a read-only bind of
# /run/secrets/wgdashboard/{server.crt,server.key,ca.crt} (0600, uid 1000).
# No key is ever baked into the image, repo, layer cache or evidence.
ENV WG_DASHBOARD_READ_ONLY=1 \
    WG_DASHBOARD_BACKEND_TLS_NAME=wgdashboard-backend.svc.ragnarsec.com \
    WG_DASHBOARD_BACKEND_CA_FILE=/run/secrets/wgdashboard/ca.crt \
    WG_DASHBOARD_BACKEND_CERT_FILE=/run/secrets/wgdashboard/server.crt \
    WG_DASHBOARD_BACKEND_KEY_FILE=/run/secrets/wgdashboard/server.key \
    WG_DASHBOARD_READ_ONLY_DATA_DIR=/config \
    WG_DASHBOARD_READ_ONLY_WG_DIR=/config/keyless \
    CONFIGURATION_PATH=/config \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/opt/wgdashboard/src:/opt/wgdashboard/src/modules

# DS002: non-root. The inherited entrypoint writes to
# /etc/wireguard/WGDashboard_Backup; the O1 read-only branch never invokes it,
# so no :rw backup path is required for this deployment contract.
USER 1000:1000

EXPOSE 10086

# HTTPS probe: HTTP 200 on /api/handshake over loopback:10086 with verified
# server name and trusted CA. The inherited PID-file probe is replaced.
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD ["/usr/local/bin/wgdashboard-healthcheck"]

WORKDIR /opt/wgdashboard/src
ENTRYPOINT ["/usr/local/bin/wgdashboard-entrypoint"]
