# syntax=docker/dockerfile:1
#
# CANDIDATO LOCAL — NO PUBLICAR NI MERGEAR.
# Correccion propuesta para el release 25 de ragnarsec-wgdashboard tras el fallo
# de Trivy documentado en EVD-PRJ-178. Requiere validacion nativa AMD64/ARM64
# y decision del owner antes de cualquier publicacion.

# Nota: el binario amneziawg-go heredado se cubre con VEX acotado en vex/ragnarsec-wgdashboard.openvex.json.
# No se reconstruye Go: el proxy de build prohibe proxy.golang.org.

FROM ghcr.io/wgdashboard/wgdashboard@sha256:8c5b550db4fda04eff06e96af801499be485c73e0912fcf0c1031babca0f7e7b

ARG BUILD_DATE=1970-01-01T00:00:00Z
ARG VCS_REF=local
ARG VERSION=dev

LABEL org.opencontainers.image.source="https://github.com/yonrasgg/ragnarsec-hardened-images" \
      org.opencontainers.image.description="Hardened WGDashboard wrapper (read-only deployment contract)" \
      org.opencontainers.image.licenses="GPL-3.0" \
      org.opencontainers.image.url="https://github.com/yonrasgg/ragnarsec-hardened-images/tree/main/wgdashboard" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.vendor="RagnarSec"

# Remediacion de dependencias Python con version corregida disponible.
# Se usa el interprete ABSOLUTO del venv heredado (/opt/wgdashboard/src/venv), sin
# depender de PATH. Trivy no lee los *.dist-info recien instalados sino dos
# pip/_vendor/vendor.txt estaticos y dos *.dist-info dentro de setuptools/_vendor;
# por eso se retira pip de ambos interpretes (pip es solo de build) y se eliminan
# esos dos directorios de metadata vendida. python-jose, ecdsa y golang.org/x/net
# permanecen cubiertos por VEX acotada, sin pin de pip.
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

# DS002: usuario no root. El entrypoint heredado escribe en /etc/wireguard/WGDashboard_Backup;
# el despliegue debe pre-crear esa ruta con propiedad de UID 1000 antes de arrancar.
# Esta linea es un CANDIDATO: debe comprobarse que el entrypoint arranca con este UID.
USER 1000:1000

EXPOSE 10086

# Entrypoint y command heredados de upstream.
