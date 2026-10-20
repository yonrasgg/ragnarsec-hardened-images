ARG BASE_TAG=latest
FROM ghcr.io/yonrasgg/ragnarsec-python-base:${BASE_TAG}

# OCI metadata (build-time args populated by CI; defaults for local builds)
ARG BUILD_DATE=1970-01-01T00:00:00Z
ARG VCS_REF=local
ARG VERSION=dev

LABEL org.opencontainers.image.source="https://github.com/yonrasgg/ragnarsec-images" \
      org.opencontainers.image.description="RagnarSec Python Base with PDF/WeasyPrint dependencies" \
      org.opencontainers.image.licenses="GPL-3.0" \
      org.opencontainers.image.url="https://github.com/yonrasgg/ragnarsec-images/tree/main/python-pdf" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.vendor="RagnarSec"

USER root

# SECURITY: Upgrade system packages to patch CVEs, then install PDF rendering dependencies.
# Required for: WeasyPrint PDF generation, Pango/Cairo text rendering, JPEG/JPEG2000 handling.
# These libraries are needed at RUNTIME for PDF generation in ragnarsec-web billing/exports.
#
# Dependencies breakdown:
#   - pango: Text layout and rendering (includes pangoft2–Pango integration, pangocairo–Cairo integration)
#   - cairo: 2D graphics library (WeasyPrint backend)
#   - harfbuzz: OpenType text shaping engine (required by WeasyPrint on Alpine)
#   - libjpeg-turbo: JPEG image handling in PDFs
#   - openjpeg: JPEG2000 support
#   - libffi: Foreign function interface runtime (used by cffi/cairocffi at runtime)
#   - font-liberation: Standard fonts for consistent PDF rendering
#   - fontconfig: Font configuration (provides fc-list for testing)
#
# hadolint ignore=DL3018
RUN apk upgrade --no-cache \
    && apk add --no-cache \
    pango \
    cairo \
    harfbuzz \
    libjpeg-turbo \
    openjpeg \
    libffi \
    font-liberation \
    fontconfig

# Smoke test: Verify libraries are loadable
RUN python3 -c "from ctypes import CDLL; CDLL('libpango-1.0.so.0'); CDLL('libcairo.so.2'); print('PDF dependencies OK')"

USER ragnarsec
WORKDIR /app

CMD ["python3"]
