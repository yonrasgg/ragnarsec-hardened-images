#!/bin/sh
set -eu

# ZAP's API can launch scans and reach arbitrary targets. Never start the
# daemon with API key checks disabled; require a runtime-provided key.
if [ -z "${ZAP_API_KEY:-}" ]; then
    echo "ZAP_API_KEY must be set; refusing to start ZAP with a keyless API" >&2
    exit 1
fi

exec "${ZAP_PATH:-/zap/zap.sh}" \
    -daemon \
    -host "${ZAP_HOST:-0.0.0.0}" \
    -port "${ZAP_PORT:-8080}" \
    -config "api.key=${ZAP_API_KEY}" \
    "$@"
