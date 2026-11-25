#!/bin/sh
# Fail-closed O1 launcher. No daemon, PID file, control socket or plaintext
# listener. All TLS paths are explicit and must live under the read-only
# secret bind; a missing, linked or misplaced file stops startup (exit 64).
set -eu

APP=/opt/wgdashboard/src
PYTHON="$APP/venv/bin/python"
GUNICORN="$APP/venv/bin/gunicorn"
SECRET_ROOT=/run/secrets/wgdashboard

[ -x "$PYTHON" ] || exit 64
[ -x "$GUNICORN" ] || exit 64
[ -f "$APP/readonly_preflight.py" ] && [ -r "$APP/readonly_preflight.py" ] || exit 64

if [ "${WG_DASHBOARD_READ_ONLY:-0}" = 1 ]; then
    for f in "$WG_DASHBOARD_BACKEND_CERT_FILE" "$WG_DASHBOARD_BACKEND_KEY_FILE" "$WG_DASHBOARD_BACKEND_CA_FILE"; do
        case "$f" in
            "$SECRET_ROOT"/*) ;;
            *) exit 64 ;;
        esac
        [ -f "$f" ] && [ -r "$f" ] && [ ! -L "$f" ] || exit 64
    done
    # Byte-level INI + keyless inventory validation precedes any network bind.
    "$PYTHON" -B "$APP/readonly_preflight.py" || exit 64
    cd "$APP" || exit 64
    exec "$GUNICORN" \
        --no-control-socket \
        --workers 1 \
        --bind 0.0.0.0:10086 \
        --keyfile "$WG_DASHBOARD_BACKEND_KEY_FILE" \
        --certfile "$WG_DASHBOARD_BACKEND_CERT_FILE" \
        dashboard:app
fi

# The inherited upstream entrypoint was replaced by this file; never recurse.
printf '%s\n' 'WGDashboard entrypoint: read-only mode required' >&2
exit 64
