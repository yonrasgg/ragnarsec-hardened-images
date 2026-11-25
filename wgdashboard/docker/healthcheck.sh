#!/bin/sh
# HTTPS healthcheck for the O1 image. Requires HTTP 200 on /api/handshake
# over loopback TCP 10086 with a trusted CA and the exact backend TLS name.
# A process-only check (or a stub that exits 78) is not a health signal.
set -eu

if [ "${WG_DASHBOARD_READ_ONLY:-0}" != 1 ]; then
    test -s /data/gunicorn.pid
    kill -0 "$(cat /data/gunicorn.pid)"
    exit
fi

name=${WG_DASHBOARD_BACKEND_TLS_NAME:-}
ca=${WG_DASHBOARD_BACKEND_CA_FILE:-}
prefix=${WG_DASHBOARD_APP_PREFIX:-}
case "$name" in
    "" | .* | *. | *..* | *[!A-Za-z0-9.-]*) exit 1 ;;
esac
case "$name" in
    [A-Za-z]*) ;;
    *) exit 1 ;;
esac
case "$ca" in
    /run/secrets/wgdashboard/*) test -f "$ca" && test -r "$ca" || exit 1 ;;
    *) exit 1 ;;
esac
case "$prefix" in
    "" | /*) ;;
    *) exit 1 ;;
esac
case "$prefix" in
    */ | *//* | *[!A-Za-z0-9/_-]*) exit 1 ;;
esac

status=$(curl --disable --noproxy '*' --proto '=https' --tlsv1.2 \
    --connect-timeout 2 --max-time 4 --silent --show-error --fail \
    --cacert "$ca" --connect-to "$name:10086:127.0.0.1:10086" \
    --output /dev/null --write-out '%{http_code}' "https://$name:10086$prefix/api/handshake")
test "$status" = 200
