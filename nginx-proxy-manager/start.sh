#!/bin/sh
set -eu
umask 077

test "$(id -u)" = 1000
test -w /data && test -w /etc/letsencrypt
test "${DISABLE_IPV6:-}" = true && test "${IP_RANGES_FETCH_ENABLED:-}" = false
mkdir -p /tmp/npm/body /tmp/npm/proxy /tmp/npm/fastcgi /tmp/npm/uwsgi /tmp/npm/scgi \
    /tmp/npm/cache/public /tmp/npm/cache/private \
    /data/custom_ssl /data/logs /data/access /data/letsencrypt-acme-challenge
for dir in default_host default_www proxy_host redirection_host stream dead_host temp; do
    mkdir -p "/data/nginx/$dir"
done

node /usr/local/lib/npm-render-resolver.cjs

# Match upstream's peer authentication contract; do not bake the secret in a layer.
NPM_PEER_SECRET="$(openssl rand -hex 32)"
test "${#NPM_PEER_SECRET}" -eq 64
export NPM_PEER_SECRET
node -e 'const fs=require("node:fs"); const t=fs.readFileSync("/etc/nginx/conf.d/production.conf.template","utf8"); fs.writeFileSync("/tmp/npm/production.conf",t.replaceAll("{{NPM_ADMIN_PORT}}","8181").replaceAll("{{NPM_PEER_SECRET}}",process.env.NPM_PEER_SECRET),{mode:0o600});'

test ! -e /tmp/npm/nginx.pid
/usr/sbin/nginx &
nginx_pid=$!
backend_pid=
cleanup() {
    if [ -n "$backend_pid" ]; then
        kill -TERM "$backend_pid" 2>/dev/null || :
        wait "$backend_pid" || :
    fi
    kill -QUIT "$nginx_pid" 2>/dev/null || :
    wait "$nginx_pid" || :
}
trap 'cleanup; exit 0' TERM INT

for i in $(seq 1 50); do
    if test -s /tmp/npm/nginx.pid; then break; fi
    if ! kill -0 "$nginx_pid" 2>/dev/null; then break; fi
    sleep 0.1
done
if ! test -s /tmp/npm/nginx.pid; then cleanup; exit 1; fi

node /app/index.js &
backend_pid=$!
while kill -0 "$nginx_pid" 2>/dev/null && kill -0 "$backend_pid" 2>/dev/null; do sleep 1; done
cleanup
exit 1
