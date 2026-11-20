#!/usr/bin/env bash
# Local/native CI only: no network, published ports, host mounts or credentials.
set -euo pipefail
image=${1:?exact image ID required}
[[ $image =~ ^sha256:[a-f0-9]{64}$ ]]
container=$(docker run -d --pull never --network none --read-only --cap-drop ALL \
    --security-opt no-new-privileges --pids-limit 64 --memory 512m \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=32m,mode=1777 \
    --tmpfs /data:rw,noexec,nosuid,nodev,size=48m,mode=0750,uid=1000,gid=1000 \
    --tmpfs /etc/letsencrypt:rw,noexec,nosuid,nodev,size=8m,mode=0700,uid=1000,gid=1000 \
    "$image")
cleanup() {
    local rc=$?
    if ((rc != 0)); then docker logs --tail 25 "$container" >&2 || :; fi
    docker rm -f -v "$container" >/dev/null || :
}
trap cleanup EXIT
for _ in $(seq 1 35); do
    state=$(docker inspect "$container" --format '{{.State.Running}} {{.State.Health.Status}}')
    [[ $state == 'true healthy' ]] && break
    [[ $state == true* ]] || exit 1
    sleep 1
done
[[ $state == 'true healthy' ]]
docker exec -i "$container" sh -se <<'TEST'
test "$(id -u)" = 1000
grep -Eq '^CapEff:[[:space:]]+0+$' /proc/self/status
grep -Eq '^NoNewPrivs:[[:space:]]+1$' /proc/self/status
test -s /data/database.sqlite
test -f /data/logs/logrotate.status
test "$(stat -c '%a' /tmp/npm/production.conf)" = 600
! touch /etc/nginx/not-writable 2>/dev/null
wget -qO /tmp/npm-ui.html http://127.0.0.1:8181/
cmp /tmp/npm-ui.html /app/frontend/index.html
wget -qO /tmp/npm-health.json http://127.0.0.1:8181/api/
node -e 'const a=require("node:assert/strict"), r=require("/tmp/npm-health.json"); a.equal(r.status,"OK"); a.equal(r.setup,false);'

certbot plugins --init --config-dir /etc/letsencrypt --work-dir /tmp/certbot --logs-dir /tmp/certbot-logs >/tmp/certbot-plugins.txt
grep -q '^\* webroot' /tmp/certbot-plugins.txt
mkdir -p /data/letsencrypt-acme-challenge/.well-known/acme-challenge
printf '%s\n' synthetic-webroot >/data/letsencrypt-acme-challenge/.well-known/acme-challenge/local-smoke
test "$(wget -qO- http://127.0.0.1/.well-known/acme-challenge/local-smoke)" = synthetic-webroot

umask 077
openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -days 1 \
    -subj /CN=npm-smoke.invalid -addext subjectAltName=DNS:npm-smoke.invalid \
    -keyout /tmp/npm/tls.key -out /tmp/npm/tls.crt 2>/dev/null
cat >/data/nginx/proxy_host/smoke.conf <<'NGINX'
server {
    listen 443 ssl;
    server_name npm-smoke.invalid;
    ssl_certificate /tmp/npm/tls.crt;
    ssl_certificate_key /tmp/npm/tls.key;
    location / { return 200 "synthetic TLS smoke\n"; }
}
NGINX
/usr/sbin/nginx -t -g 'error_log stderr;'
/usr/sbin/nginx -s reload
tls_ok=false
for _ in $(seq 1 12); do
    if openssl s_client -connect 127.0.0.1:443 -servername npm-smoke.invalid \
        -verify_hostname npm-smoke.invalid -verify_return_error -CAfile /tmp/npm/tls.crt \
        </dev/null >/tmp/npm/tls-check.log 2>&1; then
        tls_ok=true
        break
    fi
    sleep 0.25
done
"$tls_ok"
wget -qO /dev/null http://127.0.0.1:8181/api/
TEST
docker stop -t 8 "$container" >/dev/null
test "$(docker inspect "$container" --format '{{.State.ExitCode}}')" = 0
bash "$(dirname "$0")/test-dns-runtime.sh" "$image"
printf '%s\n' 'NPM_NATIVE_RUNTIME_SMOKE_OK'
