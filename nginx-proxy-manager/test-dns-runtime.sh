#!/usr/bin/env bash
# Isolated service discovery test: no network egress, published ports or host mounts.
set -euo pipefail
image=${1:?exact image ID required}
[[ $image =~ ^sha256:[a-f0-9]{64}$ ]]
network= backend= proxy=
cleanup() {
    local rc=$?
    if ((rc != 0)) && [[ -n $proxy ]]; then
        docker exec "$proxy" sh -c \
            'grep -E "no resolver defined|could not be resolved" /data/logs/fallback_error.log | tail -5' >&2 || :
    fi
    if [[ -n $proxy ]]; then docker rm -f -v "$proxy" >/dev/null || :; fi
    if [[ -n $backend ]]; then docker rm -f -v "$backend" >/dev/null || :; fi
    if [[ -n $network ]]; then docker network rm "$network" >/dev/null || :; fi
}
trap cleanup EXIT

network=$(docker network create --internal "npm-dns-smoke-$$-$RANDOM-$RANDOM")
runtime=(--pull never --network "$network" --read-only --cap-drop ALL
    --security-opt no-new-privileges --pids-limit 64)
backend=$(docker run -d "${runtime[@]}" --network-alias npm-smoke-backend \
    --memory 128m --entrypoint node "$image" -e \
    'require("node:http").createServer((req, res) => res.end(`dns-smoke:${req.url}`)).listen(8080, "0.0.0.0");')
proxy=$(docker run -d "${runtime[@]}" --memory 512m \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=32m,mode=1777 \
    --tmpfs /data:rw,noexec,nosuid,nodev,size=48m,mode=0750,uid=1000,gid=1000 \
    --tmpfs /etc/letsencrypt:rw,noexec,nosuid,nodev,size=8m,mode=0700,uid=1000,gid=1000 \
    "$image")
for _ in $(seq 1 35); do
    state=$(docker inspect "$proxy" --format '{{.State.Running}} {{.State.Health.Status}}')
    [[ $state == 'true healthy' ]] && break
    [[ $state == true* ]] || exit 1
    sleep 1
done
[[ $state == 'true healthy' ]]
docker exec -i "$proxy" sh -se <<'TEST'
cat >/data/nginx/proxy_host/resolver-smoke.conf <<'NGINX'
server {
    listen 80;
    server_name npm-dns-smoke.invalid;
    set $forward_scheme http;
    set $server npm-smoke-backend;
    set $port 8080;
    location / { include /etc/nginx/conf.d/include/proxy.conf; }
}
NGINX
/usr/sbin/nginx -t -g 'error_log stderr;'
/usr/sbin/nginx -s reload
for _ in $(seq 1 16); do
    body=$(wget -T 2 -qO- --header 'Host: npm-dns-smoke.invalid' \
        http://127.0.0.1/resolver-smoke || :)
    if [ "$body" = 'dns-smoke:/resolver-smoke' ]; then exit 0; fi
    sleep 0.25
done
printf '%s\n' 'Hostname proxy did not return the Docker service response' >&2
exit 1
TEST
printf '%s\n' 'NPM_HOSTNAME_PROXY_SMOKE_OK'
