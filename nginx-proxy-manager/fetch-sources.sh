#!/bin/sh
set -eu

fetch() {
    curl --fail --silent --show-error --location --retry 2 --max-time 80 \
        --proto '=https' --proto-redir '=https' "$3" --output "$1"
    printf '%s  %s\n' "$2" "$1" | sha256sum -c -
}

fetch npm.tar.gz 35ac72768e04d0cfc2579b19c01f1e912f9551cabe5b64866ebb20ff8152c304 \
    https://codeload.github.com/jc21/nginx-proxy-manager/tar.gz/89c43f564422a78bd0732046b636cbcd5e566b03
fetch openresty.tar.gz b569c63b420f80a4ac8466f2deffe73ed93ab760026532e039c3658409a997f4 \
    https://openresty.org/download/openresty-1.31.8.1.tar.gz
fetch geoip2.tar.gz 52b76bfe81c75a4decfbf526e030a5bb4887b5c209343162fa452526572018b7 \
    https://codeload.github.com/leev/ngx_http_geoip2_module/tar.gz/cbaa35461c62a99d2577e6bae3273492502d8769
fetch yarn.tgz c17d3797fb9a9115bf375e31bfd30058cac6bc9c3b8807a3d8cb2094794b51ca \
    https://registry.npmjs.org/yarn/-/yarn-1.22.22.tgz

mkdir -p patches

# The upstream project's GitHub-verified merge contains the reviewed backports.
vendor=https://raw.githubusercontent.com/NginxProxyManager/docker-nginx-full/38654e0736c19578e0045678480622e48473878c/docker/patches
fetch patches/http2-data-frame-queue.patch 84cdee7b886b08794e0864fbd11dc77284f45c8c7b2c037eef4ee65167f48f65 "$vendor/http2-data-frame-queue.patch"
fetch patches/CVE-2026-123633.patch e28b6463fb3a9d6807d64c5db327138e4e382bb551f02318726356930dda28d7 "$vendor/CVE-2026-123633.patch"
fetch patches/CVE-2026-123007.patch 897726fb203e1a91675d11b29db74dd3545f731daa05cf25e2214de83a32e32c "$vendor/CVE-2026-123007.patch"

# This pins a verified signature. See README for the outstanding trust anchor.
curl --fail --silent --show-error --location --retry 2 --max-time 30 \
    --proto '=https' --proto-redir '=https' https://openresty.org/download/openresty-1.31.8.1.tar.gz.asc -o openresty.asc
keyring=$(mktemp -d)
trap 'rm -r "$keyring"' EXIT
gpg --homedir "$keyring" --batch --import openresty-release-key.asc
gpg --homedir "$keyring" --batch --status-fd 1 --verify openresty.asc openresty.tar.gz > "$keyring/status"
grep -F '[GNUPG:] VALIDSIG 25451EB088460026195BD62CB550E09EA0E98066 ' "$keyring/status"

for name in npm openresty geoip2; do
    mkdir "$name"
    tar -xzf "$name.tar.gz" --strip-components=1 -C "$name"
done
