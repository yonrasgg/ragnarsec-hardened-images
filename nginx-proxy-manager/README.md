# nginx-proxy-manager

## Purpose

Reverse proxy with a web administration UI used to publish internal HTTP services
over TLS. This document describes an image interface, not a deployed system.

## Build inputs

- Declared `FROM`: `docker.io/jc21/nginx-proxy-manager:2.16.0@sha256:4393e642e233e5efd5adeb7f10918d4aaea71c9ed875b94190273fc8e87f9594`
- Upstream version observed in `/app/package.json`: **2.16.0**; `latest` resolves to the same digest at review time.
- Upstream project: Nginx Proxy Manager (MIT). The wrapper is GPL-3.0.
- The multi-arch index includes `linux/arm64`; the consumer fleet is mixed
  (`aarch64` and `x86_64`), so both platforms must be validated before promotion.

A digest pins the reviewed bytes, not the upstream trustworthiness. Re-resolve and
re-review the digest for every release.

## Hardening declared

- Debian packages inherited from upstream are upgraded during build, then caches removed.
- No `USER` override: the upstream entrypoint requires root to bind 80/443 and then
  drops privileges. Runtime hardening belongs to the consumer: `no-new-privileges`,
  `cap_drop` of everything except the caps the entrypoint needs, no Docker socket
  and no privileged mode.
- No credentials, certificates, environment files or inventories are embedded.
- Observed on a local amd64 build (image id `a12936ca0cb24b4af727ec0cf4e43945cdc0a89c39c60287864203495babdfbd`):
  effective user `root`, `nginx` is OpenResty at `/usr/sbin/nginx`, Node v22,
  `/app` and `/data` exist, and no Docker socket is present.

These are static observations, not proof of runtime isolation or vulnerability
remediation. Validate effective user, capabilities and writable paths after building.

## Patching

Rebuild from a newly reviewed upstream digest to inherit upstream fixes, then
re-run the upgrade step. An existing image is not patched because a Dockerfile
changed; only a new digest carries the evidence.

## Controls and evidence

Required before promotion: container-structure test, vulnerability scan by digest,
SBOM per platform, signed index and recorded upstream/output digests.

No built-image pass is claimed in this document. Definitions are not proof of a
passing build, and catalog inclusion does not identify a deployed service.

## Using the image

- Persist `/data` (configuration, database, certificates) and `/etc/letsencrypt`.
- Publish 80/81/443 only on an internal management address; never on a public interface.
- The admin UI (81) must not be exposed beyond the administrative network.
- TLS material for consumers is issued by the internal CA; it is not baked into the image.
- Pin the index digest or the platform digest; tags are mutable.

## License

The wrapper (Dockerfile, tests, documentation) is GPL-3.0. Nginx Proxy Manager and
its bundled OpenResty/Node components keep their own upstream licenses.
