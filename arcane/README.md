# arcane

## Purpose

Hardened wrapper for [Arcane](https://github.com/getarcaneapp/arcane), a Docker
management UI intended to replace Portainer in the RagnarSec stack. This document
describes an image interface, not a deployed service or a published digest.

## Build inputs

- `FROM ghcr.io/getarcaneapp/arcane:v2.17.3@sha256:2e0dc9f5ef03599181a49baf6470055d82e24d9cb15bbc62498ea642c0f882a7`
  (reviewed multi-arch index; `linux/amd64` and `linux/arm64`).
- Upstream license: **BSD-3-Clause**. Wrapper license: **GPL-3.0**.
- Upstream runtime: static Go binary on a Debian trixie distroless rootfs.
  No shell, no package manager, no `apk`/`apt` upgrade path.
- Observed `linux/amd64` image size on 2026-11-04: **166,476,099 bytes**.
- Wrapper runtime user: `1000:1000` (overrides upstream `0:0`). Upstream can
  drop to `PUID`/`PGID`; this wrapper does not use that path.

## Hardening declared

- Upstream index digest pinned; the version tag is mutable by design.
- No `RUN`, no downloads, no build context copied into the image: the wrapper
  adds labels, a healthcheck and the declared runtime contract only.
- No shell or package manager in the image (`/bin/sh` and `/usr/bin/apt` absent).
- Runs as non-root `1000:1000`; no root exception is declared.
- Consumer contract, enforced at deployment:
  - `/app/data` owned by `1000:1000` and writable by it;
  - Docker access through a restricted socket proxy or an explicitly granted
    socket; a non-root container user cannot write the rootless socket owned by
    container root in the default userns mapping;
  - `no-new-privileges`; `cap_drop: ALL`; no `privileged`, no host network;
  - port `3552/tcp` reachable only through the internal TLS proxy, never
    published on a public interface;
  - `/app/data` persistent and backed up; secrets supplied at runtime through
    the environment or a file, never baked into the image.

## Encryption key — observed behavior

The upstream `.env.example` documents `ARCANE_ENCRYPTION_KEY`, but in the pinned
`v2.17.3` image a production container started only when **`ENCRYPTION_KEY`** was
set. With only `ARCANE_ENCRYPTION_KEY` the process panicked with
`ENCRYPTION_KEY passphrase must be at least 32 characters in production`.

Observed on 2026-11-04 with a disposable local container:

| Environment | Result |
|---|---|
| `ARCANE_ENCRYPTION_KEY` only, 32 chars | panic before serving |
| `ENCRYPTION_KEY` only, 32 chars | started; `/app/arcane health` returned 0 |
| both variables | started (the second test also proved the key is read) |

Until upstream resolves the naming, the deployment contract requires
`ENCRYPTION_KEY` of at least 32 characters and records which variable was used.
Do not store the key in this repository.

## Patching

Move the pinned upstream digest to a new reviewed release, rebuild the wrapper,
re-scan and re-sign. Do not add a shell or package manager to the image and do
not patch inside a running container.

## Controls and evidence

Required before promotion: container-structure test, Trivy vulnerability/secret/
misconfiguration scan, license scan, SBOM, size budget and signed digest.
No built-image pass is claimed in this document. Definitions are not proof of a
passing build; the receipt must identify the exact image digest and platform.

## Docker socket access

The wrapper does not grant Docker access by itself. A direct mount of a rootless
socket was tested as uid 1000 and returned `permission denied`: in the default
userns mapping the socket is owned by container root, not by the non-root app
user. Use a restricted socket proxy with an explicit endpoint allowlist, or
verify the group mapping before granting the socket. The socket is a privileged
interface even when the container is non-root.

## Using the image

Pin the published digest, not a mutable tag. Example contract (adapt the socket
path and identity to the host):

```sh
docker run -d \
  --name arcane \
  --user 1000:1000 \
  --security-opt no-new-privileges=true \
  --cap-drop ALL \
  -e ENCRYPTION_KEY="$(openssl rand -hex 32)" \
  -e DOCKER_HOST=tcp://docker-socket-proxy:2375 \
  -v /srv/arcane/data:/app/data \
  -p 127.0.0.1:3552:3552 \
  ghcr.io/yonrasgg/ragnarsec-arcane@sha256:<published-digest>
```

- Put `3552/tcp` behind the internal TLS proxy; do not expose it directly.
- Back up `/app/data` and the encryption key together; losing either makes the
  stored secrets unreadable.
- The Docker socket is a privileged interface. Grant it only to the Arcane
  container and review which containers it can control.
- Healthcheck: `/app/arcane health --timeout 2s` (exec form, no shell).

## License

Wrapper: GPL-3.0. Arcane and its dependencies retain their own upstream licenses.
