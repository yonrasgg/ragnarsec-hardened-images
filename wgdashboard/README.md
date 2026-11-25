# wgdashboard

## Purpose

Web UI for WireGuard inventory and, in write mode, peer management. This wrapper
pins the upstream image and documents a **read-only deployment contract**.
This document describes an image interface, not a deployed system.

## Build inputs

- `FROM ghcr.io/wgdashboard/wgdashboard@sha256:8c5b550db4fda04eff06e96af801499be485c73e0912fcf0c1031babca0f7e7b`
  (multi-arch index with `linux/amd64` and `linux/arm64`).
- Upstream runs Alpine with Python 3.15 and `wireguard-tools`.
- No `apk upgrade`: this is an upstream image; patching moves the digest.

## Hardening declared

- Digest pinned; version tag mutable by design.
- O1 (`WG_DASHBOARD_READ_ONLY=1`, the image default): the image runs as
  `1000:1000` and never calls the inherited root entrypoint. The legacy root
  behavior below describes the inherited upstream mode only and is **not** the
  O1 deployment contract.
- Consumer contract for the inherited mode, enforced at deployment:
  - `/etc/wireguard` mounted **read-only**;
  - `/etc/wireguard/WGDashboard_Backup` must **pre-exist** in that host directory
    and be mounted **writable** (`:rw`) as a separate volume. Upstream creates
    this directory unconditionally during startup and writes database dumps into
    it; without the writable mount the process fails with
    `OSError: [Errno 30] Read-only file system: '/etc/wireguard/WGDashboard_Backup'`
    and the UI never starts.
  - **no** `NET_ADMIN`, no host network, no privileged mode;
  - `no-new-privileges`;
  - reachable only through the internal proxy, never published on a public interface.
- Consequence: without `NET_ADMIN`, live handshakes and traffic are **not** shown.
  The UI is an inventory view. If live status is required, a host-side exporter or
  an explicitly authorized capability is a separate change.

## Patching

Rebuild from a new reviewed upstream digest, re-scan, re-sign. Do not patch inside
the running container and do not add `apk upgrade` to this Dockerfile.

## Controls and evidence

Required before promotion: container-structure test, trivy scan, SBOM and signed
digest. Deployment additionally verifies the compose contract (ro mount, writable
backup volume, no caps).

Observed on a local amd64 run of the pinned digest: a fully read-only
`/etc/wireguard` stops at `WireguardConfiguration.__init__` with the read-only
filesystem error above; after pre-creating `WGDashboard_Backup` in the host
directory and mounting a writable volume there, the container reports healthy and
the host configuration file keeps its original SHA-256. That is a startup
observation, not a vulnerability or hardening result.

No built-image pass is claimed in this document. Definitions are not proof of a
passing build.

### O1 native HTTPS contract

- Gunicorn serves HTTPS in the foreground on `0.0.0.0:10086` with
  `--certfile`/`--keyfile`; there is no plaintext listener, sidecar, daemon,
  PID file or control socket. The inherited PID-file healthcheck is replaced by
  an HTTPS probe that requires HTTP 200 on `/api/handshake`, a trusted CA and
  the exact backend TLS name.
- TLS material is **never** in the image: bind-mount
  `/run/secrets/wgdashboard/{server.crt,server.key,ca.crt}` as regular files,
  mode `0600`, owner uid `1000`, read-only. The launcher rejects missing,
  symlinked or wrongly located files with exit 64 before binding any socket.
- The fail-closed keyless preflight runs before the HTTP server. The reviewed
  guard project only public WireGuard fields; mutations, backup download, OIDC
  and API-key access are denied, and configuration status is reported as
  unknown rather than "Off".
- Required runtime flags: `--read-only`, `--cap-drop ALL`,
  `--security-opt no-new-privileges=true`, one internal network, **no published
  host ports**, uid `1000:1000`. A `:rw` backup path is not used in O1.

## Using the image

- Port `10086/tcp` serves the UI; it must sit behind the internal TLS proxy.
- Mount the host `/etc/wireguard` read-only; never share the host network.
- Pre-create the backup directory on the host and mount it writable:

  ```sh
  mkdir -p /etc/wireguard/WGDashboard_Backup /var/lib/wgdashboard/backup
  docker run -d \
    --security-opt no-new-privileges=true \
    -v /etc/wireguard:/etc/wireguard:ro \
    -v /var/lib/wgdashboard/backup:/etc/wireguard/WGDashboard_Backup:rw \
    -v /var/lib/wgdashboard/data:/data \
    ghcr.io/wgdashboard/wgdashboard@sha256:8c5b550db4fda04eff06e96af801499be485c73e0912fcf0c1031babca0f7e7b
  ```

  The mountpoint must exist before Docker mounts the read-only parent; otherwise
  container creation fails while creating the nested mount. Do not make the whole
  configuration directory writable.
- Size reference: upstream image is ~233 MB; wrapper adds only metadata.
- If the application refuses to start, read the log before relaxing any mount:
  a missing backup mount is a provisioning error, not a reason to drop `:ro`.

## License

Wrapper: GPL-3.0. WGDashboard and its dependencies keep their own upstream licenses.
