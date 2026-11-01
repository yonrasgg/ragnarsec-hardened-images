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
- Runs as root because the upstream entrypoint initializes its own configuration.
  This is declared as an exception (`allow-root`), not as a recommendation.
- Consumer contract, enforced at deployment:
  - `/etc/wireguard` mounted **read-only**;
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
digest. Deployment additionally verifies the compose contract (ro mount, no caps).

No built-image pass is claimed in this document. Definitions are not proof of a
passing build.

## Using the image

- Port `10086/tcp` serves the UI; it must sit behind the internal TLS proxy.
- Mount the host `/etc/wireguard` read-only; never share the host network.
- Size reference: upstream image is ~233 MB; wrapper adds only metadata.
- If the application refuses to start with a read-only configuration, stop and
  review the contract instead of relaxing the mount.

## License

Wrapper: GPL-3.0. WGDashboard and its dependencies keep their own upstream licenses.
