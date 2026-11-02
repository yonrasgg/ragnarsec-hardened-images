# base-min

## Purpose

Minimal runtime floor without shell, package manager or busybox. Consumers build
their binaries in a separate stage and copy them into this image. This document
describes an image interface, not a deployed system.

## Build inputs

- `FROM alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a`
  (build stage only; the final stage is `scratch`).
- Pinned packages: `ca-certificates=20261020-r0`, `tini=0.19.0-r3`.
- No `apk upgrade`: patching means moving to a new Alpine digest and re-pinning.

## Hardening declared

- Final stage is `scratch`: no shell, no `apk`, no busybox.
- Only CA trust files, musl libc loader, `tini`, passwd/group, Alpine release
  identification and a filtered APK database for packages represented by these
  runtime files. The builder's shell and package manager are not copied.
- Runs as `1000:1000`; `/sbin/nologin` is a string in `passwd`, not a binary.
- No credentials, no TLS material, no inventories.

Absence of a shell is a deliberate control, not an oversight: debugging uses an
ephemeral debug container or a sidecar, never a shell inside the workload.

## Patching

Move the Alpine digest and the package pins together, rebuild, re-scan. There is
no in-place upgrade path by design; `apk upgrade` is forbidden by policy.

## Controls and evidence

Required before promotion: container-structure test, size budget check, trivy
scan, SBOM with the five runtime APK packages, and signed digest. Alpine 3.21
reached its published end of support on 2026-11-01; the build stage is now
pinned to Alpine 3.24.3. Validation on both architectures remains necessary
before publication. The Trivy gate also rejects end-of-support OS releases.

No built-image pass is claimed in this document. Definitions are not proof of a
passing build.

## Using the image

- Consumer recipes: `FROM alpine:<digest> AS build`, compile/install, then
  `FROM ghcr.io/yonrasgg/ragnarsec-base-min:<tag>` and `COPY --from=build`.
- `HEALTHCHECK` without shell requires a dedicated binary in the consumer image.
- Budget: 10 MB. The prototype measured 1.53 MB on amd64.

## License

Wrapper: GPL-3.0. Alpine, musl, tini and ca-certificates keep their own licenses.
