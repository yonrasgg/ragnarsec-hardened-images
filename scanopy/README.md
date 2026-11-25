# ragnarsec-scanopy

**No built-image pass.** Definition and provenance only; the signed digest from
the governed promotion pipeline is the release truth.

## Purpose

Catalog recipe for the **Scanopy** network-discovery server (canonical
spelling). This is a private, non-discovering continuity deployment: panel and
server only, no discovery daemon, no host network, no published port. The
runtime target is `odin` (`x86_64`).

## Build inputs

The runtime layer is an immutable data asset attached to GitHub release
`scanopy-candidate-20261125` in this repository:

- asset `rootfs.tar.gz`, SHA-256
  `e30914e30ffa14f42224b3b94cee007859639d8fa4a2b2741ea9c7452cba4d13`,
  pinned with `ADD --checksum` in the Dockerfile;
- extracted from `candidate-image.tar` SHA-256
  `a2b23ebcbd2a4674a0a26869c473473533c5fa50c3c51f6bfe6811a372259c3d`
  (local config ID `sha256:bf9ce218…`, a configuration ID, not a release digest);
- contents: Debian 13.8 base with pinned `base-files`, `libc6`, `libgcc-s1`,
  `gcc-14-base`; upstream server ELF `/usr/local/bin/server`; static UI in
  `/app/static`; no shell and no package manager;
- no new egress host: `github.com` and
  `release-assets.githubusercontent.com` are already in
  `tools/build-egress.json`.

## Hardening declared

- non-root runtime `1000:1000`, working directory `/app`;
- exec-form entrypoint, no shell, no package manager, no Docker socket;
- single local rootfs copy onto `scratch` — no build-time package installation;
- structure test uses file-existence and metadata assertions only, because the
  runtime has no shell.

## Patching

There is no in-image patch mechanism. Moving to a new rootfs means a new
checksum-pinned release asset, a new reviewed digest and a full re-validation.
The vulnerability below is recorded, not silently suppressed.

Accepted risk `GHSA-82j2-j2ch-gfr8` (rustls-webpki 0.101.7, HIGH) is linked in
the opaque upstream ELF. No vendored server source and no local Rust toolchain
exist here, so `cargo update -p rustls-webpki` cannot produce a byte-comparable
corrected ELF against `8825972f…`. Trivy sees no cargo-auditable metadata and
reports 0 HIGH / 0 CRITICAL; the VEX records the component as `affected` with
owner acceptance into continuity on 2026-11-25. Re-review before enabling
discovery or untrusted ingress. The single reviewed layer is used on both
native targets; the binary is AMD64 and the ARM64 index entry exists for
catalog parity, not as a deployment target.

## Controls and evidence

- Trivy 0.76.0, `vuln,secret,misconfig`, `HIGH,CRITICAL`, image-config scanners,
  `--ignorefile /dev/null`: 0 findings for the reviewed layer;
- `container-structure-test` 2.0.0: 6 file/metadata checks pass;
- `hadolint` 2.15.1 with `--failure-threshold warning`: clean;
- no image size budget entry: uncompressed layer is 83.6 MB and is covered by
  the reviewed receipt; no oversized file is committed to git;
- VEX in `vex/ragnarsec-scanopy.openvex.json`, registered in
  `vex/exceptions.json` with an expiry; publication boundary stays clean.

## Using the image

Deploy only by the signed multi-arch index digest published from `main`:
read-only root filesystem, `cap_drop: ALL`, `no-new-privileges`, internal
network, no host ports, dedicated PostgreSQL on the same internal network with
a local mode-0600 env file. Do not publish a port or add public DNS.

## License

Recipe and documentation: GPL-3.0, matching this repository. The upstream
Scanopy binary and UI retain their producer's license and are not relicensed.
