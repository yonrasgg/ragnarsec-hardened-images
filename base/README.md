# base

## Purpose

Minimal shared Linux runtime for image recipes.

This document describes an image interface, not a deployed system.

## Build inputs

- Declared `FROM`: `alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a`
  (multi-platform index; validate each platform requested for publication).
- Pinned packages: `ca-certificates=20261020-r0`, `tzdata=2026e-r0`,
  `tini=0.19.0-r3`. These versions were checked in the Alpine 3.24 repository
  for amd64; arm64 validation requires a suitable runner.

Read the Dockerfile for exact build arguments, package choices and download locations.
A tag is not immutable: resolve and review digests for a release. Availability and
support status of upstream versions must be checked before building.

## Hardening declared

- Final image user: `1000:1000` (`ragnarsec`); verify the effective user after building.
- No `apk upgrade`: changing the reviewed Alpine index digest and package pins
  requires a new build and vulnerability scan. Alpine 3.21 is end-of-support;
  `3.24.3` is the current reviewed build input, not proof of a published image.

These are static observations, not proof of runtime isolation or vulnerability remediation.
Consumers must validate required capabilities, filesystem permissions and writable data paths.

## Patching

Rebuild from reviewed upstream inputs to apply build-time package changes.
An existing image is not patched merely because a new Dockerfile is committed.
Record the upstream and output digests, scanner/database version, findings and any
time-bounded exceptions. No clean-scan claim is implied by this digest update.

## Controls and evidence

| Control | Available evidence |
|---|---|
| Publication boundary and secret scanning | Repository guard, hooks and CI definitions; require a successful run for the release commit. |
| Image test definitions | `../tests/ragnarsec-base.yaml`; execution not evidenced by this documentation. |

Defined test cases: `Tini Version`, `User is non-root`, `CA Certificates`, `Tini`, `No sudo`.

No built-image pass, SBOM, signature, multi-architecture result or runtime smoke-test
receipt is attached to this documentation update. Do not treat the catalog as an approval.

## Using the image

A local build example (does not publish or deploy):

```sh
docker build -f base/Dockerfile -t example/base:review base/
```

Images named in `FROM` must be available to the builder. Inspect build arguments before use.
Provide credentials and environment-specific settings at runtime using the consumer's
approved mechanism. Never copy real environment files, keys, certificates, inventories
or production configuration into the build context. Keep sample identifiers reserved.

## License

The wrapper source declares GPLv3; see [LICENSE](../LICENSE). Upstream components
retain their own licenses and redistribution conditions.
