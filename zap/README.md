# zap

## Purpose

Web application security testing tooling; targets require authorization.

This document describes an image interface, not a deployed system.

## Build inputs

- Declared `FROM`: `ghcr.io/yonrasgg/ragnarsec-base:${BASE_TAG}`.
- ZAP 2.17.0 is the upstream Linux x86_64 archive, verified by SHA256; other target architectures are rejected.

Read the Dockerfile for exact build arguments, package choices and download locations.
A tag is not immutable: resolve and review digests for a release. Availability and
support status of upstream versions must be checked before building.

## Hardening declared

- Last `USER` instruction: `ragnarsec`; verify the effective image user after building.
- The Dockerfile invokes `apk upgrade` during build.
- Permission or ownership adjustments are present; review their exact paths and effect in the Dockerfile.

These are static observations, not proof of runtime isolation or vulnerability remediation.
Consumers must validate required capabilities, filesystem permissions and writable data paths.

## Patching

Rebuild from reviewed upstream inputs to apply build-time package changes.
An existing image is not patched merely because a new Dockerfile is committed.
Record the upstream and output digests, scanner/database version, findings and any
time-bounded exceptions. A successful package upgrade does not prove all CVEs are fixed.

## Controls and evidence

| Control | Available evidence |
|---|---|
| Publication boundary and secret scanning | Repository guard, hooks and CI definitions; require a successful run for the release commit. |
| Image test definitions | `../tests/ragnarsec-zap.yaml`; execution not evidenced by this documentation. |

Defined test cases: `Entrypoint Syntax`, `Entrypoint Requires API Key`, `Java Version`, `Python Version`, `ZAP Help`, `ZAP Script`, `ZAP Entrypoint`, `Java Runtime`.

No built-image pass, SBOM, signature, multi-architecture result or runtime smoke-test
receipt is attached to this documentation update. Do not treat the catalog as an approval.

## Using the image

A local build example (does not publish or deploy):

```sh
docker build -f zap/Dockerfile -t example/zap:review zap/
```

The default command requires `ZAP_API_KEY`; startup fails closed without it. The
entrypoint binds ZAP to `ZAP_HOST` (default `0.0.0.0`) on `ZAP_PORT` (default
`8080`) and passes the key through `api.key`. Do not set
`api.disablekey=true` outside a disposable, isolated test. Restrict network access
to the API to the authorized scanner control plane.

Images named in `FROM` must be available to the builder. Inspect build arguments before use.
Provide credentials and environment-specific settings at runtime using the consumer's
approved mechanism. Never copy real environment files, keys, certificates, inventories
or production configuration into the build context. Keep sample identifiers reserved.

## License

The wrapper source declares GPLv3; see [LICENSE](../LICENSE). Upstream components
retain their own licenses and redistribution conditions.
