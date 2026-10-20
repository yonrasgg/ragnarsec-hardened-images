# buildkit

## Purpose

Container image build service.

This document describes an image interface, not a deployed system.

## Build inputs

- Declared `FROM`: `ghcr.io/yonrasgg/ragnarsec-base:${BASE_TAG}`.
- `buildkitd` and `buildctl` come from the pinned upstream release and are verified by SHA256.

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
| Image test definitions | `../tests/ragnarsec-buildkit.yaml`; execution not evidenced by this documentation. |

Defined test cases: `BuildKit Version`, `BuildKit Client Version`, `Entrypoint Syntax`, `BuildKit Daemon`, `BuildKit Client`, `Runc`, `Rootless Entrypoint`.

No built-image pass, SBOM, signature, multi-architecture result or runtime smoke-test
receipt is attached to this documentation update. Do not treat the catalog as an approval.

## Runtime requirements

The daemon runs as `ragnarsec` inside a RootlessKit user and network namespace.
The container runtime must permit user namespaces, mounts and the `/dev/net/tun`
and `/dev/fuse` devices required by that setup. In Docker this may require
`--privileged` or an equivalent reviewed combination of capabilities, devices and
seccomp settings; grant only what the deployment actually needs and do not expose
the BuildKit socket outside the trusted workload.

## Using the image

A local build example (does not publish or deploy):

```sh
docker build -f buildkit/Dockerfile -t example/buildkit:review buildkit/
```

Images named in `FROM` must be available to the builder. Inspect build arguments before use.
Provide credentials and environment-specific settings at runtime using the consumer's
approved mechanism. Never copy real environment files, keys, certificates, inventories
or production configuration into the build context. Keep sample identifiers reserved.

## License

The wrapper source declares GPLv3; see [LICENSE](../LICENSE). Upstream components
retain their own licenses and redistribution conditions.
