# nginx

## Purpose

HTTP server with a generic runtime-mounted TLS example.

This document describes an image interface, not a deployed system.

## Build inputs

- Declared `FROM`: `ghcr.io/yonrasgg/ragnarsec-base:${BASE_TAG}`.
- Direct runtime additions (`nginx`, `openssl`, `pcre2`) have exact package
  versions recorded in [`versions.json`](../versions.json).

Read the Dockerfile for exact build arguments, package choices and download locations.
A tag is not immutable: resolve and review digests for a release. Availability and
support status of upstream versions must be checked before building.

## Hardening declared

- Last `USER` instruction: `ragnarsec`; verify the effective image user after building.
- The Dockerfile does not upgrade the entire inherited filesystem. Base updates
  are reviewed separately; nginx additions use explicit package versions.
- Dockerfile policy violations are enforced for this recipe, not only warned.
- Permission or ownership adjustments are present; review their exact paths and effect in the Dockerfile.

These are static observations, not proof of runtime isolation or vulnerability remediation.
Consumers must validate required capabilities, filesystem permissions and writable data paths.

## Patching

Rebuild from reviewed upstream inputs to apply build-time package changes.
An existing image is not patched merely because a new Dockerfile is committed.
Record the upstream and output digests, scanner/database version, findings and any
time-bounded exceptions. A successful package upgrade does not prove all CVEs are fixed.
Package pins improve input control but do not establish bit-for-bit reproducibility:
the parent digest, transitive dependencies and upstream package availability still
need to be recorded for the exact build. A missing pinned version must fail the build,
not trigger an unreviewed upgrade or fallback.

## Controls and evidence

| Control | Available evidence |
|---|---|
| Publication boundary and secret scanning | Repository guard, hooks and CI definitions; require a successful run for the release commit. |
| Image test definitions | `../tests/ragnarsec-nginx.yaml`; execution not evidenced by this documentation. |

The config test rejects deprecation warnings, including the former `listen ...
http2` syntax. HTTP/2 uses `http2 on;` separately from the TLS listener.

Defined test cases: `Nginx Version`, `Nginx Config Test`, `Nginx Config`, `Site Config`, `Log Directory`, `Run Directory`.

No built-image pass, SBOM, signature, multi-architecture result or runtime smoke-test
receipt is attached to this documentation update. Do not treat the catalog as an approval.

## Using the image

A local build example (does not publish or deploy):

```sh
docker build -f nginx/Dockerfile -t example/nginx:review nginx/
```

Images named in `FROM` must be available to the builder. Inspect build arguments before use.
Declared image ports: `8443`. Declaring a port does not publish it.
Provide credentials and environment-specific settings at runtime using the consumer's
approved mechanism. Never copy real environment files, keys, certificates, inventories
or production configuration into the build context. Keep sample identifiers reserved.

## License

The wrapper source declares GPLv3; see [LICENSE](../LICENSE). Upstream components
retain their own licenses and redistribution conditions.
The license scan is currently informational (`--exit-code 0`), not an approved
license allowlist. Its severity labels are not CVE severities. Review notices,
source obligations and unknown license metadata before redistribution; this
documentation does not declare legal compliance or waive any obligation.
