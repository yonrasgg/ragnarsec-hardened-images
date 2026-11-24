# postgres

## Purpose

PostgreSQL database runtime.

This document describes an image interface, not a deployed system.

## Build inputs

- PostgreSQL 15.20 from the official `postgres:15-alpine` OCI index pinned in
  the Dockerfile. The index contains AMD64 and ARM64 platform images.
- Alpine's `libxml2=2.13.9-r3` updates the version inherited from that index.

Read the Dockerfile for exact build arguments, package choices and download locations.
A tag is not immutable: resolve and review digests for a release. Availability and
support status of upstream versions must be checked before building.

## Hardening declared

- Last `USER` instruction: `postgres`; verify the effective image user after building.
- The server starts as `postgres` with read-only configuration; PostgreSQL
  data remains writable through the upstream volume contract.
- Permission or ownership adjustments are present; review their exact paths and effect in the Dockerfile.

These are static observations, not proof of runtime isolation or vulnerability remediation.
Consumers must validate required capabilities, filesystem permissions and writable data paths.

## Patching

Rebuild from reviewed upstream inputs to apply build-time package changes.
An existing image is not patched merely because a new Dockerfile is committed.
Record the upstream and output digests, scanner/database version, findings and any
time-bounded exceptions.

## Controls and evidence

| Control | Available evidence |
|---|---|
| Publication boundary and secret scanning | Repository guard, hooks and CI definitions; require a successful run for the release commit. |
| Image test definitions | `../tests/ragnarsec-postgres.yaml`; execution not evidenced by this documentation. |

Defined test cases: `Postgres Version`, `Postgres Config`, `HBA Config`, `Gosu Removed`, `SCRAM-SHA-256 Auth Enforced`, `HBA IPv4 Uses SCRAM`.

No built-image pass, SBOM, signature, multi-architecture result or runtime smoke-test
receipt is attached to this documentation update. Do not treat the catalog as an approval.

## Using the image

A local build example (does not publish or deploy):

```sh
docker build -f postgres/Dockerfile -t example/postgres:review postgres/
```

Images named in `FROM` must be available to the builder. Inspect build arguments before use.
Provide credentials and environment-specific settings at runtime using the consumer's
approved mechanism. Never copy real environment files, keys, certificates, inventories
or production configuration into the build context. Keep sample identifiers reserved.

## License

The wrapper source declares GPLv3; see [LICENSE](../LICENSE). Upstream components
retain their own licenses and redistribution conditions.
