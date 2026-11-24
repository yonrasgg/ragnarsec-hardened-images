# postgres-exporter

## Purpose

PostgreSQL metrics exporter.

This document describes an image interface, not a deployed system.

## Build inputs

- PostgreSQL Exporter v0.21.1, pinned to the upstream amd64/arm64 OCI index.
- The pipeline builds a `ragnarsec-base-min` parent for the same platform.

## Hardening declared

- Runtime UID/GID `1000:1000` with the baseline `tini` entrypoint.
- The final stage copies the read-only binary and upstream notices into a base
  with no shell or package manager.

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
| Image test definitions | `../tests/ragnarsec-postgres-exporter.yaml`; execution not evidenced by this documentation. |

Defined test cases: `Postgres Exporter Version`, `Postgres Exporter Binary`.
Jenkins checks each platform against a 32 MiB uncompressed layer budget.

No built-image pass, SBOM, signature, multi-architecture result or runtime smoke-test
receipt is attached to this documentation update. Do not treat the catalog as an approval.

## Using the image

A local build example (does not publish or deploy):

```sh
docker build -f postgres-exporter/Dockerfile -t example/postgres-exporter:review postgres-exporter/
```

Images named in `FROM` must be available to the builder. Inspect build arguments before use.
Declared image ports: `9187`. Declaring a port does not publish it.
Provide credentials and environment-specific settings at runtime using the consumer's
approved mechanism. Never copy real environment files, keys, certificates, inventories
or production configuration into the build context. Keep sample identifiers reserved.

## License

The wrapper source declares GPLv3; see [LICENSE](../LICENSE). Upstream components
retain their own licenses and redistribution conditions.
