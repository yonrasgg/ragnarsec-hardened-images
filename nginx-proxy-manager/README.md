# nginx-proxy-manager

## Purpose

Reverse proxy built from official Nginx Proxy Manager 2.17.1 source, with its
web UI, OpenResty/GeoIP2, the Node backend and Certbot. This document describes
an image interface, not a deployed system.

## Build inputs

The recipe builds from the pinned Alpine and Node indexes, not the upstream
Debian runtime or prebuilt local components. `fetch-sources.sh` pins the
NPM, OpenResty, GeoIP2, Yarn and vendor backport bytes. The two Yarn lockfiles
constrain dependencies; `backend-lock.patch` updates the ProxyAgent chain.
`certbot-requirements.txt` pins all 17 Python packages with wheel hashes for
Linux AMD64 and ARM64 on musl. Validate both architectures independently.

The pinned OpenResty archive and detached signature match the staged public
key. Its full fingerprint still needs independent confirmation from an
authoritative source before promotion; the vendor download page lists the
short key ID. A valid signature with a pinned key is not that confirmation.

## Hardening declared

- The final image starts as UID/GID `1000:1000`. Tini supervises a startup
  script that generates a per-start peer secret in `/tmp` for the admin proxy.
- The final layers do not contain the OpenResty build tree or upstream test
  CA. Only the PEM value in the certificate upload API example is removed;
  the live schema is unchanged. Trivy secret scanning stays enabled.
- Runtime must not use a socket mount, privileged mode or root. Use a
  read-only root filesystem, no added capabilities, and writable mounts for
  `/data`, `/etc/letsencrypt` (both pre-owned by UID/GID 1000), and `/tmp` as a
  private tmpfs. For ports below 1024, verify the container network namespace
  supports non-root binds without additional capabilities.
- The admin proxy binds to container loopback port 8181; the Node API is also
  loopback-only. A host `ports` mapping is not an admin access design. No
  external listener, resolver change, or release rollout is authorized here.
- This candidate targets IPv4 and ACME HTTP-01. IPv6, automatic external
  IP-range downloads, and writable runtime installation of DNS plugins are
  outside this contract. Existing DNS-01 state must not be migrated onto it.

## Patching

Refresh a supported source or package version, verify the updated source
provenance, then rebuild and rescan both architectures. Do not substitute an
unreviewed runtime or use scanner exclusions for deleted fixtures.

## Controls and evidence

Run the complete image Trivy gate and structure/functional tests on AMD64
and native ARM64 using the exact PR commit. CI adds exact image file hashes
and source metadata for the compiled/copied binaries in `runtime-components.json`
to Trivy's package SBOM; this does not change what the scanner covers.
Before promoting, demonstrate persisted state migration and restore and
scheduled renewal. Publish only by separate approval with
verified digest, signature, and SBOM; applying to any host is separate.

No built-image pass is claimed by this recipe or its documentation.

## Using the image

In an isolated test, provide disposable state for `/data` and
`/etc/letsencrypt`, and run the UI/API smoke through container loopback. Do not
reuse the upstream Compose unchanged or connect production volumes during
qualification. Pin the verified platform digest after a release, not a tag.

## License

The wrapper (Dockerfile, tests, documentation) is GPL-3.0. Nginx Proxy Manager
and its bundled components retain their upstream licenses.
