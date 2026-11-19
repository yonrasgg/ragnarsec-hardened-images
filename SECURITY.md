# Security Policy

## Supported Versions

No version series is currently designated as supported. Image tags are mutable;
identify the exact image digest and architecture when reporting a problem. Reports
about any image in this catalog are welcome; inclusion in the catalog is not a
promise that a particular digest receives ongoing security updates.

## Reporting a Vulnerability

Report vulnerabilities **privately** using GitHub's
[private vulnerability reporting form](https://github.com/yonrasgg/ragnarsec-hardened-images/security/advisories/new).
If you cannot use that form, contact the repository owner through the private
contact options on [their GitHub profile](https://github.com/yonrasgg), as
described in [CONTRIBUTING.md](CONTRIBUTING.md). Do not open a public issue or
pull request containing exploit steps, credentials, or confidential evidence.

Include the affected image name, digest, platform, impact, and a minimal
reproduction without live secrets. The maintainer aims to acknowledge a report
within 7 calendar days and provide an update at least every 14 calendar days
while it remains open; these are targets, not guaranteed response times. If
accepted, the maintainer will coordinate a fix and disclosure timeline with
the reporter. If declined, the maintainer will explain why privately. Please
allow time for a coordinated fix before making details public.

## Image Verification

Digests published from `main` by the CI pipeline are signed with
[cosign](https://github.com/sigstore/cosign) using a project-held private key.
The corresponding public key is committed at [`cosign.pub`](cosign.pub) in the
repository root, and signatures are recorded in the public
[Sigstore Rekor](https://docs.sigstore.dev/logging/overview/) transparency log.

Verify a published image index and its per-platform digests with cosign
(v3.1.3 is the version pinned by this repository's CI):

```sh
cosign verify --key cosign.pub ghcr.io/yonrasgg/ragnarsec-<image>@sha256:<index-digest>
cosign verify-attestation --type cyclonedx --key cosign.pub \
  ghcr.io/yonrasgg/ragnarsec-<image>@sha256:<platform-digest>
```

Each published platform digest also carries a CycloneDX SBOM attestation.
Tags are mutable references; always verify against the exact digest. A green
verification proves signature and attestation integrity, not the absence of
vulnerabilities.
