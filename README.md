# RagnarSec Hardened Images

**A source catalog for building, validating, and publishing container images by digest.**
This repository contains reusable Dockerfile recipes, image-specific contracts,
structural tests, and a guarded CI pipeline. It does **not** contain a deployment
stack, runtime credentials, or a guarantee that any catalog entry has been built,
published, or cleared for use in a particular environment.

For each image, start with its linked README: it records the upstream inputs,
declared hardening, patching approach, test definitions, and usage constraints.

**Contents:** [Choose an image](#image-catalog) · [Run local checks](#check-a-change-locally) ·
[Understand validation](#how-validation-and-publication-work) ·
[Consume an image safely](#using-a-published-image) · [Contribute](#contributing-and-security)

## What this repository provides

- **Recipes, not deployments.** Dockerfiles define build inputs; environment-specific
  networks, volumes, access controls, and secrets remain the consumer's responsibility.
- **Reviewable controls.** Policy checks, structure tests, vulnerability scanning,
  SBOM generation, and signing are defined in source. Definitions are not proof
  of a passing result: evidence must identify the exact image digest and platform.
- **Gated releases.** Changes move from `development` to `staging` to `main`.
  Registry publication requires a separate approved Jenkins run on `main`.

“Hardened” describes the intended design and review process, **not** a security
certification. Upstream dependencies, available fixes, and scanner data change;
review the current build result before relying on an image.

## Image catalog

Catalog inclusion does not mean an image is published, validated, or deployed.
Use the image-specific contract before selecting a recipe.

| Category | Images and intended use |
|---|---|
| Base and build | [base](base/README.md) — shared Linux runtime; [base-min](base-min/README.md) — shell-less minimal runtime; [builder](builder/README.md) — Python/JavaScript build tools; [buildkit](buildkit/README.md) — container builds. |
| Web and applications | [nginx](nginx/README.md) — HTTP server with a runtime-mounted TLS example; [nginx-proxy-manager](nginx-proxy-manager/README.md) — reverse proxy with an administration UI; [wgdashboard](wgdashboard/README.md) — WireGuard web UI and read-only deployment contract. |
| Data and messaging | [postgres](postgres/README.md) — PostgreSQL runtime; [minio](minio/README.md) — S3-compatible object storage; [rabbitmq](rabbitmq/README.md) — message broker; [valkey](valkey/README.md) — key-value runtime. |
| Observability | [prometheus](prometheus/README.md) — metrics collection; [grafana](grafana/README.md) — dashboards; [alertmanager](alertmanager/README.md) — alert routing; [node-exporter](node-exporter/README.md) — host metrics; [postgres-exporter](postgres-exporter/README.md) — PostgreSQL metrics; [redis-exporter](redis-exporter/README.md) — Redis-compatible metrics. |
| Utilities and security | [python-base](python-base/README.md) — Python runtime; [python-pdf](python-pdf/README.md) — document/PDF dependencies; [iac](iac/README.md) — infrastructure-as-code tools; [clamav](clamav/README.md) — malware scanning; [trivy](trivy/README.md) — image and filesystem scanning. |

Plane component recipes are quarantined pending upstream input review; they are
not part of the current catalog, CI choices, or publication set.

## Check a change locally

Use a **complete checkout**. The following commands inspect source and run the
portable contract checks; they do not build, push, or deploy an image:

```bash
python3 -m unittest discover -s tests -p 'test_public*.py'
python3 tools/publication_guard.py . --history
python3 tools/image_ci.py plan --image ragnarsec-base-min
```

Replace `ragnarsec-base-min` with a name in the [catalog](#image-catalog).
The plan shows the selected recipe and its required build parents; it is **not**
a vulnerability scan. The publication guard checks public-content boundaries,
not every secret or every semantic security issue. A complete, pinned secret
scan and actual image validation are separate release checks. A shallow clone
cannot satisfy the history-path check.

For full image validation, use an approved disposable **Linux x86_64 CI host**
with Docker Buildx and the AMD64-only pinned tools in
[`tools/ci-tools.json`](tools/ci-tools.json). ARM64 target images require
`qemu-aarch64` binfmt on that host; a native ARM64 CI host is not supported
until matching checksum-pinned tools and installation are added. Do not run these
builds against a production Docker engine. See the exact commands and runner
requirements in [`Jenkinsfile`](Jenkinsfile) and [`tools/image_ci.py`](tools/image_ci.py).

## How validation and publication work

The [Jenkins multibranch pipeline](Jenkinsfile) selects **one image plus its
required build parents**. On `development`, it runs the contract and secret
checks and prints the image plan; full image validation runs on `staging` and
`main`. Validation builds a local image for each requested platform, then
checks the built bytes before any registry push.

| Gate | What to verify |
|---|---|
| Source boundary | [`publication_guard.py`](tools/publication_guard.py) and a pinned Gitleaks tree/history scan ran against the intended commit and history. A clean scan is scoped evidence, not proof of no secrets. |
| Build and policy | Lint passed and policy results were reviewed (some recipes report warnings rather than enforced failures); upstream inputs and output IDs are recorded. |
| Image evidence | Structure tests, size budget, vulnerability/secret/misconfiguration scans, license scan, and a per-platform SBOM correspond to the **same local build**. HIGH/CRITICAL findings and end-of-life operating systems block validation. |
| Release | After validation on `main`, `PUBLISH` and human approval are required. Publication pushes the validated images, assembles the index, and verifies digest-bound signatures and attestations. |

The pipeline defaults to `linux/amd64,linux/arm64`, but requested platforms
must be supported by the runner; a single-platform run is **not** multi-platform
evidence. Neither a successful source check nor the existence of a Jenkins
stage proves that a particular image passed. Consult the run's receipts, scanner
versions/database, SBOM, exact output digests, signatures, and declared
exclusions before promotion or use. No automatic downstream deployment or
mutable `latest` promotion is configured.

### Promotion order

`main` is the repository default branch; new pull requests must target
`development` rather than accepting the default target.

1. Open a short-lived branch pull request into `development`; review and squash
   merge after the source checks pass.
2. Promote `development` to `staging` for full validation and human review.
3. Promote the reviewed `staging` state to `main`, validate it again, then use
   an explicitly approved publication run if publication is intended.

The order is never skipped. Failed promotions return to `development` for a
corrected change; no image is published merely because a pull request merged.
Promotions use fast-forward or rebase, not squash or merge commits. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the complete branch and approval rules.

## Using a published image

1. Read the [image-specific README](#image-catalog), including its upstream
   inputs, exposed interfaces, persistence needs, and privilege limitations.
2. Confirm the intended release actually exists in the registry. Verify its
   **index digest and platform digest**, signatures, attestations, SBOM, and
   validation receipt; do not treat a mutable tag as an identity.
3. Pin the verified digest in the consumer configuration. Mount secrets and TLS
   material at runtime, grant only the required access, and test backups and
   rollback before changing a live service.

### Is every image in the catalog ready to deploy?

No. A recipe can be present
while its validation fails or its package has never been published. Promotion,
publication, and deployment are separate decisions.

### Can I use the same digest on AMD64 and ARM64?

A verified multi-platform
index selects a platform-specific manifest; check that both platforms were
validated and that the intended architecture is present in the published index.

## Contributing and security

Read [CONTRIBUTING.md](CONTRIBUTING.md) before adding or updating a recipe.
Document upstream provenance, version/digest pins, applicable licenses, tests,
patching, and only the controls that actually ran. Keep credentials, internal
inventories, runtime configuration, and environment-specific architecture out
of the public catalog.

Report suspected vulnerabilities **privately** through the
[GitHub advisory reporting form](https://github.com/yonrasgg/ragnarsec-hardened-images/security/advisories/new);
see [SECURITY.md](SECURITY.md) for the policy. Do not post credentials or
confidential reproduction steps in public issues or pull requests.

## License and upstream notices

Source: [github.com/yonrasgg/ragnarsec-hardened-images](https://github.com/yonrasgg/ragnarsec-hardened-images).
The wrapper source declares GPLv3; see [LICENSE](LICENSE). Upstream components
retain their own licenses. Review redistribution obligations per dependency.
