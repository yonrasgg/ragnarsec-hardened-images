# RagnarSec Hardened Images

Reusable container-image recipes, generic configuration examples and tests.
For each image, its README documents purpose, build inputs, declared hardening,
patching process, usage contract and the status of validation evidence.

## Image catalog

- [alertmanager](alertmanager/README.md): Alert routing and notification processing.
- [base](base/README.md): Minimal shared Linux runtime for image recipes.
- [builder](builder/README.md): Build tooling for Python and JavaScript projects.
- [buildkit](buildkit/README.md): Container image build service.
- [clamav](clamav/README.md): Malware scanning tooling.
- [grafana](grafana/README.md): Metrics and observability visualization.
- [iac](iac/README.md): Infrastructure-as-code validation and authoring tools.
- [minio](minio/README.md): S3-compatible object storage software.
- [nginx](nginx/README.md): HTTP server with a generic runtime-mounted TLS example.
- [node-exporter](node-exporter/README.md): Host metrics exporter; host access must be reviewed by consumers.
- [postgres](postgres/README.md): PostgreSQL database runtime.
- [postgres-exporter](postgres-exporter/README.md): PostgreSQL metrics exporter.
- [prometheus](prometheus/README.md): Metrics collection and query software.
- [python-base](python-base/README.md): Python runtime and common dependencies.
- [python-pdf](python-pdf/README.md): Python document and PDF generation dependencies.
- [rabbitmq](rabbitmq/README.md): Message broker runtime.
- [redis-exporter](redis-exporter/README.md): Redis-compatible metrics exporter.
- [trivy](trivy/README.md): Container and filesystem security scanning tooling.
- [valkey](valkey/README.md): Valkey key-value runtime.
- [waf](waf/README.md): HTTP filtering software and rule-set build recipe.
- [wazuh-agent](wazuh-agent/README.md): Security telemetry agent recipe.
- [zap](zap/README.md): Web application security testing tooling; targets require authorization.

Additional component recipes under `plane/` are defined by their Dockerfiles and
matching structure-test files. Catalog inclusion does not identify a deployed service.

## Controls and validation

| Control | Definition | Required evidence |
|---|---|---|
| Publication boundary | `tools/publication_guard.py` | Successful check of the exact tree; no sensitive values in output. |
| Secret detection | Pinned Gitleaks in `Jenkinsfile` | Successful tree and intended-history scans; a clean scan is scoped evidence. |
| Regression tests | `tests/test_public*.py` | Successful test run for the release commit. |
| Image structure and runtime | Service-specific test definitions | Actual build and test results tied to the output digest. |
| Vulnerabilities, SBOM and signatures | `Jenkinsfile` build definitions | Actual versioned scanner/database results, SBOM and signature verification per digest. |

Definitions are not proof of a successful image validation. No build, runtime,
vulnerability, SBOM or signing result is asserted by the presence of a recipe.
Automatic downstream deployment is not part of this repository. Image publication
requires an explicit Jenkins run, the `PUBLISH` parameter and an approval step on
`main`; repository changes alone do not publish. The default run validates
one selected recipe and its build parents, without registry write credentials.
The candidate build path validates Linux AMD64 only; it does not claim ARM64 or
multi-platform coverage. It builds once per required recipe, then checks the
same local image before any push, SBOM attestation and signature verification.
There is no automatic downstream deployment or mutable `latest` promotion.

## Continuous integration

CI runs on Jenkins as a multibranch pipeline defined by [`Jenkinsfile`](Jenkinsfile).
Changes flow through `development`, `staging` and `main`. Short-lived branches
merge into `development` by pull request; `development` is promoted to `staging`
for full validation and human review, and `staging` is promoted to `main` only
after that validation. The job runs the public contract checks, a pinned secret
scan of the tree and history, and the selected-image plan/validation; it writes to
a registry only when `PUBLISH` is enabled on `main` and the approval step is
accepted. Rulesets, credentials, agent labels and the required status check are
Jenkins/GitHub configuration and are not asserted by this repository.

## Contributions and patches

Follow [CONTRIBUTING.md](CONTRIBUTING.md). Each new recipe needs public upstream
provenance, version/digest management, applicable notices, minimal privileges,
meaningful tests, a rebuild/patch process and evidence of controls that actually ran.
Use reserved example identifiers. Runtime secrets and environment-specific material
do not belong in source code, example configuration or build contexts.

## License and source

Source: https://github.com/yonrasgg/ragnarsec-hardened-images.
The wrapper source declares GPLv3; see [LICENSE](LICENSE). Upstream components
retain their respective licenses. Dependency redistribution needs its own review.
