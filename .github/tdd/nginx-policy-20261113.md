# Nginx policy and HTTP/2 regression evidence

## Scope and journeys

Journeys were derived from review of the existing recipe, not an external plan:

- A maintainer needs reviewed direct package versions instead of a whole-base
  upgrade, with policy violations blocking this recipe.
- A consumer needs supported HTTP/2 syntax while retaining the TLS protocol floor.
- A reviewer needs license scan classifications distinguished from CVE findings.

No image publication, deployment, protected-branch update or ruleset mutation is
authorized by this report. Existing promotion documentation is not changed by
the recipe fix; ancestry-preserving promotion remains a separate policy review.

## RED / GREEN

Runner: Python standard-library `unittest`.

1. RED: `python3 -m unittest discover -s tests -p test_public_nginx_hardening.py`
   executed seven tests against the original recipe: six intended failures and
   one pass (existing TLS protocol floor). Failures reproduced the upgrade,
   advisory-only policy, missing manifest pins, package-pin lint suppression,
   deprecated HTTP/2 syntax and absence of a deprecation-warning assertion.
   Checkpoint: `604c116`.
2. GREEN: `python3 -m unittest discover -s tests` executed 107 tests, all passing.
   `git diff --check` also exited zero. Fix checkpoint: `3287d41`.

| Guarantee | Test in `tests/test_public_nginx_hardening.py` | Kind |
|---|---|---|
| Recipe has no policy violations | `test_nginx_dockerfile_is_policy_clean` | Static contract |
| Nginx is in the enforced policy set | `test_nginx_policy_is_enforced_not_advisory` | Static contract |
| Exact direct additions match the manifest | `test_nginx_direct_packages_match_version_manifest` | Static contract |
| Package-pin lint is not suppressed | `test_nginx_does_not_suppress_package_pin_lint` | Static contract |
| HTTP/2 is enabled without deprecated listener syntax | `test_http2_uses_supported_separate_directive` | Static contract |
| TLS 1.2/1.3 floor is unchanged | `test_tls_protocol_floor_is_preserved` | Static contract |
| Runtime config test declares rejection of deprecations | `test_runtime_config_check_rejects_deprecation_warnings` | Test-definition contract |

These are recipe/configuration contracts, not proof of new runtime bytes. The
container structure test must run again for both architectures after the fix.
Line coverage was not measured; no numerical coverage claim is made for config
files or for the unchanged pipeline implementation.

## Input lookup

The Alpine v3.24 `main` indexes over HTTPS listed the same versions for x86_64
and aarch64: nginx `1.30.6-r0`, openssl `3.5.9-r0`, pcre2 `10.49-r0`.

- <https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/APKINDEX.tar.gz>
  SHA-256 `3c7fd55bbb047333c6e835582564adfd3d84f4af8de97ce42f88e7fae4991ba9`.
- <https://dl-cdn.alpinelinux.org/alpine/v3.24/main/aarch64/APKINDEX.tar.gz>
  SHA-256 `0abc27e1ee015e78e259b077d10a389afc875737609d6b3ceafb4b2a4aabbce3`.
- <https://nginx.org/en/docs/http/ngx_http_v2_module.html#http2> documents the
  separate `http2 on;` directive, available since 1.25.1.
- Container Structure Test v1.22.1 documents `excludedError` in its command tests:
  <https://github.com/GoogleContainerTools/container-structure-test/blob/v1.22.1/README.md>.

Index availability is a point-in-time observation, not a package snapshot or a
claim of complete dependency reproducibility. Missing versions must fail closed.

## Remaining gates

- Repeat full image validation, structure tests, scans and SBOM generation on the
  exact corrected revision for amd64 and arm64. Earlier green builds do not cover
  these changed bytes or a future signed promotion commit.
- Review license obligations independently; no allowlist, exception or waiver
  was added to make a scanner result pass.
- Preserve this RED/GREEN summary if the feature PR is squash-merged. The signed
  integration commit and any signed promotion candidate require their own exact
  revision checks before enforcement, publication or deployment.
