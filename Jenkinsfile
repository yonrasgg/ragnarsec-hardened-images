// RagnarSec Hardened Images — Jenkins multibranch pipeline.
//
// This file replaces the former GitHub Actions workflows. It validates one
// selected image and its required build parents, runs the public contract
// checks and a pinned secret scan, and never writes to a registry unless the
// PUBLISH parameter is enabled on `main` and the approval step is accepted.
// A green build is not proof of image security; it records that the declared
// controls ran for this commit.
//
// Branch model: development (integration) -> staging (validation) -> main
// (release). A staging build must be contained in development; a main build
// must be contained in staging.
//
// Job requirements (owned by Jenkins, not by this repository):
// - multibranch pipeline with a non-shallow checkout;
// - an x86_64 agent labeled `ragnarsec-linux` with python3, git, docker and buildx;
// - PR builds infer IMAGE from the diff (tools/select_image.py); IMAGE stays a
//   parameter for manual runs. Promotion builds (target staging/main) validate
//   linux/amd64 and linux/arm64 in parallel, each on its native agent;
// - dedicated AArch64 agent labeled `ragnarsec-linux-arm64`, with
//   the same rootless Docker and guarded egress contract; never the controller;
// - a selected buildx builder using the `docker` driver so validated local
//   parent tags are visible to dependent builds before publication;
// - credentials id `ragnarsec-registry` (username/password) for publication;
// - credentials ids `ragnarsec-cosign-key` (file) and `ragnarsec-cosign-password`
//   (secret text) for digest signing and verification;
// - a required status check named after this job, configured in the ruleset.

pipeline {
  // Control, AMD64 validation and publication share the sole AMD64 executor.
  // Only the ARM64 branch acquires another node; it binds its own Docker socket.
  agent { label 'ragnarsec-linux' }

  options {
    skipDefaultCheckout()
    timeout(time: 60, unit: 'MINUTES')
    disableConcurrentBuilds()
    buildDiscarder(logRotator(numToKeepStr: '30'))
  }

  parameters {
    choice(
      name: 'IMAGE',
      choices: [
        '',
        'ragnarsec-alertmanager',
        'ragnarsec-arcane',
        'ragnarsec-base',
        'ragnarsec-base-min',
        'ragnarsec-builder',
        'ragnarsec-buildkit',
        'ragnarsec-clamav',
        'ragnarsec-grafana',
        'ragnarsec-iac',
        'ragnarsec-minio',
        'ragnarsec-nginx',
        'ragnarsec-nginx-proxy-manager',
        'ragnarsec-node-exporter',
        'ragnarsec-postgres',
        'ragnarsec-postgres-exporter',
        'ragnarsec-prometheus',
        'ragnarsec-python-base',
        'ragnarsec-python-pdf',
        'ragnarsec-rabbitmq',
        'ragnarsec-redis-exporter',
        'ragnarsec-scanopy',
        'ragnarsec-trivy',
        'ragnarsec-valkey',
        'ragnarsec-wgdashboard'
      ],
      description: 'One image; only its required build parents are included. Empty = infer from the change request diff.'
    )
    booleanParam(
      name: 'PUBLISH',
      defaultValue: false,
      description: 'Publish validated digests. Requires main and approval.'
    )
    string(
      name: 'PLATFORMS',
      defaultValue: 'linux/amd64,linux/arm64',
      description: 'Comma-separated platforms validated and published by this build.'
    )
    string(
      name: 'IMAGE_TAG_SUFFIX',
      defaultValue: '',
      description: 'Optional suffix appended to the generated image tag.'
    )
    booleanParam(
      name: 'NATIVE_ARM64',
      defaultValue: false,
      description: 'Legacy parameter; leave false. Promotion always validates both native runners.'
    )
  }

  environment {
    DOCKER_HOST = "unix://${env.XDG_RUNTIME_DIR}/docker.sock"
    DOCKER_CONTEXT = ''
    PYTHONDONTWRITEBYTECODE = '1'
    IMAGE = "${params.IMAGE ?: ''}"
    PLATFORMS = "${params.PLATFORMS}"
    CI_NATIVE_ARM64 = "${params.NATIVE_ARM64 == true ? 'true' : 'false'}"
    CI_PUBLISH_REQUESTED = "${params.PUBLISH == true ? 'true' : 'false'}"
    CI_CAPTURE_PLAN_CONTEXT = 'true'
    CI_ROOT = "${WORKSPACE_TMP}/ragnarsec-ci"
    CI_TOOLS = "${WORKSPACE_TMP}/ragnarsec-ci/tools"
    VALIDATION_OUTPUT = "${WORKSPACE_TMP}/ragnarsec-ci/image-validation"
    DOCKER_CONFIG = "${WORKSPACE_TMP}/ragnarsec-ci/docker-auth"
    TRIVY_CACHE_DIR = "${WORKSPACE_TMP}/ragnarsec-ci/trivy-cache"
  }

  stages {
    stage('Control') {
      stages {
      stage('Checkout SCM') {
        steps {
          checkout scm
        }
      }

      stage('Provenance') {
        steps {
          sh '''
            set -euo pipefail
            python3 tools/ci_docker_endpoint.py
            test "$(git rev-parse --is-shallow-repository)" = "false" || {
              echo 'STOP: complete history required; configure a non-shallow checkout.' >&2
              exit 2
            }
            require_traceable() {
              branch="$1"
              commit="$2"
              message="$3"
              git fetch --no-tags origin "+refs/heads/${branch}:refs/remotes/origin/${branch}"
              if git merge-base --is-ancestor "$commit" "origin/${branch}"; then
                return 0
              fi
              tree="$(git rev-parse "${commit}^{tree}")"
              if git log --format='%T' "origin/${branch}" | grep -x "$tree" >/dev/null; then
                return 0
              fi
              echo "STOP: ${message}" >&2
              exit 2
            }
            # One-time recovery for the divergent staging/main histories. Each
            # branch is exact-named, based on a frozen target tip, and must equal
            # the current source tree. The exception expires when the target moves.
            require_one_time_sync() {
              commit="$1"
              base="$2"
              expected_tip="$3"
              source_branch="$4"
              git fetch --no-tags origin \
                "+refs/heads/${base}:refs/remotes/origin/${base}" \
                "+refs/heads/${source_branch}:refs/remotes/origin/${source_branch}"
              test "$(git rev-parse "origin/${base}")" = "$expected_tip" || {
                echo 'STOP: target base changed; sync exception expired.' >&2
                exit 2
              }
              git merge-base --is-ancestor "origin/$base" "$commit" || {
                echo 'STOP: sync branch must descend from target base.' >&2
                exit 2
              }
              test "$(git rev-parse "${commit}^{tree}")" = \
                "$(git rev-parse "origin/${source_branch}^{tree}")" || {
                  echo 'STOP: sync tree differs from current source branch.' >&2
                  exit 2
              }
            }
            require_linear_arm64_sync() {
              require_one_time_sync "$@"
              test "$(git rev-list --parents -n 1 "$1")" = "$1 $3" || {
                echo 'STOP: ARM64 sync must have exactly the pinned target parent.' >&2
                exit 2
              }
            }
            # Scoped recovery. The current source must be precisely
            # one reviewed squash after its frozen tip, and the signed sync
            # candidate must reproduce that source tree on the frozen target.
            require_scoped_sync() {
              sync_head="$1" sync_target="$2" sync_base="$3" sync_source="$4" sync_source_parent="$5"
              test -z "${CHANGE_FORK:-}" || {
                echo 'STOP: scoped recovery requires a branch from this repository.' >&2
                exit 2
              }
              require_one_time_sync "$sync_head" "$sync_target" "$sync_base" "$sync_source"
              source_tip="$(git rev-parse "origin/${sync_source}")"
              test "$(git rev-list --parents -n 1 "$source_tip")" = "$source_tip $sync_source_parent" &&
              test "$(git rev-list --parents -n 1 "$sync_head")" = "$sync_head $sync_base" || {
                echo 'STOP: scoped recovery expired or has unexpected source/target parents.' >&2
                exit 2
              }
            }
            target="${CHANGE_TARGET:-$BRANCH_NAME}"
            if [ -n "${CHANGE_TARGET:-}" ]; then
              source="${CHANGE_BRANCH:-}"
              source="${source##*:}"
              head="$(git rev-parse --verify HEAD^2 2>/dev/null || git rev-parse HEAD)"
              case "$target" in
                staging)
                  if [ "$source" = "development" ]; then
                    require_traceable development "$head" 'staging pull request is not traceable to development.'
                  elif [ "$source" = "sync/development-to-staging-native-arm64-trivy-workspace-tmp" ]; then
                    require_linear_arm64_sync "$head" staging \
                      e4821cb1bcefb2e0a0a3b55c7461be8e73e8bd1e development
                  elif [ "$source" = "sync/development-to-staging-native-nginx-118" ]; then
                    require_linear_arm64_sync "$head" staging \
                      e4821cb1bcefb2e0a0a3b55c7461be8e73e8bd1e development
                  elif [ "$source" = "sync/development-to-staging-native-nginx-budget" ]; then
                    require_linear_arm64_sync "$head" staging \
                      e4821cb1bcefb2e0a0a3b55c7461be8e73e8bd1e development
                  elif [ "$source" = "sync/development-to-staging-native-npm-124" ]; then
                    require_linear_arm64_sync "$head" staging \
                      edc2b7eee148551f122a89c59298008f69eaf70d development
                  elif [ "$source" = "sync/development-to-staging-vex-20261103" ]; then
                    require_one_time_sync "$head" staging \
                      be401b0e4b6f4463e419ee4e67f0d567221ccc9d development
                  elif [ "$source" = "sync/development-to-staging-node-exporter-entrypoint-20261119" ]; then
                    staging_tip=96e2cba1a818751d827ddda9397b8f14995c2c91
                    require_one_time_sync "$head" staging "$staging_tip" development
                    test "$(git rev-list --parents -n 1 "$head")" = "$head $staging_tip" || {
                      echo 'STOP: staging sync must have exactly the pinned staging parent.' >&2
                      exit 2
                    }
                  elif [ "$source" = "sync/development-to-staging-pr164-repair-20261123" ]; then
                    require_scoped_sync "$head" staging e9ab7f4655ff1c32cd60bc3e4f6750e3d7b68e26 \
                      development 40c82e789bad5895b730a92ffba2ee8838aeaf4a
                  elif [ "$source" = "sync/development-to-staging-actions-base-20261124-v2" ]; then
                    require_scoped_sync "$head" staging dbf31c83b18b66b5f6b2aa14516fed4c8b01b604 \
                      development f94d751309a08107529b0fa3584ef41aac06d700
                  elif [ "$source" = "sync/development-to-staging-scanopy-20261125" ]; then
                    require_scoped_sync "$head" staging f8035cd71e576c9ea469a554dac0df1f07e2ba29 \
                      development b7b53157573b0325b6c544122f1a6ac22b0903fb
                  elif [ "$source" = "sync/development-to-staging-o1-ds007-20261125" ]; then
                    require_scoped_sync "$head" staging d3af4e2d79a3796c73d7bef5f0c0ad9717c1304d \
                      development 8cc8afd1c6b89c4b3ee50a26a12602ead05cdc8d
                  elif [ "$source" = "sync/development-to-staging-o1-ds007-final-20261125" ]; then
                    require_scoped_sync "$head" staging 6421e1b72b11dabe68c0bd3759885989fe81ee8e \
                      development 5699b18d1a3b599cb27a7783702f0912c4947ffe
                  elif [ "$source" = "sync/development-to-staging-manifest-aware-20261126" ]; then
                    require_scoped_sync "$head" staging e5b1d84b2c7f8de69016b56a94a2a24116201c71 \
                      development 0e2cf0a1121647a50ba8676270ac16231ad5c555
                  else
                    echo 'STOP: staging accepts development or the one-time exact-tree sync.' >&2
                    exit 2
                  fi
                  ;;
                main)
                  if [ "$source" = "staging" ]; then
                    require_traceable staging "$head" 'main pull request is not traceable to staging.'
                  elif [ "$source" = "sync/staging-to-main-native-arm64-106" ]; then
                    require_linear_arm64_sync "$head" main \
                      32ba41c1ec403776cb4a8d8df3d184205f6020d0 staging
                  elif [ "$source" = "sync/staging-to-main-native-npm-124" ]; then
                    require_linear_arm64_sync "$head" main \
                      86db549ecd9853853e8821844dccc9dc8197e8c5 staging
                  elif [ "$source" = "sync/staging-to-main-vex-20261103" ]; then
                    require_one_time_sync "$head" main \
                      faaf17460b6e828c02e455665015fb05828b1c87 staging
                  elif [ "$source" = "sync/staging-to-main-pr164-repair-20261123" ]; then
                    require_scoped_sync "$head" main f0a1d6f044406d04e0410016985c638b04b4e47f \
                      staging e9ab7f4655ff1c32cd60bc3e4f6750e3d7b68e26
                  elif [ "$source" = "sync/staging-to-main-actions-base-20261124-v2" ]; then
                    require_scoped_sync "$head" main 07806bb98d24774074713f241f2922d2edc90487 \
                      staging dbf31c83b18b66b5f6b2aa14516fed4c8b01b604
                  elif [ "$source" = "sync/staging-to-main-scanopy-20261125" ]; then
                    require_scoped_sync "$head" main 84d70416ea3038f23d36bd5187af5f3b324c505b \
                      staging f8035cd71e576c9ea469a554dac0df1f07e2ba29
                  elif [ "$source" = "sync/staging-to-main-o1-ds007-20261125" ]; then
                    require_scoped_sync "$head" main 84d70416ea3038f23d36bd5187af5f3b324c505b \
                      staging d3af4e2d79a3796c73d7bef5f0c0ad9717c1304d
                  elif [ "$source" = "sync/staging-to-main-o1-ds007-final-20261125" ]; then
                    require_scoped_sync "$head" main 6abfb7aed7287c43a920427c170d26b8e4dfe76d \
                      staging 6421e1b72b11dabe68c0bd3759885989fe81ee8e
                  elif [ "$source" = "sync/staging-to-main-manifest-aware-20261126" ]; then
                    require_scoped_sync "$head" main 57bec7ffc5aa4baf87dfbf333d3b087c5b2befea \
                      staging e5b1d84b2c7f8de69016b56a94a2a24116201c71
                  else
                    echo 'STOP: main accepts staging or the one-time exact-tree sync.' >&2
                    exit 2
                  fi
                  ;;
              esac
            else
              case "$target" in
                staging)
                  require_traceable development HEAD 'staging commit is not traceable to development.'
                  ;;
                main)
                  require_traceable staging HEAD 'main commit is not traceable to staging.'
                  ;;
              esac
            fi
          '''
        }
      }

      stage('Contract') {
        steps {
          dir('ci-summary') { deleteDir() }
          // Retire transfer paths used by the earlier revision of this PR.
          dir('validation-artifacts') { deleteDir() }
          dir('validation-amd64') { deleteDir() }
          dir('validation-arm64') { deleteDir() }
          sh 'rm -f -- ragnarsec-ci-image'
          sh '''
            set -euo pipefail
            test -n "${WORKSPACE_TMP:-}" || {
              echo 'STOP: WORKSPACE_TMP is required to keep CI artifacts outside the checkout.' >&2
              exit 2
            }
            test "$(git rev-parse --is-shallow-repository)" = "false" || {
              echo 'STOP: complete history required; configure a non-shallow checkout.' >&2
              exit 2
            }
            python3 -m unittest discover -s tests -p 'test_public*.py'
            python3 tools/publication_guard.py . --history
          '''
        }
      }

      stage('Promotion route') {
        when { expression { env.CHANGE_TARGET == 'development' } }
        steps {
          dir('ci-route') { deleteDir() }
          // Historical reconciliation aliases, frozen as documentation only.
          // Admission comes from the owner-signed PR manifest; this list is NOT an allowlist.
          // 'ragnarsec-hardened-images/PR-164:164:fix/automated-promotion-preflight'
          // 'ragnarsec-hardened-images/PR-173:173:fix/actions-promotion-base-checkout'
          // 'ragnarsec-hardened-images/PR-204:204:fix/scanopy-image-catalog-20261125'
          // 'ragnarsec-hardened-images/PR-203:203:fix/wgdashboard-o1-native-https'
          // 'ragnarsec-hardened-images/PR-207:207:fix/scanopy-sync-lanes-20261125'
          // 'ragnarsec-hardened-images/PR-210:210:fix/wgdashboard-o1-ds007'
          // 'ragnarsec-hardened-images/PR-214:214:fix/o1-ds007-promotion-lanes-20261125'
          // 'ragnarsec-hardened-images/PR-219:219:fix/o1-ds007-main-lane-repin-20261125'
          // 'ragnarsec-hardened-images/PR-222:222:fix/o1-ds007-staging-lane-repin-20261125'
          // 'ragnarsec-hardened-images/PR-224:224:fix/o1-ds007-lane-pins-final-20261125'
          // 'ragnarsec-hardened-images/PR-215:215:fix/promotion-candidate-evaluator-20261125'
          // 'ragnarsec-hardened-images/PR-233:233:fix/repin-unblock-sync-lanes-20261125'
          // 'ragnarsec-hardened-images/PR-236:236:fix/ansible-check-publisher-20261126'
          // 'ragnarsec-hardened-images/PR-238:238:fix/actions-reconciliation-preflight-20261126'
          sh '''
            set -euo pipefail
            mkdir -m 700 ci-route
            set -- --source "$CHANGE_BRANCH" --pr "$CHANGE_ID" \
              --allow-manifest-reconciliation
            python3 tools/jenkins_promotion_route.py "$@" | tee ci-route/promotion-route.json
          '''
        }
        post {
          always {
            archiveArtifacts artifacts: 'ci-route/promotion-route.json'
          }
          cleanup {
            dir('ci-route') { deleteDir() }
          }
        }
      }

      stage('Tools') {
        steps {
          sh '''
            set -euo pipefail
            test "$(uname -m)" = x86_64 || { echo 'STOP: control stages require the x86_64 agent.' >&2; exit 2; }
            : "${CI_ROOT:?}"
            # Jenkins may reuse the workspace; the installer requires a new
            # directory and validation receipts must never survive a build.
            rm -rf "$CI_ROOT"
            mkdir -m 700 -p "$CI_ROOT"
            python3 tools/install_ci_tools.py "$CI_TOOLS"
          '''
        }
      }

      stage('Secret scan') {
        steps {
          sh '''
            set -euo pipefail
            export PATH="$CI_TOOLS:$PATH"
            cfg="$CI_ROOT/gitleaks.toml"
            cat > "$cfg" <<'GITLEAKS_CONFIG'
[extend]
useDefault = true
GITLEAKS_CONFIG
            gitleaks git . --log-opts='--all --full-history' \
              --config "$cfg" --gitleaks-ignore-path "$CI_ROOT/no-ignore" \
              --ignore-gitleaks-allow --redact=100 --no-banner
            gitleaks dir . \
              --config "$cfg" --gitleaks-ignore-path "$CI_ROOT/no-ignore" \
              --ignore-gitleaks-allow --redact=100 --no-banner
          '''
        }
      }

      stage('Plan') {
        steps {
          sh '''
            set -euo pipefail
            target="${CHANGE_TARGET:-$BRANCH_NAME}"
            test "$CI_NATIVE_ARM64" = false || {
              echo 'STOP: the legacy NATIVE_ARM64 flag must be false.' >&2
              exit 2
            }
            case "$target" in
              staging|main)
                python3 -c 'from tools.image_ci import platforms; import sys; sys.exit(set(platforms()) != {"linux/amd64", "linux/arm64"})' || {
                  echo 'STOP: promotion requires both native platforms.' >&2
                  exit 2
                }
                ;;
            esac
            if [ -n "${CHANGE_TARGET:-}" ]; then
              git fetch --no-tags origin "+refs/heads/${target}:refs/remotes/origin/${target}"
              base="origin/${target}"
            else
              if [ -z "${IMAGE:-}" ]; then
                echo 'STOP: select IMAGE explicitly for a branch build.' >&2
                exit 2
              fi
              base=HEAD
            fi
            selection="$(python3 tools/select_image.py --image "${IMAGE:-}" --base "$base" --head HEAD)"
            resolved="$(printf '%s' "$selection" | python3 -c 'import json,sys; print(json.load(sys.stdin)["image"])')"
            echo "Resolved image: ${resolved}"
            printf '%s\\n' "$resolved" > "$CI_ROOT/image"
            python3 tools/image_ci.py plan --image "$resolved"
            if [ "$target" = "development" ]; then
              echo 'Development build: plan only; full image validation runs on staging.'
            fi
          '''
          script {
            env.CI_VALIDATION_IMAGE = sh(script: 'cat "$CI_ROOT/image"', returnStdout: true).trim()
            env.CI_SOURCE_REVISION = sh(script: 'git rev-parse --verify HEAD', returnStdout: true).trim()
            env.CI_BUILD_DATE = sh(script: "date -u +'%Y-%m-%dT%H:%M:%SZ'", returnStdout: true).trim()
            def suffix = params.IMAGE_TAG_SUFFIX ? "-${params.IMAGE_TAG_SUFFIX}" : ''
            env.CI_IMAGE_TAG = "sha-${env.CI_SOURCE_REVISION}-${env.BUILD_NUMBER}${suffix}"
          }
        }
      }

      }
    }

    stage('Validate') {
      when {
        anyOf {
          expression { (env.CHANGE_TARGET ?: env.BRANCH_NAME) == 'staging' }
          expression { (env.CHANGE_TARGET ?: env.BRANCH_NAME) == 'main' }
        }
      }
      // Each platform validates the same source on its native agent.
      parallel {
        stage('Validate linux/amd64') {
          environment { CI_PLATFORM = 'linux/amd64'; CI_RUNNER_ARCH = 'amd64' }
          steps {
            script { validatePlatform() }
          }
        }
        stage('Validate linux/arm64') {
          agent { label 'ragnarsec-linux-arm64' }
          environment { CI_PLATFORM = 'linux/arm64'; CI_RUNNER_ARCH = 'arm64' }
          steps {
            checkout scm
            script {
              validatePlatform()
              dir("${pwd(tmp: true)}/ragnarsec-ci/arm64") {
                stash name: 'validation-arm64', includes: '*'
              }
            }
          }
          post {
            cleanup {
              dir("${pwd(tmp: true)}/ragnarsec-ci") { deleteDir() }
            }
          }
        }
      }
    }

    stage('Verify native handoff') {
      when {
        anyOf {
          expression { (env.CHANGE_TARGET ?: env.BRANCH_NAME) == 'staging' }
          expression { (env.CHANGE_TARGET ?: env.BRANCH_NAME) == 'main' }
        }
      }
      steps {
        dir("${env.CI_ROOT}/arm64") { unstash 'validation-arm64' }
        sh '''
          set -euo pipefail
          # The same AMD64 node already proved its rootless daemon. After
          # Buildx, verify the now-existing private config instead of requiring absence.
          python3 tools/ci_docker_endpoint.py --config-only
          python3 tools/validation_handoff.py assemble --image "$CI_VALIDATION_IMAGE" \
            --tag "$CI_IMAGE_TAG" --revision "$CI_SOURCE_REVISION" --directory "$CI_ROOT" \
            --output "$VALIDATION_OUTPUT"
          cat "$CI_ROOT/amd64/validate.log" "$CI_ROOT/arm64/validate.log" > "$CI_ROOT/validate.log"
          mkdir -m 700 "$WORKSPACE/ci-summary"
          python3 tools/validation_summary.py --output "$VALIDATION_OUTPUT" --log "$CI_ROOT/validate.log" \
            --commit "$CI_SOURCE_REVISION" --target "${CHANGE_TARGET:-$BRANCH_NAME}" \
            --run-url "${BUILD_URL:-}" --write "$WORKSPACE/ci-summary"
        '''
        archiveArtifacts artifacts: 'ci-summary/summary.md, ci-summary/summary.json'
      }
      post {
        cleanup {
          dir('ci-summary') { deleteDir() }
        }
      }
    }

    stage('Publish') {
      when {
        allOf {
          expression { params.PUBLISH }
          expression { env.BRANCH_NAME == 'main' }
        }
      }
      steps {
        input message: 'Publish the validated digests to the registry?', ok: 'Publish'
        withCredentials([
          usernamePassword(
            credentialsId: 'ragnarsec-registry',
            usernameVariable: 'REGISTRY_USER',
            passwordVariable: 'REGISTRY_TOKEN'
          ),
          file(credentialsId: 'ragnarsec-cosign-key', variable: 'COSIGN_KEY'),
          string(credentialsId: 'ragnarsec-cosign-password', variable: 'COSIGN_PASSWORD')
        ]) {
          sh '''
            set -euo pipefail
            export PATH="$CI_TOOLS:$PATH"
            python3 tools/release_signing_guard.py
            export PUBLICATION_ENABLED=true
            printf '%s' "$REGISTRY_TOKEN" | docker login ghcr.io -u "$REGISTRY_USER" --password-stdin
            python3 tools/image_ci.py publish --image "$CI_VALIDATION_IMAGE" \
              --tag "$CI_IMAGE_TAG" --output "$VALIDATION_OUTPUT"
          '''
        }
      }
    }
  }

  post {
    always {
      script {
        if (env.CHANGE_TARGET in ['development', 'staging', 'main'] &&
            fileExists("${env.CI_ROOT}/validation-context.json")) {
          catchError(buildResult: 'FAILURE') {
            sh '''
              set -euo pipefail
              mkdir -m 700 "$WORKSPACE/ci-summary"
              install -m 600 "$CI_ROOT/validation-context.json" "$WORKSPACE/ci-summary/validation-context.json"
            '''
            archiveArtifacts artifacts: 'ci-summary/validation-context.json'
          }
          dir('ci-summary') { deleteDir() }
        }
      }
      sh '''
        if command -v docker >/dev/null 2>&1 &&
           python3 tools/ci_docker_endpoint.py --config-only >/dev/null 2>&1; then
          docker logout ghcr.io >/dev/null 2>&1 || true
        fi
        # This post step cleans the AMD64 workspace. ARM64 has its own post step.
        if [ -n "${CI_ROOT:-}" ]; then
          rm -rf "$CI_ROOT"
        fi
      '''
    }
    success {
      echo 'Validation completed for the selected image. See stage logs for control results.'
    }
    failure {
      echo 'Validation failed. Do not publish or merge on this build.'
    }
  }
}

// Validation of one platform on its native agent. Called from the parallel matrix.
def validatePlatform() {
  sh '''
    set -euo pipefail
    case "$CI_RUNNER_ARCH:$(uname -m)" in
      amd64:x86_64|arm64:aarch64) ;;
      *) echo 'STOP: platform/agent mismatch.' >&2; exit 2 ;;
    esac
    export PLATFORMS="$CI_PLATFORM"
    export CI_NATIVE_ARM64="$([ "$CI_RUNNER_ARCH" = arm64 ] && echo true || echo false)"
    export GIT_COMMIT="$(git rev-parse --verify HEAD)"
    test "$GIT_COMMIT" = "$CI_SOURCE_REVISION" || {
      echo 'STOP: native checkout does not match the control revision.' >&2
      exit 2
    }
    export BUILD_DATE="$CI_BUILD_DATE"
    export DOCKER_HOST="unix://${XDG_RUNTIME_DIR:?}/docker.sock"
    export CI_ROOT="${WORKSPACE_TMP:?}/ragnarsec-ci"
    export CI_TOOLS="$CI_ROOT/tools"
    export DOCKER_CONFIG="$CI_ROOT/docker-auth"
    export TRIVY_CACHE_DIR="$CI_ROOT/trivy-cache"
    if [ "$CI_RUNNER_ARCH" = arm64 ]; then
      rm -rf "$CI_ROOT"
      mkdir -m 700 "$CI_ROOT"
    fi
    python3 tools/ci_docker_endpoint.py
    mkdir -m 700 "$DOCKER_CONFIG"
    if [ "$CI_RUNNER_ARCH" = arm64 ]; then
      python3 tools/install_ci_tools.py "$CI_TOOLS"
    fi
    export PATH="$CI_TOOLS:$PATH"
    output="$CI_ROOT/$CI_RUNNER_ARCH"
    # Trivy extracts large OCI databases; the agent's /tmp may be tmpfs.
    validation_tmp="$(mktemp -d "$CI_ROOT/validation-tmp.XXXXXXXX")"
    TMPDIR="$validation_tmp" RAGNARSEC_REQUIRE_STAGE_EGRESS=1 python3 tools/image_ci.py validate \
      --image "$CI_VALIDATION_IMAGE" --tag "$CI_IMAGE_TAG" --output "$output" 2>&1 | tee "$CI_ROOT/validate-$CI_RUNNER_ARCH.log"
    mv "$CI_ROOT/validate-$CI_RUNNER_ARCH.log" "$output/validate.log"
    if [ "$CI_RUNNER_ARCH" = arm64 ]; then
      python3 tools/validation_handoff.py pack --image "$CI_VALIDATION_IMAGE" \
        --tag "$CI_IMAGE_TAG" --revision "$CI_SOURCE_REVISION" --directory "$output"
    fi
  '''
}
