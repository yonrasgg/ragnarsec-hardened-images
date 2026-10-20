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
// - an agent labeled `ragnarsec-linux` with python3, git, docker and buildx;
// - credentials id `ragnarsec-registry` (username/password) for publication;
// - credentials ids `ragnarsec-cosign-key` (file) and `ragnarsec-cosign-password`
//   (secret text) for digest signing and verification;
// - a required status check named after this job, configured in the ruleset.

pipeline {
  agent { label 'ragnarsec-linux' }

  options {
    timeout(time: 60, unit: 'MINUTES')
    disableConcurrentBuilds()
    buildDiscarder(logRotator(numToKeepStr: '30'))
  }

  parameters {
    choice(
      name: 'IMAGE',
      choices: [
        'ragnarsec-alertmanager',
        'ragnarsec-base',
        'ragnarsec-builder',
        'ragnarsec-buildkit',
        'ragnarsec-clamav',
        'ragnarsec-grafana',
        'ragnarsec-iac',
        'ragnarsec-minio',
        'ragnarsec-nginx',
        'ragnarsec-node-exporter',
        'ragnarsec-postgres',
        'ragnarsec-postgres-exporter',
        'ragnarsec-prometheus',
        'ragnarsec-python-base',
        'ragnarsec-python-pdf',
        'ragnarsec-rabbitmq',
        'ragnarsec-redis-exporter',
        'ragnarsec-trivy',
        'ragnarsec-valkey',
        'ragnarsec-zap'
      ],
      description: 'One image; only its required build parents are included.'
    )
    booleanParam(
      name: 'PUBLISH',
      defaultValue: false,
      description: 'Publish validated digests. Requires main and approval.'
    )
    string(
      name: 'IMAGE_TAG_SUFFIX',
      defaultValue: '',
      description: 'Optional suffix appended to the generated image tag.'
    )
  }

  environment {
    PYTHONDONTWRITEBYTECODE = '1'
    CI_ROOT = "${WORKSPACE_TMP}/ragnarsec-ci"
    CI_TOOLS = "${WORKSPACE_TMP}/ragnarsec-ci/tools"
    VALIDATION_OUTPUT = "${WORKSPACE_TMP}/ragnarsec-ci/image-validation"
    DOCKER_CONFIG = "${WORKSPACE_TMP}/ragnarsec-ci/docker-auth"
    TRIVY_CACHE_DIR = "${WORKSPACE_TMP}/ragnarsec-ci/trivy-cache"
  }

  stages {
    stage('Provenance') {
      steps {
        sh '''
          set -euo pipefail
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
            if git log --format='%T' "origin/${branch}" | grep -qx "$tree"; then
              return 0
            fi
            echo "STOP: ${message}" >&2
            exit 2
          }
          target="${CHANGE_TARGET:-$BRANCH_NAME}"
          if [ -n "${CHANGE_TARGET:-}" ]; then
            source="${CHANGE_BRANCH:-}"
            source="${source##*:}"
            head="$(git rev-parse --verify HEAD^2 2>/dev/null || git rev-parse HEAD)"
            case "$target" in
              staging)
                test "$source" = "development" || {
                  echo 'STOP: staging accepts pull requests only from development.' >&2
                  exit 2
                }
                require_traceable development "$head" 'staging pull request is not traceable to development.'
                ;;
              main)
                test "$source" = "staging" || {
                  echo 'STOP: main accepts pull requests only from staging.' >&2
                  exit 2
                }
                require_traceable staging "$head" 'main pull request is not traceable to staging.'
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

    stage('Tools') {
      steps {
        sh '''
          set -euo pipefail
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

    stage('Plan and validate') {
      steps {
        sh '''
          set -euo pipefail
          export PATH="$CI_TOOLS:$PATH"
          export BUILD_DATE="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
          export IMAGE_TAG="sha-$(git rev-parse HEAD)-${BUILD_NUMBER}-amd64"
          if [ -n "${IMAGE_TAG_SUFFIX:-}" ]; then
            export IMAGE_TAG="${IMAGE_TAG}-${IMAGE_TAG_SUFFIX}"
          fi
          mkdir -p "$CI_ROOT"
          printf '%s' "$IMAGE_TAG" > "$CI_ROOT/image-tag"
          target="${CHANGE_TARGET:-$BRANCH_NAME}"
          python3 tools/image_ci.py plan --image "$IMAGE"
          if [ "$target" = "development" ]; then
            echo 'Development build: plan only; full image validation runs on staging.'
          else
            python3 tools/image_ci.py validate --image "$IMAGE" \
              --tag "$IMAGE_TAG" --output "$VALIDATION_OUTPUT"
          fi
        '''
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
            export IMAGE_TAG="$(cat "$CI_ROOT/image-tag")"
            export PUBLICATION_ENABLED=true
            printf '%s' "$REGISTRY_TOKEN" | docker login ghcr.io -u "$REGISTRY_USER" --password-stdin
            python3 tools/image_ci.py publish --image "$IMAGE" \
              --tag "$IMAGE_TAG" --output "$VALIDATION_OUTPUT"
          '''
        }
      }
    }
  }

  post {
    always {
      sh '''
        if command -v docker >/dev/null 2>&1; then
          docker logout ghcr.io >/dev/null 2>&1 || true
        fi
        # Remove every per-build artifact: credentials, pinned tools, receipts
        # and the derived public key. The next build starts from an empty root.
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
