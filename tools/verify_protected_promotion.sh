#!/usr/bin/env bash
# Load policy from the live protected target, never from the PR checkout.
# The Jenkins job must independently require this adapter for the same PR head.
(
  set -euo pipefail

  stop() {
    printf 'STOP: %s\n' "$1" >&2
    exit 2
  }

  [[ $# == 3 ]] || stop 'usage: verify_protected_promotion.sh SOURCE TARGET HEAD'
  source_branch=$1
  target_branch=$2
  candidate_head=$3
  repository='yonrasgg/ragnarsec-hardened-images'

  case "$target_branch" in
    development|staging|main) ;;
    *) stop 'unsupported protected target' ;;
  esac
  [[ "$candidate_head" =~ ^[0-9a-f]{40}$ ]] || stop 'a full candidate commit SHA is required'
  [[ -n "$source_branch" && "$source_branch" != -* ]] || stop 'invalid source branch'
  git check-ref-format "refs/heads/$source_branch" >/dev/null || stop 'invalid source branch'
  [[ "${CHANGE_ID:-}" =~ ^[1-9][0-9]*$ ]] || stop 'a numeric Jenkins PR identity is required'
  [[ "${JOB_NAME:-}" == "ragnarsec-hardened-images/PR-$CHANGE_ID" ]] || stop 'unexpected Jenkins job'
  [[ "${CHANGE_TARGET:-}" == "$target_branch" ]] || stop 'Jenkins target does not match'
  [[ "${CHANGE_BRANCH:-}" == "$source_branch" ||
     "${CHANGE_BRANCH:-}" == "yonrasgg:$source_branch" ]] || stop 'Jenkins source does not match'
  [[ -z "${CHANGE_FORK:-}" ]] || stop 'fork promotion is not allowed'
  [[ "$(git --no-replace-objects rev-parse --verify HEAD)" == "$candidate_head" ]] ||
    stop 'check out the exact PR head, not a synthetic merge'

  # Read the configured URL, not get-url (which expands insteadOf rewrites).
  origin_url=$(git config --local --get-all remote.origin.url) || stop 'origin is unavailable'
  case "$origin_url" in
    https://github.com/yonrasgg/ragnarsec-hardened-images|\
    https://github.com/yonrasgg/ragnarsec-hardened-images.git|\
    git@github.com:yonrasgg/ragnarsec-hardened-images|\
    git@github.com:yonrasgg/ragnarsec-hardened-images.git|\
    ssh://git@github.com/yonrasgg/ragnarsec-hardened-images|\
    ssh://git@github.com/yonrasgg/ragnarsec-hardened-images.git) ;;
    *) stop 'origin must name the approved GitHub repository' ;;
  esac
  [[ -n "${WORKSPACE_TMP:-}" && -d "$WORKSPACE_TMP" ]] || stop 'WORKSPACE_TMP is unavailable'

  target_ref="refs/heads/$target_branch"
  remote_ref=$(git --no-replace-objects ls-remote --refs origin "$target_ref")
  IFS=$'\t' read -r protected_base observed_ref <<< "$remote_ref"
  [[ "$protected_base" =~ ^[0-9a-f]{40}$ &&
     "$remote_ref" == "$protected_base"$'\t'"$target_ref" ]] || stop 'protected target ref is unavailable or ambiguous'
  git --no-replace-objects fetch --no-tags --no-write-fetch-head --refmap= origin "$target_ref"

  policy_parent=$(mktemp -d "$WORKSPACE_TMP/protected-promotion.XXXXXXXX")
  policy_path="$policy_parent/policy"
  worktree_added=false
  cleanup() {
    evaluation_rc=$?
    trap - EXIT
    cleanup_rc=0
    if "$worktree_added"; then
      if git --no-replace-objects worktree remove --force "$policy_path"; then
        :
      else
        cleanup_rc=$?
        printf 'ERROR: protected-policy worktree cleanup failed (rc=%s).\n' "$cleanup_rc" >&2
      fi
    fi
    if rmdir "$policy_parent"; then
      :
    else
      directory_rc=$?
      printf 'ERROR: protected-policy temporary directory cleanup failed (rc=%s).\n' "$directory_rc" >&2
      if [[ "$cleanup_rc" == 0 ]]; then
        cleanup_rc=$directory_rc
      fi
    fi
    if [[ "$evaluation_rc" != 0 ]]; then
      exit "$evaluation_rc"
    fi
    exit "$cleanup_rc"
  }
  trap cleanup EXIT
  git --no-replace-objects -c core.hooksPath=/dev/null worktree add --detach "$policy_path" "$protected_base"
  worktree_added=true
  (
    cd "$policy_path"
    if [[ "$target_branch" == development ]]; then
      python3 -B tools/jenkins_promotion_route.py \
        --source "$source_branch" --reviewed-head "$candidate_head" \
        --manifest-from-pr "$candidate_head" --pr "$CHANGE_ID" \
        --change-id "$CHANGE_ID" --repo "$repository" --allow-manifest-reconciliation
    else
      python3 -B tools/promotion_candidate.py \
        --jenkins-input "$source_branch" "$target_branch" "$candidate_head" "$protected_base"
    fi
  )
)
