#!/usr/bin/env bash
# Load policy from the protected target or the qualified transition revision.
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

  transition_policy=
  case "$target_branch:$protected_base" in
    staging:2add4efdd48e1d579e47158928b9d0cde9bccd97|main:dfd4b7e9d9a0f0b7fe4cec05fe893d8153c78daa)
      # Immutable policy qualified in Actions run 46173709617. Keep this
      # synchronized with check-promotion-candidate.yml.
      transition_policy=326546a32c000ed16abe78767152323770a9e232
      git --no-replace-objects fetch --no-tags --no-write-fetch-head --refmap= origin "$transition_policy"
      ;;
  esac

  policy_parent=$(mktemp -d "$WORKSPACE_TMP/protected-promotion.XXXXXXXX")
  policy_path="$policy_parent/policy"
  worktree_added=false
  transition_path="$policy_parent/transition"
  transition_added=false
  cleanup() {
    evaluation_rc=$?
    trap - EXIT
    cleanup_rc=0
    if "$transition_added"; then
      git --no-replace-objects worktree remove --force "$transition_path" || cleanup_rc=$?
    fi
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
  git --no-replace-objects -c core.hooksPath=/dev/null worktree add --detach "$policy_path" "$protected_base" >&2
  worktree_added=true
  promotion_evaluator=tools/promotion_candidate.py
  if [[ -n "$transition_policy" ]]; then
    git --no-replace-objects -c core.hooksPath=/dev/null worktree add --detach "$transition_path" "$transition_policy" >&2
    transition_added=true
    [[ "$(git --no-replace-objects -C "$transition_path" rev-parse HEAD)" == "$transition_policy" ]] ||
      stop 'transition policy revision mismatch'
    printf 'Promotion policy: %s\n' "$transition_policy" >&2
    promotion_evaluator="$transition_path/tools/promotion_candidate.py"
  fi
  (
    cd "$policy_path"
    if [[ "$target_branch" == development ]]; then
      python3 -B tools/jenkins_promotion_route.py \
        --source "$source_branch" --reviewed-head "$candidate_head" \
        --manifest-from-pr "$candidate_head" --pr "$CHANGE_ID" \
        --change-id "$CHANGE_ID" --repo "$repository" --allow-manifest-reconciliation
    else
      python3 -B "$promotion_evaluator" \
        --jenkins-input "$source_branch" "$target_branch" "$candidate_head" "$protected_base"
    fi
  )
)
