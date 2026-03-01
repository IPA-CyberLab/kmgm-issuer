#!/usr/bin/env bash
# Source this script to set up envtest assets for kubebuilder/controller-runtime tests.
#
# Usage:
#   source setup_testenv.sh

is_sourced=false

if [[ -n "${ZSH_VERSION-}" ]]; then
  case "${ZSH_EVAL_CONTEXT-}" in
    *:file) is_sourced=true ;;
  esac
elif [[ -n "${BASH_VERSION-}" ]]; then
  [[ "${BASH_SOURCE[0]-}" != "${0}" ]] && is_sourced=true
fi

if [[ "${is_sourced}" != "true" ]]; then
  echo "This script must be sourced, not executed"
  exit 2
fi

set -euo pipefail

: "${ASSETS_ROOT:=$HOME/.cache/envtest}"
mkdir -p "${ASSETS_ROOT}"

KUBEBUILDER_ASSETS="$(setup-envtest use --bin-dir "${ASSETS_ROOT}" -p path latest 2>/dev/null)"
export KUBEBUILDER_ASSETS

echo "KUBEBUILDER_ASSETS=${KUBEBUILDER_ASSETS}"