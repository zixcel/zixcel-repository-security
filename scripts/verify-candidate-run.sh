#!/usr/bin/env bash
# Validate API data before artifact retrieval; no API calls or side effects here.
set -euo pipefail
run=$1
source=$2
[[ "$source" =~ ^[a-f0-9]{40}$ ]]
jq -e --arg sha "$source" '
  .head_sha==$sha and .head_branch=="main" and
  (.event=="push" or .event=="workflow_dispatch") and .conclusion=="success" and
  .path==".github/workflows/detector-candidate.yml" and
  .head_repository.full_name=="zixcel/zixcel-repository-security" and
  (.run_attempt|type=="number" and .>=1 and floor==.)
' "$run" >/dev/null
