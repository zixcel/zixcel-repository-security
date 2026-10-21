#!/usr/bin/env bash
# No advisory allowlist: reject compiled findings and unknown module-only impact.
set -euo pipefail
findings=$1
inventory=$2
imports=$3
jq -s -e 'length>0 and any(.[]; .config|type=="object")' "$findings" >/dev/null
jq -s -e '.[1].pkgSymbols|length > 0' "$inventory" >/dev/null
jq -e 'type=="array" and length>0 and all(.[]; type=="string" and length>0)' "$imports" >/dev/null
jq -s -e '[.[]|select(.finding.trace[0].package)]|length == 0' "$findings" >/dev/null
jq -s -e --slurpfile imports "$imports" '
  . as $documents | all($documents[] |
    select(.finding and (.finding.trace[0].package == null)) | .finding;
    . as $finding |
    [$documents[] | select(.osv.id == $finding.osv) | .osv.affected[] |
      select(.package.name == $finding.trace[0].module) |
      .ecosystem_specific.imports[]?.path] as $affected |
    ($affected|length) > 0 and all($affected[];
      . as $package | (contains("*")|not) and ($imports[0]|index($package)) == null))
  ' "$findings" >/dev/null
