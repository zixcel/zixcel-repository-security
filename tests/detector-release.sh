#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
source=1111111111111111111111111111111111111111
jq -n --arg sha "$source" '{head_sha:$sha,head_branch:"main",event:"push",conclusion:"success",path:".github/workflows/detector-candidate.yml",head_repository:{full_name:"zixcel/zixcel-repository-security"},run_attempt:1}' > "$work/accepted.json"
bash "$root/scripts/verify-candidate-run.sh" "$work/accepted.json" "$source"
for change in '.event="pull_request"' '.head_branch="feature"' '.conclusion="failure"' '.path=".github/workflows/ci.yml"' '.head_repository.full_name="other/repo"' '.run_attempt=0' '.head_sha="wrong"'; do
  jq "$change" "$work/accepted.json" > "$work/rejected.json"
  if bash "$root/scripts/verify-candidate-run.sh" "$work/rejected.json" "$source" >/dev/null 2>&1; then exit 1; fi
done
printf '%s\n' '{}' '{"pkgSymbols":{"safe":["symbol"]}}' > "$work/inventory.jsonl"
printf '%s\n' '["safe"]' > "$work/imports.json"
printf '%s\n' '{"config":{}}' > "$work/findings.jsonl"
bash "$root/scripts/verify-binary-audit.sh" "$work/findings.jsonl" "$work/inventory.jsonl" "$work/imports.json"
for finding in '{"finding":{"osv":"SYNTHETIC","trace":[{"module":"module","package":"safe"}]}}' '{"finding":{"osv":"UNKNOWN","trace":[{"module":"module"}]}}'; do
  printf '%s\n' "$finding" > "$work/findings.jsonl"
  if bash "$root/scripts/verify-binary-audit.sh" "$work/findings.jsonl" "$work/inventory.jsonl" "$work/imports.json" >/dev/null 2>&1; then exit 1; fi
done
printf '%s\n' 'Exact candidate identity and fail-closed binary audit boundaries passed.'
