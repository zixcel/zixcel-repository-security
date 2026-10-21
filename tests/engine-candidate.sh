#!/usr/bin/env bash
# Synthetic packaging boundaries; upstream execution remains the CI build gate.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
export GITHUB_SHA=1111111111111111111111111111111111111111
mkdir "$work/engine"
for name in go.mod go.sum gitleaks; do
  printf '%s\n' synthetic > "$work/engine/$name"
done
printf '%s\n' '["synthetic"]' > "$work/engine/imports.json"
tar -czf "$work/engine/gitleaks_8.30.1_hardened_linux_x64.tar.gz" -C "$work/engine" gitleaks
printf '%s\n' '{}' '{"pkgSymbols":{"synthetic":["symbol"]}}' > "$work/engine/binary-inventory.jsonl"
printf '%s\n' '{"config":{}}' > "$work/engine/vulnerabilities.jsonl"
bash "$root/scripts/engine-candidate.sh" "$work/engine" "$work/candidate"
reject() {
  if bash "$root/scripts/verify-engine-candidate.sh" "$work/candidate" "$1" >/dev/null 2>&1; then
    printf '%s\n' 'Expected candidate rejection' >&2; exit 1
  fi
}
reject 2222222222222222222222222222222222222222
cp "$work/candidate/candidate.json" "$work/original.json"
printf '%s\n' changed >> "$work/candidate/go.sum"
reject "$GITHUB_SHA"
cp "$work/engine/go.sum" "$work/candidate/go.sum"
rm "$work/candidate/go.mod"
ln -s "$work/engine/go.mod" "$work/candidate/go.mod"
reject "$GITHUB_SHA"
rm "$work/candidate/go.mod"
cp "$work/engine/go.mod" "$work/candidate/go.mod"
jq '.files["../escape"]=("a"*64)' "$work/original.json" > "$work/candidate/candidate.json"
reject "$GITHUB_SHA"
jq '.repository="other/owner"' "$work/original.json" > "$work/candidate/candidate.json"
reject "$GITHUB_SHA"
cp "$work/original.json" "$work/candidate/candidate.json"
printf '%s\n' 'unexpected' > "$work/candidate/unreviewed.txt"
reject "$GITHUB_SHA"
rm "$work/candidate/unreviewed.txt"
bash "$root/scripts/verify-engine-candidate.sh" "$work/candidate" "$GITHUB_SHA"
printf '%s\n' 'Candidate source, content, symlink, member and repository boundaries passed.'
