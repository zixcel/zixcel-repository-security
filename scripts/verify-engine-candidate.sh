#!/usr/bin/env bash
# Hash-bound read-only verification; no extraction, network, or publication.
set -euo pipefail
directory=$1
source_sha=$2
[[ "$source_sha" =~ ^[a-f0-9]{40}$ && "$directory" == /* && ! -L "$directory" ]]
[[ -f "$directory/candidate.json" && ! -L "$directory/candidate.json" ]]
[[ $(stat -c %s "$directory/candidate.json") -le 16384 ]]
jq -e --arg source "$source_sha" '
  .schema == 1 and .repository == "zixcel/zixcel-repository-security" and
  .source == $source and .detectorVersion == "8.30.1" and .platform == "linux-amd64" and
  (.executableSha256 | test("^[a-f0-9]{64}$")) and
  (.files | keys == ["binary-inventory.jsonl","gitleaks_8.30.1_hardened_linux_x64.tar.gz",
    "go.mod","go.sum","imports.json","vulnerabilities.jsonl"]) and
  all(.files[]; test("^[a-f0-9]{64}$"))' "$directory/candidate.json" >/dev/null
while IFS=$'\t' read -r file expected; do
  [[ -f "$directory/$file" && ! -L "$directory/$file" ]]
  [[ $(stat -c %s "$directory/$file") -le 67108864 ]]
  test "$(sha256sum "$directory/$file" | cut -d ' ' -f 1)" = "$expected"
done < <(jq -r '.files|to_entries[]|[.key,.value]|@tsv' "$directory/candidate.json")
executable_sha=$(timeout 20s tar -xOzf "$directory/gitleaks_8.30.1_hardened_linux_x64.tar.gz" -- gitleaks |
  head -c 67108865 | sha256sum | cut -d ' ' -f 1)
test "$executable_sha" = "$(jq -r '.executableSha256' "$directory/candidate.json")"
jq -s -e '[.[]|select(.finding.trace[0].package)]|length == 0' "$directory/vulnerabilities.jsonl" >/dev/null
jq -s -e '.[1].pkgSymbols|length > 0' "$directory/binary-inventory.jsonl" >/dev/null
