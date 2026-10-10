#!/usr/bin/env bash
# Rebuild unchanged detector source with fixed dependencies and a patched Go runtime.
set -euo pipefail
umask 077
: "${RUNNER_TEMP:?Set an operation-scoped temporary directory}"
output=$1
[[ "$output" == /* && ! -e "$output" ]] || exit 1
recipe=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
work=$(mktemp -d "$RUNNER_TEMP/zixcel-engine.XXXXXX")
trap 'chmod -R u+w -- "$work"; rm -rf -- "$work"' EXIT
curl --disable --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-time 120 \
    https://go.dev/dl/go1.27.2.linux-amd64.tar.gz -o "$work/go.tgz"
printf '%s  %s\n' ecbadb99091a3f46e31f5f934b068b1864eafa7995211b39eaddf76996045fe5 "$work/go.tgz" | sha256sum -c --strict
tar -xzf "$work/go.tgz" -C "$work"
source="$work/source"
git init -q "$source"
git -C "$source" fetch -q --depth 1 https://github.com/gitleaks/gitleaks.git 83d9cd684c87d95d656c1458ef04895a7f1cbd8e
git -C "$source" checkout -q --detach FETCH_HEAD
[[ "$(git -C "$source" rev-parse HEAD)" == 83d9cd684c87d95d656c1458ef04895a7f1cbd8e ]] || exit 1
cp "$recipe/gitleaks/go.mod" "$recipe/gitleaks/go.sum" "$source/"
export GOENV=off GOTOOLCHAIN=local GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org
export GOPRIVATE='' GONOSUMDB='' GONOPROXY='' GOFLAGS=-p=2 GOMAXPROCS=2
export GOPATH="$work/modules" GOCACHE="$work/cache" CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1
mkdir -m 700 "$output"
(
    cd "$source"
    "$work/go/bin/go" mod verify
    "$work/go/bin/go" list -mod=readonly -deps . | jq -R -s 'split("\n")|map(select(length > 0))' > "$output/imports.json"
    "$work/go/bin/go" test -mod=readonly ./...
    "$work/go/bin/go" build -mod=readonly -trimpath -buildvcs=false \
        -ldflags='-w -buildid= -X=github.com/zricethezav/gitleaks/v8/version.Version=8.30.1-hardened' \
        -o "$output/gitleaks" .
    bash "$recipe/gitleaks-notices.sh" "$output/licenses" "$work/go/bin/go"
)
chmod 755 "$output/gitleaks"
install -m 644 "$source/LICENSE" "$output/LICENSE"
install -m 644 "$work/go/LICENSE" "$output/Go-runtime-LICENSE"
cp "$source/go.mod" "$source/go.sum" "$output/"
# Retain symbols so binary scanning cannot fall back to imprecise module-only results.
"$work/go/bin/go" tool nm "$output/gitleaks" > "$output/symbols.txt"
[[ -s "$output/symbols.txt" ]] || exit 1
# JSON mode always returns zero. Reject affected compiled packages and symbols;
# module-only notices can describe unused packages and remain in the audit evidence.
GOBIN="$work/bin" "$work/go/bin/go" install golang.org/x/vuln/cmd/govulncheck@v1.8.0
"$work/bin/govulncheck" -mode=extract "$output/gitleaks" > "$output/binary-inventory.jsonl"
jq -s -e '.[1].pkgSymbols|length > 0' "$output/binary-inventory.jsonl" > /dev/null
"$work/bin/govulncheck" -mode=binary -json "$output/gitleaks" > "$output/vulnerabilities.jsonl"
jq -s -e '[.[]|select(.finding.trace[0].package)]|length == 0' "$output/vulnerabilities.jsonl" > /dev/null
# Accept module-only notices only when every affected package is proven absent.
# Missing/unknown package definitions fail closed; no advisory-specific allowlist.
jq -s -e --slurpfile imports "$output/imports.json" '
    . as $documents | all($documents[] |
        select(.finding and (.finding.trace[0].package == null)) | .finding;
        . as $finding |
        [$documents[] | select(.osv.id == $finding.osv) | .osv.affected[] |
            select(.package.name == $finding.trace[0].module) |
            .ecosystem_specific.imports[]?.path] as $affected |
        ($affected|length) > 0 and all($affected[];
            . as $package | (contains("*")|not) and ($imports[0]|index($package)) == null))
    ' "$output/vulnerabilities.jsonl" > /dev/null
tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner -C "$output" -cf - Go-runtime-LICENSE LICENSE gitleaks licenses | \
    gzip -n > "$output/gitleaks_8.30.1_hardened_linux_x64.tar.gz"
printf '%s\n' 'Hardened engine: upstream tests, module integrity and binary vulnerability checks passed.'
