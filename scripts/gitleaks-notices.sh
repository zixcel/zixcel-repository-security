#!/usr/bin/env bash
# Copy upstream notices for every module actually compiled into the engine.
set -euo pipefail
output=$1
go=$2
mkdir "$output"
while IFS=$'\t' read -r module version directory; do
    name=${module//\//__}
    destination="$output/$name@$version"
    mkdir "$destination"
    printf 'Module: %s\nVersion: %s\n' "$module" "$version" > "$destination/MODULE.txt"
    (
        cd "$directory"
        while IFS= read -r -d '' file; do
            mkdir -p "$destination/$(dirname "$file")"
            install -m 644 "$file" "$destination/$file"
        done < <(find . -type f \( -iname 'license*' -o -iname 'licence*' -o -iname 'copying*' -o -iname 'notice*' -o -iname 'copyright*' \) -print0)
    )
    [[ "$(find "$destination" -type f | wc -l)" -gt 1 ]] || { printf 'Missing license: %s\n' "$module" >&2; exit 1; }
done < <("$go" list -mod=readonly -deps -json . | \
    jq -r 'select(.Module != null and .Module.Main != true)|.Module|[.Path,.Version,.Dir]|@tsv' | sort -u)
# Normalize modes to make archive bytes independent of module-cache permissions.
find "$output" -type f -exec chmod 644 {} +
find "$output" -type d -exec chmod 755 {} +
