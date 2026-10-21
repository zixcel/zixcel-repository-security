# Using zixcel-repository-security

All content and word/name pattern matching is performed by the pinned Gitleaks
engine. Zixcel loads and compiles settings, builds bounded read-only snapshots,
normalizes literal inputs, maps locations and records inspection identity and gaps.
All orchestration is implemented in Rust; Python is not required.

A passing receipt covers only the inspected snapshot and configured rules. It
never authorizes publication. Git history, dependency vulnerabilities, full SAST,
credential validity, rights/licensing and media/OCR require separate inspections.
Native binary contents remain uninspected even when their names are checked.

## Run from the source checkout

Set private configuration and result paths outside the inspected tree:

```sh
zixcel-repository-security scan \
  --root "$PWD" \
  --config "${ZIXCEL_SECURITY_CONFIG:?Set the private configuration path}" \
  --definitions-file "${ZIXCEL_SECURITY_DEFINITIONS_FILE:?Set the private definition path}" \
  --output "${ZIXCEL_SECURITY_RECEIPT:?Set the private receipt path}"
```

Build from the checkout or install locally into an external prefix:

```sh
CARGO_TARGET_DIR="${ZIXCEL_SECURITY_BUILD_DIR:?Set an external build directory}" \
  cargo install --path . --locked \
  --root "${ZIXCEL_SECURITY_INSTALL_DIR:?Set an external install directory}"
```

Add that prefix's `bin` to PATH. Linux/WSL and Git are required.
The Rust toolchain is declared in `rust-toolchain.toml`. Validation does not fetch
engine binaries implicitly; only `provision-gitleaks --download` downloads the
fixed public release. The CLI and test suite need no Python interpreter.

Exit codes are `0` for passed, `1` for findings or incomplete inspection, and `2`
for invalid CLI settings or preparation conditions. Check the current exit code
and receipt identity: a rejected invocation can leave an older output untouched.
Receipts use mode `0600` and contain locations, IDs and hashes, not detected
values or source lines. File names are location metadata and can themselves be
sensitive; results must stay private. Output cannot overwrite source or settings.

## Common settings and definition schema

Copy [the common JSON example](../examples/config.example.json) to a private settings
directory. Set a real verified Gitleaks executable path and SHA-256. The configuration
schema is `zixcel://repository-security/config/v1`; legacy files without `schema` remain
accepted. Private values belong in external files, not arguments, environment values,
source defaults or public examples. Environment variables below hold paths only.

- `repository_id`: inspected repository identity; inventories supply each root's ID.
- `gitleaks.path`, `gitleaks.sha256`: absolute physical executable and verified hash.
- `definitions_file`: recommended literal/RE2 definition JSON.
- `gitleaks.config_file`: optional additional native Gitleaks TOML.
- `private_dictionary_file`, `words_file`: supported legacy literal definitions.
- `exceptions_file`: reviewed, expiring, exact-fingerprint exceptions.

Referenced settings resolve relative to the common JSON file. CLI file paths resolve
from the current directory. `--definitions-file` and `--words-file` add to configured
files, with the same resolved path read once; `--gitleaks-config` overrides the native
TOML reference for that invocation. These options work with `scan`, `scan-inventory`
and `prepare-snapshot`. Settings documents are limited to 16 MiB.

Use [the unified example](../examples/definitions.example.json) and
[the packaged JSON Schema](../assets/definitions.v1.schema.json):

```json
{
  "schema": "zixcel://repository-security/definitions/v1",
  "rules": [
    {"id": "word-01", "kind": "literal", "values": ["FORBIDDEN_SAMPLE"]},
    {"id": "pattern-01", "kind": "regex", "regex": "SYNTHETIC_NATIVE_[0-9]{4}"}
  ]
}
```

These values are synthetic. IDs are public-safe metadata and must not contain
private names. Unknown fields/kinds, duplicate IDs across all combined definitions,
nonblank-normalization failures, invalid bounds and nonfinite numbers are rejected.
The combined limit is 256 literal/regex definitions. Native RE2 syntax is validated
by Gitleaks; failed rules cannot produce a passing scan.

| Kind | Definition | Gitleaks input |
| --- | --- | --- |
| `literal` | Required `id`, `kind`, `values`; optional `category` (`word`, `person`, `company`, `project`, default `word`). IDs are 1–64 lowercase letters/digits/hyphens; 1–32 aliases, each 2–256 characters. | Escaped RE2 patterns against NFKC/casefold document lines and name metadata. |
| `regex` | Required `id`, `kind`, `regex`; optional native `secretGroup`, `entropy`, `keywords`. See Schema for bounds. | Original staged text, without Unicode normalization; RE2 is evaluated by Gitleaks. |

`keywords` is a Gitleaks prefilter: incorrect keywords can suppress matches for that
rule. The unified schema cannot execute commands, fetch resources, disable the
baseline or introduce allowlists. Legacy dictionaries and `words/v1` settings
compile through the same literal backend. See [the legacy word example](../examples/words.example.json).

## Engine passes and coverage

| Pass | Responsibility |
| --- | --- |
| Default | Independent `[extend] useDefault = true` standard secrets. Source allowlists, inline suppressions and additional settings cannot disable it. |
| Policy | Bundled native [disclosure rules](../assets/disclosure.toml) and compiled custom RE2 rules share one pass on original text. |
| Literal | Compiled normalized words inspect document text and file/archive names as metadata fragments. |
| Additional native TOML | Optional advanced rules, isolated from all other passes. |

Bundled disclosure rules cover email addresses, selected mobile-number patterns,
classified-record/profile fields and machine home paths. Native rule-scoped
allowlists exclude documented example domains, URI userinfo, SSH remotes and
mobile-number matches embedded in longer digit strings. An allowed match must not
suppress another finding on the same line. These are review indicators, not proof
that an account, number or person is real.

Gitleaks's standard private-key rule requires a body and terminator. A native
header-only policy rule preserves incomplete-header coverage. When the standard
rule already detects the same location, the header finding is removed as duplicate
location metadata; Zixcel does not evaluate key content itself.

Literal inputs use NFKC + casefold. Metacharacters are escaped for RE2. Normalized
lines map back to the original document and line numbering; normalized names map
to the original file/archive-member path with `line: 0`. Names are text fragments,
not host paths: Unicode slash normalization cannot create filesystem paths.
There is no supplementary Python word matching or silent fallback if Gitleaks fails.

Source inputs include tracked files and nonignored untracked files. Ignored tracked
files stay visible and produce an unwaivable `tracked-excluded-data` finding from
Git provenance. Ignored untracked runtime data is outside this inventory. Deleted
tracked files are recorded separately; their history remains uninspected.

Supported TAR/TGZ/TAR.GZ documents are decoded with bounds on bytes, members, depth
and paths before being passed to Gitleaks. Container bytes are not rescanned as a
second payload. Native engine archive/recursive decoding is disabled so it cannot
bypass these bounds. Unsupported members, symlinks or formats remain incomplete.

Gitleaks runs on private staging directories. Original source paths have a `files/`
prefix; decoded member staging paths use `archives/`. Native TOML path rules must
account for these staging paths. Reports are mapped to original source/member paths.
The literal pass handles logical names explicitly, independently of those prefixes.

## Native TOML settings and results

Use [the native example](../examples/gitleaks.example.toml) and
[the pinned upstream specification](https://github.com/gitleaks/gitleaks/blob/v8.30.1/README.md#configuration).
Native TOML supports top-level `title`, `rules`, `allowlist`, `allowlists`, `extend`;
`extend` is limited to `useDefault` and `disabledRules`. External `path` and `url`
extensions are rejected; consolidate them into one local file first. There must be
1–256 explicit rules with unique safe IDs. Symlink setting files are rejected.
Allowlisting/overriding in this optional pass cannot suppress other passes.

Findings retain definition IDs: literals use `configured-word` or
`registered-private-<category>`, custom RE2 uses `configured-regex`, bundled policy
uses its disclosure name and standard rules use `gitleaks:<rule-id>`. Additional
native rules use `gitleaks-additional:<rule-id>`. Results contain no match text.

Receipts bind source inventory, scanner/compiler/adapter and bundled rule hashes,
engine hash, external TOML bytes, semantic definitions and compiled TOML hashes.
Every pass must complete; missing/malformed/inconsistent reports fail closed.
Definitions changing invalidates previous reviewed fingerprints. External TOML bytes
are snapshotted and rechecked; source file sets/bytes and engine bytes are checked
again after scanning. Staging, compiled settings and raw reports are private temporary
files and removed on exit. Unsupported content never becomes a pass by omission.

Repository policy `v2` requires only `gitleaks`. Legacy `v1` policies naming
`builtin-disclosure` remain accepted as a compatibility contract; their disclosure
coverage is now delegated to the Gitleaks policy pass, not a separate Python engine.
Current receipts expose only Gitleaks as the pattern-detection engine.

## Rust verification and workspace orchestration

The checked-in tests fail when the real Gitleaks configuration is missing; they
never silently skip detection cases. Use an already verified executable offline:

```sh
zixcel-repository-security provision-gitleaks \
  --executable "${ZIXCEL_GITLEAKS_BIN:?Set the verified executable path}" \
  --output-directory "${ZIXCEL_TEST_ENGINE_DIR:?Set a new external private directory}"
ZIXCEL_TEST_GITLEAKS_CONFIG="$ZIXCEL_TEST_ENGINE_DIR/config.json" \
  CARGO_TARGET_DIR="$ZIXCEL_SECURITY_BUILD_DIR" cargo test --locked
cargo fmt --check
CARGO_TARGET_DIR="$ZIXCEL_SECURITY_BUILD_DIR" cargo clippy --locked --all-targets -- -D warnings
CARGO_TARGET_DIR="$ZIXCEL_SECURITY_BUILD_DIR" cargo package --locked
```

`--archive` accepts the SHA-pinned curated release archive offline. `--download`
is a separate explicit choice requiring curl/HTTPS; it fetches only the fixed
public URL in `tests/gitleaks-pin.json`. Executable and archive hashes are checked
before writing any installation files. No scanned source is uploaded.

`scan-workspace --workspace /absolute/workspace` discovers physical Git roots
under `organizations/<organization>/<repository>`. Repeat `--repository-path`
for exact relative selections. Unknown selections and empty inventories fail.
`--jobs` accepts 1–4. Fresh workspace scans omit previous review exceptions;
individual `scan` and `scan-inventory` retain configured exact-fingerprint reviews.
The Wonderland shell entry point delegates directly to this Rust command:

```sh
ZIXCEL_SECURITY_BIN=/absolute/installed/bin/zixcel-repository-security \
  tools/run-repository-security --repository-path organizations/zixcel/zixcel-repository-security
```

Configuration/definition/engine inputs and all source roots are protected from
output overwrites, including existing hardlinks. Descriptor-relative reads refuse
symlinks at every ancestor. Output writes refuse symlinks and multiply-linked files.
Receipts bind the Rust source modules and rule hashes; old Python receipts and
exception fingerprints are historical and cannot establish a Rust scan result.
Unicode NFKC/full casefold uses the Unicode versions of the locked Rust libraries;
Unicode table upgrades change the rules/dependency identity and require revalidation.
CI also runs the Rust `check-oss-policy` command. CI, installation and tests contain
no Python bootstrap step. Remote CI still requires a separately approved push.

## Mounted directories

Use `scan-directory` instead of `scan` to inspect all files and entry names under
one explicitly selected Linux/WSL directory. It does not invoke Git or apply ignore
rules; `.env`, ignored files and empty directory names remain visible to Gitleaks.
Settings and output must remain outside the selected root. The receipt scope is
`directory-secret-disclosure/v1`. Reviewed exceptions are not applied in this mode.

```sh
zixcel-repository-security scan-directory \
  --root /mnt/c/Inspection/Selected \
  --config /private/detection.json --output /private/directory-receipt.json
```

Traversal depth, entries, file bytes and expanded archives are bounded. Symlinks,
unreadable/changed inputs, unsupported formats and Git administrative entries are
incomplete; Git object/history inspection is not implied. Detected values are not
stored, but receipt location metadata can be sensitive and must remain private.

## Curated engine build

The curated engine retains Gitleaks 8.30.1 detector source and rules. Its fixed
Go module lockfiles update compression, RAR, XZ and Go crypto/text dependencies;
The candidate build uses Go 1.27.3 to address the compiled crypto/x509 finding
GO-2026-6809. This does not rewrite an existing published detector pin. `scripts/build-gitleaks.sh`
verifies the official toolchain archive, checks Go module integrity, runs upstream
tests and audits compiled packages/symbols with govulncheck 1.8.0 before packaging.
Symbols are retained for accurate binary inspection; no compiler is needed at runtime.

Module-only notices remain in the build evidence. In particular, the deprecated
OpenPGP packages in `golang.org/x/crypto` are not imported or linked by this engine;
its used crypto packages are separately inspected. No advisory IDs are ignored.
Curated engine assets are independently released by this repository; the retired
vPremises route is not used. Normal Rust CI and installed consumers use verified
prebuilt bytes without a Go compiler. See [artifact lifecycle](detector-distribution.md)
for candidate acceptance, published-version auditing and immutable pin updates.
The adapter verifies exact executable/archive hashes before provisioning.
