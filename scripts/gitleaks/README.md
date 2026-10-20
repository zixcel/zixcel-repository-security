# Detector dependency maintenance

The maintenance module declares the actual detector as a Go tool. Its version
`v8.30.1` matches immutable upstream commit
`83d9cd684c87d95d656c1458ef04895a7f1cbd8e`. The Go tool directive keeps the full
upstream import graph visible to dependency update jobs without copying detector
implementation or maintaining a surrogate import list.

The existing hardened build verifies this binding and resolves the maintenance
module with readonly dependencies. It restores the detector's original module
identity and drops only the maintenance tool/self requirement in the temporary
pinned source tree. It then runs the unchanged upstream tests, module-integrity
checks, dependency-license retention and compiled-binary vulnerability gates.

The source pin, tool version and displayed detector version must be reviewed
together when upgrading the detector itself. Ordinary dependency updates remain
independent; no guard or advisory is suppressed to pass an update.

Go tool directives: https://go.dev/doc/modules/managing-dependencies

`upstream_tests_test.go` retains the immutable detector's test-only dependency
roots during Dependabot tidy. Tool directives alone retain production imports,
not the tool module's test imports. These explicit roots do not replace or skip
upstream tests. The temporary source build continues using readonly module
resolution, checksum verification, actual upstream tests and binary vulnerability
checks; missing closure still rejects the candidate. Remove a root only after
checking the pinned detector source no longer imports it.

## Candidate and production acceptance

A dependency update changes detector bytes. CI therefore audits and tests the
candidate using its exact computed hash, while independently rebuilding the current
published detector recipe recorded by `source` in `tests/gitleaks-pin.json`.
Production provisioning must still match the unchanged executable hash in
`tests/gitleaks-pin.json`. The public archive is downloaded anonymously, checked
against its pinned hash and verified with GitHub CLI against the exact source,
signer workflow and GitHub-hosted runner identity before provisioning. Both builds
retain upstream tests, checksum verification,
licenses and binary vulnerability rejection. No candidate hash replaces that pin.
The additional test configuration is CI-only and does not add a production bypass.
The accepted component release replaces the retired download route. Its archive,
executable and recipe are pinned together. Future dependency candidates do not
automatically replace the published production pin. Source CI success does not
claim an installed scanner or a future detector component has been updated.
