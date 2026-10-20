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
