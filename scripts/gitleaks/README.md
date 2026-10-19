# Detector dependency maintenance

The hardened detector is built from the immutable upstream commit in
`../build-gitleaks.sh`. Only the reviewed module manifest/lock is overlaid.

`imports.go` records that commit's external production and test imports, without
copying upstream implementation. Go module maintenance considers the `tools`
build tag when resolving dependencies. This prevents an update job from pruning
required imports merely because the detector source is fetched during CI instead
of being duplicated in this directory. The stub is never copied into the build.

When changing the upstream source pin, review its external import set and refresh
this list. Every update still builds the full detector from pinned source, runs
its real upstream tests and module integrity checks, retains dependency licenses,
and checks the compiled binary for vulnerabilities. No `-mod=readonly` or
vulnerability guard is removed to make an update pass.
