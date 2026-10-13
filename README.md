# zixcel-repository-security

Inspect a local source snapshot for secrets and information that should not be
published. The CLI, configuration compiler, bounded source/archive reader and
receipt writer are implemented in Rust. Gitleaks is the sole pattern detector.
Python is not required to build, test, install or run this tool.

## Build and use

Linux/WSL, Git and the declared Rust toolchain are required. Keep build output and
private configuration outside the inspected repository:

```sh
CARGO_TARGET_DIR="${ZIXCEL_SECURITY_BUILD_DIR:?Set an external build directory}" \
  cargo build --locked --release
```

Run the resulting `zixcel-repository-security` binary with `scan --root`,
`scan-inventory` or `scan-workspace`. See the [usage guide](docs/getting-started.md)
for configuration, engine provisioning, installation and tests.

- Standard secrets, disclosure rules, custom RE2 rules and normalized words/names
  all run through a SHA-pinned Gitleaks executable.
- Private definitions are read from external JSON/TOML files. Detected values and
  source lines are never copied into receipts or CLI messages.
- Unsupported files, unsafe paths and changed sources cannot receive a passing
  result. A receipt identifies exactly the inspected source and rule definitions.

A passing receipt covers only the current source snapshot and configured rules.
It does not inspect Git history, dependency vulnerabilities, credential validity,
licenses, full SAST or binary contents, and never authorizes publication.

Crates.io publication is disabled pending release review. Registry availability
and registry installation have not been verified.

[Examples](examples) · [Source](src) · [Verification cases](tests) ·
[Contributing](CONTRIBUTING.md) · [Security reporting](SECURITY.md) ·
[License](LICENSE) · [Attribution notices](NOTICE)

[OSS responsibility and source completion](docs/oss-source-contract.md) defines the supported package boundary and required acceptance. It does not declare unexecuted source, distribution or production checks complete.
