# zixcel-repository-security

Check a source tree for secrets and information that should not be published before sharing it.

## What you can do

- Scan eligible source files and supported archives.
- Apply a private disclosure dictionary and pinned Gitleaks engine.
- Produce a receipt with findings and uninspected-file status.

## Current scope

A clean receipt covers the inspected source snapshot and configured rules. Unsupported files and unresolved findings must be reviewed; findings never grant publication approval.

Package distribution is not activated by this documentation. Use the checked-in source and the declared dependency versions; published availability must be verified separately.

## Getting started

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e .
```

## Documentation and source

[Usage guide](docs/getting-started.md)

[Examples](examples) · [Implementation and public interfaces](src) · [Verification cases](tests) · [Contributing](CONTRIBUTING.md) · [Security reporting](SECURITY.md) · [License](LICENSE) · [Attribution notices](NOTICE)
