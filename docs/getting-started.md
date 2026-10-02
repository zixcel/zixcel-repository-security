# Using zixcel-repository-security

Check a source tree for secrets and information that should not be published before sharing it.

## Before you start

A clean receipt covers the inspected source snapshot and configured rules. Unsupported files and unresolved findings must be reviewed; findings never grant publication approval.

## First steps

Run from the repository root:

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e .
```

## How to assess the result

- Scan eligible source files and supported archives.
- Apply a private disclosure dictionary and pinned Gitleaks engine.
- Produce a receipt with findings and uninspected-file status.

A passing source-level check establishes only what that check observes. Keep missing configuration, unavailable services and unverified deployment paths visible.

## Continue reading

[Repository overview](../README.md)
