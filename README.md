# Zixcel repository security

Independent local source disclosure scanner. It scans Git-eligible tracked and untracked files, inspects bounded tar archives without extracting them, rejects symlinks, and detects ignored-but-tracked data. It does not print matching values. Unknown binary formats, unavailable Gitleaks, and concurrent source changes make inspection incomplete.

Run with Python 3.12 or later and a checksum-pinned official Gitleaks executable:

```sh
PYTHONPATH=src python -m zixcel_repository_security scan --config registration/config.json --root "$PWD" --output state/receipt.json
```

Configuration is JSON containing `repository_id`, optional `private_dictionary_file`, optional `exceptions_file`, and `gitleaks: {path, sha256}`. Dictionary entries contain an opaque `id`, `category` (`person`, `company`, `project`), and `values`. Keep dictionaries/configuration in ignored registration storage with restrictive permissions. No customer data belongs in examples.

`scan-inventory --inventory <csv> --workspace <absolute-root>` inspects every CSV entry. Output receipts retain file hashes, locations, rules and review dispositions, never matched source values. Scope is disclosure and secret detection; dependency vulnerability analysis and SAST are explicitly reported as not run.

Exceptions require an exact finding fingerprint (bound to the entire file), a reviewer, reason and expiration. Do not exempt whole repositories, all tests, or every detected name. A private key remains a finding even in tests until reviewed as an intentional public fixture.

`prepare-snapshot --root <absolute-root> --branch main --message <text>` reruns inspection and prepares a bounded source artifact only after a passing result. It does not commit, push, create or delete repositories. Provide the resulting digest-named JSON artifact to the Crowsi artifact store; configured Zixcel policy, signed HAT authority and GitHub token permissions are separate requirements. Existing Git history must be inspected separately before a normal Git push; this source scanner does not certify history.

Each repository declares scope, required engines and Gitleaks version in `repository-security.json`. Running `python3 tools/run-repository-security.py` in Wonderland inspects every inventory entry and updates counts, source digests and timestamps in the CSV. Private configuration and dictionaries remain under `state/repository-security/`. Register personal, company and project names, identifiers and aliases under opaque dictionary IDs. Unknown names and semantic confidentiality cannot be guaranteed by this inspection alone.

Use checksum-verified official Gitleaks 8.30.1 and verify its executable digest at runtime. Explicit default rules and an empty ignore file prevent repository `.gitleaks.toml`, `.gitleaksignore` or inline allow comments from weakening inspection. Exception fingerprints bind the whole file, scanner rules, dictionary and engine digest. Review fixtures and public dependency metadata individually with evidence and expiry; move real customer information into private registration data.

`passed` certifies the current source candidate within secret/disclosure scope. Git history, dependency vulnerabilities, SAST, image/OCR and database contents are excluded. Maintain backups of excluded registration data separately.

## License

The current distribution is offered under Apache-2.0; see LICENSE. Prior MIT notices are retained in LICENSE-MIT and NOTICE, without revoking previous permissions. Private dictionaries, registration data and execution receipts are excluded from distribution. Gitleaks is an external tool with its own license.