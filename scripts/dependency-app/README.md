# Owner-local dependency App registration

This Linux/WSL tool registers one organization's private GitHub App for a **single
pilot repository**. Registering an App still requires the owner's GitHub browser
session. It uses the official manifest flow and `@octokit/auth-app`; it implements
no cryptographic algorithm or local key store.

After source/permission approval, prepare a private directory and a local JSON file:

```json
{"repository":"example/project","receiptDirectory":"/private/directory"}
```

Install the locked dependencies with
`pnpm --dir scripts/dependency-app install --frozen-lockfile --ignore-scripts`, then
run `bash scripts/dependency-app/open-local.sh /absolute/path/to/config.json`.
Open the printed loopback page and register the App without changing its name, then select **only the pilot
repository** when installing it. Leave the process running until completion.

The key is received in memory. Before registering it with `gh secret set` via
stdin, the tool verifies the owner/App permissions, selected installation,
single-repository token scope, API access and revocation of temporary tokens.
GitHub CLI performs Environment-secret encryption. No PEM, token, client secret,
callback code or webhook secret is saved to disk, logs or receipts. JavaScript
memory is not claimed to be zeroized. Core dumps are disabled by the launcher.

Only `dependency-maintenance`, restricted to the **main branch**, may hold the key.
Existing keys, mismatched variables or other Environment protections are never
overwritten. The receipt is exclusive, private, append-only metadata with fsync.
On failure, inspect the receipt before further writes; App creation or an unknown
token-issuance outcome may need manual recovery. The tool does not delete Apps,
change rulesets, activate merging, publish or deploy.

An installation-wide **metadata-read-only** token checks the selected repository
set. A separate explicit single-repository token checks the reviewed permission
subset. Both are revoked, including known-token validation failures. Unknown POST
outcomes are not retried. If token issuance has an unknown outcome, cleanup is not
claimed; such a token expires according to GitHub's installation-token policy.

Broad owner rollout requires separate live pilot acceptance and a reviewed scope
extension. Unit tests and closed-PR rejection do not prove a live positive merge.

## Owner-wide selected installations

A configuration may use `repositories` instead of `repository`: a nonempty, unique list from one organization (at most 100). Only the explicitly reviewed set is accepted at installation. Each repository must be public, active, administered by the caller, and use main. No new repository is inferred from organization membership.

Before any key registration, all destinations must pass inactive/main-only checks. One metadata-only discovery token verifies the entire selected installation; separate write tokens each explicitly select exactly one repository and are independently revoked. The owner key is encrypted into each repository's main-only Environment, never a shared cross-owner credential. Keys are registered only after all token probes succeed. Partial writes are recorded per repository and never silently replayed. Registration still does not grant a ruleset bypass or enable merging.

For multiple owners, run `open-batch-local.sh` with the reviewed local configuration paths. It processes one owner at a time, stops on any failure, and does not retry or skip an existing registration. Finish the pilot's live acceptance before using this rollout path.
