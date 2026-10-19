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
