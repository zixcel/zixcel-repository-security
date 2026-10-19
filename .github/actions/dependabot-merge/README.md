# Conditional dependency merging

Call this action from a trusted default-branch workflow after PR validation.
Pin the reviewed action source and supply `required-workflows` as a JSON array
of the registered PR validation workflow names, such as `["CI"]`. Keep that
contract synchronized with the repository's validation workflows.

The action admits one verified Dependabot commit, checks its GitHub committer,
and verifies that successful PR workflows attest the same head and Bot actor.
Every configured validation workflow must be active, unambiguous and present;
a passing check context alone does not replace a workflow run.

Only dependency manifests and locks qualify. Changed npm dependencies retain
their names and use compatible pinned versions. Peer contracts, scripts,
engines, overrides, source and workflow changes require individual review.
Major and zero-major minor updates also require individual review.

The caller supplies either its workflow token or an explicit repository-scoped
GitHub App token. App mode verifies the official token action's installation/slug
against protected Environment bindings, then independently verifies the token can
access exactly the current repository. App mode never silently falls back to the
workflow token. Normal
merge protection remains effective. The action executes no PR source or
artifacts, performs no publication, and never retries an unverified write.
Use the SHA-pinned official `actions/create-github-app-token` with explicit owner,
current repository and permission subset. Keep default post-action token revocation
enabled. Its `client-id` input avoids deprecated App-ID configuration. Store the
key only in a main-branch-only `dependency-maintenance` Environment, and validate
the App and installation first. See `scripts/dependency-app/README.md`.
This action does not register Apps, change rulesets or grant repository permissions.
