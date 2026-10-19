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

The caller supplies the repository-scoped `GITHUB_TOKEN` authority. Normal
merge protection remains effective. The action executes no PR source or
artifacts, performs no publication, and never retries an unverified write.
An elevated App credential integration requires its own reviewed setup before
activation; this action does not grant or change repository permissions.
