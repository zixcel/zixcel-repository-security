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

The action uses only the caller repository's built-in `GITHUB_TOKEN`, with
contents/pull-requests write and checks/statuses/actions read at the merge job.
No dedicated App registration, private key, installation, Environment secret or
personal token is required. Token issuance and repository scoping are GitHub-owned;
the HTTP client also refuses cross-repository routes and all mutation endpoints
except a normal, exact-head PR merge. No PR source/artifacts are executed.

Repository membership alone does not grant write access. GitHub's assigned write,
maintain, admin/custom permissions and any branch rules determine who can update
main. Do not add a single-user update allowlist or a blanket Actions bypass. The
normal merge endpoint enforces existing protection, and refusal is never retried
with administrator credentials. Human contributions remain governed by repository
roles and configured review/CI rules.

The script independently requires the signed Bot update and complete successful
trusted PR CI even when a private repository's plan does not offer server-side
branch protection. Absence of paid protection features is not itself a reason to
block dependency automation. This CI admission is not a replacement for global
server-side branch protection, and does not claim to prevent a separately authorized
human from pushing. Failed/missing CI, major changes and conflicts remain manual.

Call from a pinned trusted default-branch `workflow_run` handler, guarded to main
and successful Dependabot pull-request runs, or main-only workflow_dispatch. Keep
PR test jobs read-only and separate from the privileged merge handler. Explicitly
configure required validation workflows; never run untrusted PR code with write
credentials. This action changes no repository access, rules, tags or releases.
GITHUB_TOKEN merges do not normally trigger subsequent push workflows; use the
validated pre-merge evidence and explicit dispatch/version tags for later stages.
