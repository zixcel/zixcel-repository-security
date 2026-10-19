# Verified dependency merging

This owner-maintained composite action uses the GitHub API only. It never checks
out or executes a pull request, installs its packages, reads its artifacts, or
uses a persistent PAT. Pin the action to a reviewed full commit SHA in each owner.

Call it from an owner `workflow_run` after named validation workflows complete,
and optionally from an owner `workflow_dispatch` accepting a PR number. Give only
`contents: write`, `pull-requests: write`, `checks: read`, `statuses: read` and
`actions: read` to that job. Do not run it in a validation workflow it watches.
No scheduled central controller is required.

Admission requires a same-repository Dependabot PR to main, exactly one signed
Dependabot commit, compatible numeric patch/minor changes, dependency manifests
and locks only, unchanged npm behavior, successful checks and PR workflows,
current main ancestry, and effective strict required PR checks. A 0.x minor
change, major version, image/workflow update, unknown version, changed scripts,
missing verification, conflict, failed check or missing protection stays manual.
An empty or incomplete API response never means success.

The normal SHA-matched squash merge endpoint enforces all existing rulesets.
No admin flag, ruleset mutation, approval fabrication or retry of a rejected
write exists in this action. A separate owner authorization is necessary if an
existing update-access rule does not permit the Actions integration to merge PRs.
Results are read back and written to Actions Summary. The action does not tag,
publish packages, deploy sites, dismiss advisories, or alter update cooldowns.

Run `pnpm install --frozen-lockfile --ignore-scripts`, `pnpm test` and
`pnpm typecheck` in this directory to verify the policy. The runtime has no npm
package dependency; the two development dependencies are monitored daily.
