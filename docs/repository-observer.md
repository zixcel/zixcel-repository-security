# Repository configuration observer

`zix-repository-observer` is a separate, read-only Rust CLI and library. The
Gitleaks source scanner retains its existing executable and dependencies. This
observer does not schedule fleet work, apply settings, approve PRs, retrieve
secret values or grant permission to another tool.

## Observe one owner/repository

Use a short-lived GitHub credential with only the read permissions needed for
the selected repository. Supply it as `ZIX_REPOSITORY_GITHUB_TOKEN` in the local
process environment, never an argument or a committed configuration. The tool
does not enroll, renew or persist credentials. The existing OS custody owner can
supply credentials separately; this CLI does not implement a key store.

```sh
umask 077
zix-repository-observer observe --repository example/project > observation.json
```

Add `--secret-metadata` only when authorized to list repository Actions secret
names and creation/update timestamps. It never fetches values. Organization and
Environment secrets are outside that endpoint's scope and remain unobserved.
Treat observations as private operational metadata, including for public repos.

The fixed API origin is `https://api.github.com`, API version `2026-03-10`.
Crowsi's HTTPS transport supplies TLS verification, a fixed client identifier,
no proxies/redirects/retries, a shared 40-second/32-request budget and a 1 MiB
response limit. Lists use at most two pages of 100 entries. Up to eight rulesets
receive detailed reads. The complete output is limited to 1 MiB. No HTTP method
other than GET is implemented. No child process is launched during observation.

## What the states mean

Each component carries `supported`, `denied`, `unobserved` or `partial` and a
reason. `supported` means this specific projection was read, not that it is safe
or that every GitHub protection was evaluated. An empty successful list differs
from a 404, denial, timeout, schema mismatch or truncated list. Duplicate IDs,
count changes, pagination and detail limits retain incomplete evidence.

Collected projections cover repository workflow defaults, default-branch legacy
protection, inherited and local branch/tag rulesets, and Environment reviewer,
timer and branch-policy declarations. Effective per-job/reusable-workflow token
permissions require source review and are explicitly **unobserved**. Environment
deployment pattern effectiveness and custom protection apps also remain
unobserved. There is no claim of organization-wide credential visibility or a
comprehensive security certification. Review-requirement declarations do not
prove a future deployment will actually use that Environment.

Repository ID, full name and default branch are checked before and after reads.
GitHub does not provide an atomic cross-endpoint snapshot here. Fresh collection
detects drift in the projected components; it cannot prevent later changes.
API list pagination is not a server-side transactional snapshot.

## Review an exact proposed defaults change

A proposal names the repository ID, configuration hash, component's data hash
and desired observation. `configuration_sha256` excludes retrieval time and
includes identity, states, reasons and projected data. Hashes bind content;
they are not signatures, authorization or evidence of a trusted author.

```json
{
  "schema": "zix-repository-proposal/v1",
  "repository_id": 1,
  "configuration_sha256": "<observation.configuration_sha256>",
  "changes": [{
    "component": "actions_defaults",
    "expected_sha256": "<SHA256 of compact canonical component.data JSON>",
    "desired": {
      "default_workflow_permissions": "read",
      "can_approve_pull_request_reviews": false
    }
  }]
}
```

```sh
zix-repository-observer review --baseline /absolute/observation.json \
  --proposal /absolute/proposal.json > review.json
```

Both input files must be regular, non-group/world-writable, absolute paths with
no symlink components, and at most 1 MiB. The CLI recollects from GitHub before
review. Retain the same secret-metadata selection in both calls. It refuses
tampering, identity/configuration drift, timestamps older than 24 hours or over
60 seconds in the future, duplicates, unknown fields, unsupported targets and
no-op changes. Desired data uses compact sorted JSON keys for component hashes.

Only the two typed Actions defaults fields are currently proposal targets.
Ruleset, Environment and credential operations require a separate owner-specific
operation and human authorization; their observation is not an executable plan.
Successful review always emits `approval_required: true`, `executable: false`.
It never applies a change, even after a previously approved proposal.

## Development and distribution

Run `cargo test --locked -p zixcel-repository-observer` and Clippy for this
package. Read-only hosted CI performs compilation and bounded synthetic tests;
it does not use management tokens or call real configuration APIs. Native
candidate archives contain source identity, hashes, owner licenses and resolved
build/development dependency notices. That inventory is not a linked-binary
SBOM. Formal GitHub Release publication is a separate protected operation.

Official endpoint contracts:

- [Actions defaults](https://docs.github.com/en/rest/actions/permissions#get-default-workflow-permissions-for-a-repository)
- [Repository rulesets](https://docs.github.com/en/rest/repos/rules#get-all-repository-rulesets)
- [Environments and plan limitations](https://docs.github.com/en/rest/deployments/environments#list-environments)
- [Secret metadata](https://docs.github.com/en/rest/actions/secrets#list-repository-secrets)
