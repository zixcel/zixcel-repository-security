# Reviewed detector distribution

The repository owns its curated Gitleaks build and its dependency licenses.
The retired vPremises archive URL is not a working distribution route.
The production pin now selects the published component archive and its exact
source recipe. Anonymous archive bytes and signature provenance must be accepted
before production provisioning succeeds. Source CI alone does not repair a URL.

Successful owner CI records the tested detector archive, executable digest,
source identity, exact Go module locks, compiled imports and vulnerability evidence
as a source-bound artifact. CI still runs actual upstream tests, license retention,
compiled-binary vulnerability rejection, scanner regressions and current production
pin provisioning. Synthetic packaging tests do not replace these real checks.

After source acceptance, review the actual main CI artifact and its archive hash.
Only an explicitly approved candidate may receive the component tag
`gitleaks/v8.30.1-r1`. Then dispatch `Publish reviewed detector` on the same main
source with that CI run ID and exact archive hash. It checks successful main CI,
OSS policy, dependency-policy validation and the source-bound tag. The write job
publishes those same bytes without rebuilding, adds build provenance and verifies
the downloaded archive. Existing assets are never replaced; failed attempts must
be inspected before any retry. No cloud credential, external App or central
execution repository is needed.

This releases the detector component, not a new Rust scanner package. Production
CI binds the canonical URL, archive/executable hashes and published recipe together.
It freshly rebuilds/audits that recipe and independently verifies and provisions
the actual published archive before running scanner regressions. The old recipe
is no longer a fallback. Future pin changes require the same source review and
independent consumer acceptance. GitHub provenance identifies the trusted
publishing workflow and source; it does not independently prove every test claim.
