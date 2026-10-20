# Reviewed detector distribution

The repository owns its curated Gitleaks build and its dependency licenses.
The retired vPremises archive URL is not a working distribution route.
Current production pin values remain unchanged until an actual published archive
has been independently accepted. Source CI success alone does not repair that URL.

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

This releases the detector component, not a new Rust scanner package. Afterwards,
review the canonical download URL, archive/executable hashes and production build
recipe together in a normal source PR. Verify provisioning from the anonymous
published archive and real scanner consumers before removing the historical
production-recipe fallback. Do not mark that separate acceptance complete merely
because the component was published. GitHub provenance identifies the trusted
publishing workflow and source; it does not independently prove every test claim.
