# Detector ownership and artifact lifecycle

## Responsibilities

Rust owns source enumeration, input/expansion budgets, private policy dictionaries,
exceptions, redaction, stable receipts and the final passed/findings/incomplete
decision. It does not reimplement a secret-detection database or upload source or
credentials to an engine service. The Gitleaks adapter translates local inputs and
redacted reports; the child owns detection only. There is no general plugin host.

The artifact lifecycle owns intake, integrity, origin, licenses, binary security
acceptance, synthetic detection regressions and immutable distribution. A Rust
source change is not itself an engine update. `tests/gitleaks-pin.json` records the
consumer's exact URL, source, archive/executable hashes and build identity.

## Prebuilt first, reviewed rebuild when necessary

Prefer official prebuilt binaries that satisfy the same acceptance contract.
An upstream version number or checksum alone is insufficient: verify authenticated
origin/source identity, supported platform, retained licenses/notices, actual
binary vulnerability coverage, report compatibility and positive/negative fixtures.
Missing evidence means not accepted. Never select `latest` at scan time.

The current accepted distribution uses an owner rebuild because the existing
8.30.1 recipe required patched runtime/dependency versions and retained binary
symbols for precise auditing. This fallback does not fork detector behavior.
`scripts/build-gitleaks.sh` pins upstream source, verifies module integrity, runs
the real upstream suite, retains licenses and audits compiled code. Its Go tooling
exists only in operation-scoped CI storage and is not a runtime prerequisite.
Moving to an upstream artifact is a normal tested manifest/adapter change, not a
reason to remove vulnerability or license checks. No automatic upstream adoption
is implemented or implied by this policy.

## Independent pipelines

1. `CI/test` consumes the immutable published archive, verifies its hash and GitHub
   provenance, and tests the Rust consumer. It neither builds Go nor silently
   updates the pin. Integrity/compatibility failures still reject source changes.
2. `Detector candidate acceptance` builds the fallback only in its dedicated job,
   audits the candidate and runs actual detection/consumer tests. It records exact
   bytes, locks, compiled imports and audit evidence after success.
3. `Published detector security` audits the actual pinned binary with fresh
   vulnerability data on main changes or explicit dispatch. It does not rebuild
   an obsolete compiler recipe. An audit failure stays visible and requires a
   replacement; it is not a pass or advisory suppression. There is no new schedule.
4. `Publish reviewed detector` accepts only a successful exact-main candidate run,
   successful main CI and owner policies, and the source-bound component tag.
   It publishes the tested bytes once, attests them and verifies anonymous readback.
   Published-version alarms cannot make a validated replacement unpublishable.

`scripts/gitleaks/component.json` identifies the next immutable revision. Dispatch
the candidate on accepted main, inspect its actual archive hash, create its tag at
that exact source, then dispatch publication with the candidate run and hash.
Never reuse a tag, replace assets, or blindly replay a failed publication.
The separate consumer-pin PR must verify published bytes, provenance and all real
consumer tests. The published-security check must succeed for the new pin before
the recovery issue closes. Do not roll back to a known-vulnerable artifact.

## Process safety and remaining platform boundary

The detector receives a bounded private staging tree, sanitized environment, no
stdin and redacted-report flags. Rust verifies the executable before/after use,
limits execution to 120 seconds, watches report growth and Linux resident memory,
and kills/reaps its owned child on errors or unwinding. Reports are no-follow reads
with size/metadata checks. Unexpected exits, malformed reports, timeouts and limits
fail the operation; they cannot produce a passed receipt.

`GOMAXPROCS=1` and `GOMEMLIMIT=384MiB` constrain normal behavior. The 512MiB sampled
RSS threshold and 25ms polling are observations, not hard memory/disk isolation.
They cannot prevent allocation spikes or contain a compromised executable spawning
descendants. On constrained hosts, run the entire scanner in an owner-controlled
cgroup/container with hard memory, swap, task and CPU limits and group cleanup.
Do not use Go virtual-address-space limits as a substitute for a memory cgroup.
Local tests use a capped transient user service; they never exhaust memory or PIDs.
The current adapter is for reviewed engines, not execution of untrusted binaries;
it is not a network or privilege sandbox and does not claim to be one.

GitHub attestations establish an expected publishing identity and source. They do
not alone prove detector correctness or absence of vulnerabilities.
