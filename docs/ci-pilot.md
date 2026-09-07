# Public-fixture CI pilot

The reference gate checks two explicitly public versions of an inert Agent Skill
before publishing the already reviewed release candidate. It does **not** submit
or establish a verdict for the release wheel, sdist, product source, dependencies,
logs or host. The fixture text is treated as bytes, never installed or executed.
The synthetic policy matrix has run in GitHub Actions. Each release run must
separately complete both live fixture gates and retain their evidence before
Publish can run; see [validation scope](#validation-scope).

| Fixture | Bytes | SHA256 |
|---|---:|---|
| `tests/fixtures/public/v1/vtai-ci-public-fixture/SKILL.md`, version 1.0.0 |488|`cdf61469f070b50910a2dcb123311956149ac9175f9a3cefbdb0a7a671532397`|
| `tests/fixtures/public/v2/vtai-ci-public-fixture/SKILL.md`, version 1.0.1 |488|`e21dd34159d74531c304ebfd58c177b1be9e073f0a6457fbfccdc9d1706aa657`|

These new fixtures explicitly permit sharing their exact contents with VirusTotal
and its security community. Their reviewed manifest describes only those bytes.
The script checks both hashes, sizes, exact manifest and closed fixture directory;
extra files, symlinks or changes fail the gate. Changing a skill's content requires
new evidence for its new SHA; version 2 cannot reuse version 1's result.
The [Agent Skills specification](https://agentskills.io/specification) defines the
fixture's frontmatter format. No scanner treats this format as a safety guarantee.

## Credential and service setup

Use one dedicated, stable VTAI agent for the pilot. Create its credential once via
the existing public VTAI registration flow, then put it directly in repository
Settings → Secrets and variables → Actions as **VTAI_CI_TOKEN**. Do not place it in
chat, arguments, a prompt, this repository or evidence. Configure it through a
repository administrator's secret-management interface. No credential is created
by this driver or workflow.

A supported, configured GitHub environment can further restrict release refs.
Availability in a private repository depends on the account plan; declaring an
environment is not proof that its protections exist. The reference workflow uses
a repository secret; verify your repository's protections before enabling it. See [GitHub Secrets](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/use-secrets)
and [environment availability](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments).

Only the two live steps receive `VTAI_TOKEN`, from that secret. Their base URL is
fixed to `https://ai.virustotal.com/api/v3`; no PR input or manifest can redirect it.
`VTAI_TOKEN_FILE` must be unset. A missing credential fails; it does not skip the
gate or register a replacement. PR, fork and synthetic checks have no VTAI secret.
Never rotate identities to avoid quota. Revocation or replacement does not move
receipts to another actor. Repository writers remain part of the secret's trust
boundary; follow [GitHub's secure-use guidance](https://docs.github.com/en/actions/reference/security/secure-use).

Live execution requires the compatible VTAI submission/analysis API and the
reviewed client with durable local recovery. Confirm service availability,
credential access and quota before enabling the workflow. A configuration example
does not provision the secret or establish deployment availability.

## Policy fixed before live testing

`public-fixture-v1`, `minimum_completed_engines=1`, applies identically to real and
synthetic evidence. A final analysis must belong to the registered analysis ID
and fixture SHA. An `exists` response preserves the existing FileResponse and is
labelled `file_report`, with no new analysis ID or claim of a new submission.

| Decision | Criterion | Driver exit |
|---|---|---:|
| allow | Explicit zero malicious/suspicious; at least one harmless+undetected; coherent positive coverage and usable date |0|
| review | Suspicion, insufficient completion, missing decisive counters, unknown/invalid types/categories, incoherent coverage or unusable date |10|
| block | Valid, coherent final evidence with malicious greater than zero |11|
| pending | Registered receipt or analysis still awaiting final results/item/availability |12|
| unknown | Uncertain submission or receipt recovery; no automatic resubmission |13|
| error | Invalid JSON/identity, absent configuration, access/service/quota failure, or an unusable operation |2|

Local cancellation exits130. None of the nonzero results permits publication.
A CLI exit0 can mean `submitted` or `pending`; the gate evaluates its JSON and does
not mistake it for approval. An incomplete analysis remains pending even if its
partial results include a detection. Valid final malicious evidence takes priority
over an absent date; invalid identity or incoherent counts never establish a verdict.

The four decisive counters `malicious`, `suspicious`, `harmless` and `undetected`
must be explicit nonnegative strict integers. No missing decisive count becomes
zero. Optional categories are `timeout`, `confirmed-timeout`, `failure` and
`type-unsupported`. Coverage must contain1–4096 engines; the sum of all observed
statistics must equal that count, and categories with positive statistics must
match the observed coverage categories exactly. An analysis additionally checks
counts against its per-engine results. FileResponse exposes only statistics and
aggregate coverage, so it cannot support the same independent per-engine check.

A failure/timeout/unsupported result is not a completed harmless/undetected result.
Such results can coexist with allow when the minimum and other criteria hold.
Evidence retains every observed counter, `partial: true` and the exact sorted
`partial_reasons`. No zero-failure condition is hidden in allow. Unknown categories
or count disagreements require review. These criteria were chosen before any real
fixture submission, not adjusted to obtain a passing result.

Analysis time must be present, UTC, nonnegative, and no more than300 seconds into
the future. Both analysis and observation timestamps are retained so age can be
assessed. This policy does not promise freshness or force reanalysis: the client
has no such operation. A freshness threshold would require a new policy version.
Allow is a decision under this limited policy, never a claim that a file is safe.

## Reference driver and JSON

Use the complete [v0.7.0 source checkout](https://github.com/king-tero/vt-mcp/tree/v0.7.0),
with that version's verified wheel installed in its Python environment. The wheel
and sdist do **not** contain the driver, fixtures or workflows; downloading the
installation sdist alone is insufficient. Select the actual tag and verify its
release provenance before running from the checkout root. These are reference-script
options, not new `vt-mcp` commands:

```text
python scripts/ci_vtai_fixture.py evaluate --fixture-version 1.0.0 --input CASE.json --evidence /absolute/evidence.json
python scripts/ci_vtai_fixture.py live --fixture-version 1.0.0 --wait 180 --state-dir /absolute/private-state --evidence /absolute/evidence.json
```

The driver uses the installed package's public formatters and CLI, invoking
`python -m vt_mcp` with an argument vector, no shell, and no inherited stdin or
stderr output. Analysis IDs remain opaque; `analysis --wait N -- ID` prevents a
leading dash being treated as an option. It adds no HTTP client or polling SDK.
The child gets the live step's credential in the environment, never in argv.

Live first reads `submission SHA`. Only an explicit initial `not_found` with
HTTP404 permits `submit PATH --mode standard --accept-standard --expected-sha256
SHA --state-dir ABS`. The CLI checks a private copy and records local recovery
state before POST. A prior local reference prevents a new POST, even if receipt
GET returns404. Never delete that state to retry. `submitted` allows polling only
its registered analysis ID; `exists` ends with its file report. An uncertain POST
gets at most one recovery GET, never a repeated POST. Uncertainty can be permanent.

The same state directory is used for both fixtures and reruns on that runner.
Across runners, continuity comes from the stable actor's backend receipts; the
credential or private state directory is not cached/uploaded. A lost acknowledgement
can leave quota consumed or a submission accepted despite local failure. Stopping
locally does not withdraw an accepted file.

The total subprocess budget is350 seconds per fixture. Initial/recovery reads
allow40 seconds each; submission allows150 seconds including the client's15-second
copy and130-second POST; polling allows at most180 seconds, shortened to the
remaining total. Two seconds of each child budget are reserved for interruption,
kill if needed, and reaping. JSON stdout is capped at512KiB; public response models
retain their256KiB limit; the complete evidence file is capped at512KiB. Duplicate
JSON keys/non-finite values, inconsistent CLI status/exit and oversized output fail
closed. No upstream body or child stderr enters evidence.

The evidence file is created exclusively, mode0600. Existing files are not
replaced. Top-level keys are always `schema_version`, `mode`, `scope`, `artifact`,
`provenance`, `evidence`, `decision`, `error`; mode is `synthetic` or `live`, scope
is `public-fixture-only`, schema_version is1. Artifact/provenance may be null when
configuration fails before their identity can be established. There is no empty
successful model.

- `artifact`: fixed name, fixture version/SHA/size, manifest SHA256.
- `provenance`: repository, actual Git commit, run ID/attempt, installed client
  version, and the already verified candidate manifest hash (null for synthetic).
- `evidence`: kind `analysis|file_report|receipt|none`, UTC observation time, owned
  analysis ID or null, and the existing formatted AnalysisResponse, FileResponse,
  SubmissionResponse or null. Analysis `wait` metadata is retained as validated;
  its optional error is reduced to the same closed error fields below.
- `decision`: policy, state, fixed reason, minimum_completed_engines,
  completed_engines (null if not established), partial and partial_reasons.
- `error`: null or `{code,message,retry_after_seconds}`. Messages are fixed;
  backend/CLI free text is not retained. Missing evidence never implies success.

Reason strings are `final_no_detections_with_coverage`, `detected_malicious`,
`suspicious_evidence`, `insufficient_coverage`, `inconsistent_coverage`,
`unknown_category`, `invalid_analysis_date`, `analysis_pending`,
`submission_unknown`, `recovery_unavailable`, `invalid_evidence`,
`configuration_error`, `access_denied`, `service_unavailable`, `rate_limited`,
`deadline_exceeded`. stdout is only a bounded JSON summary of scope/mode/artifact/
decision; full sanitized evidence is retained in the explicit file. Evidence hashes
are recorded separately, not embedded recursively in the JSON.

## Workflows and acceptance

CI retains its existing test/build jobs and adds a no-secret matrix using inert
synthetic analysis responses. The matrix runs the actual `evaluate` entry point.
An allow creates an inert publication marker in a separate conditional step;
review/block/pending/unknown/error skip that step. A final step verifies decision,
exit, Actions outcome, and marker presence/absence. `continue-on-error` is confined
to this synthetic observation; an expected blocked case can make the test job pass
without pretending the fixture was allowed or actually analysed by VirusTotal.
See [step outcome semantics](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax).

Release still validates its annotated tag, approved manifest, successful same-commit
main CI run and exact wheel/sdist bytes. It then installs that wheel with locked
dependencies before exposing any VTAI secret. Both public versions must pass live,
and sanitized evidence retention must succeed, before Publish can run. There is no
live continue-on-error, automatic registration, package upload to VTAI, or rebuild.
The existing installation check still verifies the wheel downloaded from Releases.

An `always()` retention step records only the public fixture manifest, v1/v2 evidence
and their hashes; it excludes credentials, subprocess stderr, state and temporary
files. Artifact names include run ID/attempt and request90-day retention within the
repository's limit. Failed/pending evidence is retained but cannot enable Publish.
[GitHub artifacts](https://docs.github.com/en/actions/tutorials/store-and-share-data)
provide artifact identity; this is not a signature or proof of third-party adoption.

## Validation scope

| Check | Evidence or requirement | What it establishes |
|---|---|---|
| Synthetic policy matrix in actual GitHub Actions | Eight cases exercised | Expected driver outcomes and conditional publication-marker behavior, without a VTAI credential or sample submission |
| Two fixed public fixtures through live VTAI in the pipeline | Required for every release run | Inspect both retained decisions and the selected run; synthetic evidence does not establish live acceptance |
| Versioned release and installation from its channel | Tag, same-commit CI, checksums and post-publication installation verification | Inspect the selected release run and downloaded bytes; no result is inferred from these instructions alone |

For a real run, retain each decision, source/analysis identity and evidence hash
alongside the unchanged release-artifact checksums. If a fixture already exists,
record that fact; never force an upload or label it a new analysis. A synthetic
marker is not an actual publication or a VirusTotal verdict. The gate's scope
remains these two public files, even after live acceptance.
