# Check one Python execution before starting it

This guide describes the `vt-mcp guard` commands introduced in version 0.6.0.
An earlier published vt-mcp wheel
does not acquire them by adding a hook configuration. Use the exact reviewed
artifact that includes this module. Codex CLI 0.153.4 is the reference host.

The synchronous hook recognizes exactly this Bash command:

```text
/usr/bin/python3 -I /absolute/path/script.py
```

The hook rewrites it to the installed vt-mcp runner. The runner copies the main
script, seals that copy against modification, queries its SHA-256 through VTAI,
and applies a local policy before handing **those same bytes** to Python. This
sequence does not depend on a model deciding to call an MCP tool. It reads an
existing file report; it never uploads the script or requests a new analysis.

## Exact scope

The command has three tokens, separated by single spaces. The path is absolute,
ends in `.py`, and contains only ASCII letters, digits, `.`, `_`, `-` and `/`.
Components `.` and `..`, doubled slashes, spaces, quotes, escapes, expansions,
redirections, extra arguments and compound commands are outside the grammar.
The path must identify a readable, nonempty regular file of at most **8 MiB**.
The final path component cannot be a symbolic link. Paths are limited to 4096
characters. Policy and credential paths use the same path character restrictions.

Commands outside this grammar pass through unchanged and have **not been
checked**. Other tools, commands sent to an already running process, imports,
libraries, interpreter installation, subprocesses and later actions of a script
are outside this check. The host must actually run and apply the trusted hook;
this adapter is not a host sandbox or a complete execution policy.

This first form is for standalone Python scripts that already use `-I` and can
tolerate a descriptor path. Python sees `/proc/self/fd/N` as both `__file__` and
`sys.argv[0]`. Code that finds resources relative to its original filename can
break. `-I` excludes the original script directory and user site from normal
imports and ignores Python configuration variables. Standard library imports
continue to work; dependencies are not checked by this runner.
[Python isolated mode](https://docs.python.org/3.12/using/cmdline.html#cmdoption-I).

The runtime requires Linux support for `memfd_create`, `MFD_NOEXEC_SEAL`, content
seals and `/proc/self/fd`, plus an executable `/usr/bin/python3`. The memfd is
**non-executable data** read by that interpreter. The runner requires and verifies
the non-executable and content seals; it has no executable-file, ordinary temporary
file or original-path fallback, and does not alter kernel settings.
[Linux memfd execution policy](https://docs.kernel.org/userspace-api/mfd_noexec.html).

Some CPython builds omit the `fcntl` seal constants despite kernel support. The
runner uses the fixed Linux UAPI command and bit values and still checks the
kernel's actual seals and file mode before any lookup or execution. Missing
constants alone do not establish an unsupported kernel; a failed sealing or
descriptor check still blocks both modes.
[Linux seal definitions](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/fcntl.h)
and [Linux command base](https://github.com/torvalds/linux/blob/v6.12/include/uapi/asm-generic/fcntl.h)
(checked 2026-09-06).

## Policy and credentials

Review and create a private regular JSON file outside model prompts and tool
arguments. This is the complete schema; unknown or duplicate fields are rejected:

```json
{
  "schema_version": 1,
  "mode": "control",
  "token_file": "/absolute/private/vtai-token",
  "base_url": "https://ai.virustotal.com/api/v3",
  "minimum_completed_engines": 1,
  "maximum_analysis_age_days": 30
}
```

Store only the existing VTAI credential in `token_file`, using the
[access guide](access.md). Keep the directory and files private to the account
that runs the tool (for example, directory mode 700 and file mode 600). The policy
contains a path, never the credential value. Both files must be regular files;
final symlinks are rejected. The policy limit is 16 KiB and the credential file
limit is 514 bytes, including surrounding whitespace. The credential itself uses
the existing printable ASCII, maximum 512-character VTAI contract.

`minimum_completed_engines` is an integer from 1 to 10000;
`maximum_analysis_age_days` is an integer from 1 to 365. These are explicit policy
choices, not scientifically calibrated guarantees. `mode` must be `control` or
`observe`. The endpoint must pass the existing VTAI HTTPS validation; HTTP is
accepted only for loopback test fixtures. Authentication is **`x-apikey` only**.

Compute the SHA-256 of the exact reviewed policy bytes:

```bash
sha256sum /absolute/private/guard.json
```

Put that digest in the trusted hook definition. Whitespace changes also require
updating the pin. The runner loads the policy again and verifies the same pin;
mode, token path, endpoint and thresholds cannot be overridden by ambient
`VTAI_*` variables or tool input. Missing, malformed or changed policy blocks in
both modes. The policy hash is public metadata, not a credential.

The allow condition requires the correct SHA-256 and all of the following:

- Explicit nonnegative integer `malicious`, `suspicious`, `harmless` and
  `undetected` counters, with malicious and suspicious both zero.
- `harmless + undetected` at least `minimum_completed_engines`, and an explicit
  `coverage.engines` at least that minimum. Failed or timed-out engines alone
  cannot meet the completed-engine condition.
- A UTC analysis timestamp that is not in the future and is no older than
  `maximum_analysis_age_days`. Retrieval time does not replace analysis time.

Detection names and AI analysis text do not participate in this policy. A report
that satisfies it is not a guarantee that a script is safe.

| Result | `control` | `observe` |
|---|---|---|
| Policy conditions satisfied | Start the checked copy | Start the checked copy |
| Detection or insufficient/stale evidence | Block | Report the result and start the checked copy |
| Unknown hash, access failure, missing credential, quota exhaustion, unavailable service, malformed report or timeout | Block | Report the failed check and start the checked copy |
| Invalid/changed policy, invalid file, detected source mutation, preparation or platform failure | Block | Block |
| Cancellation before interpreter start | Do not start | Do not start |

Observation explicitly permits execution after an adverse or unavailable result;
it is not an approval. There are no caches, exceptions supplied by the model,
automatic retries, sleeps for `Retry-After`, uploads or alternate providers.
An admitted query can consume VTAI quota even when the report is unknown or fails.

## Install and activate in Codex

Use a reviewed, fixed artifact in a dedicated versioned environment. Keep its
Python interpreter, package and policy outside agent-editable project files where
the host's permissions allow that. The runner uses the same environment's
absolute Python executable with `-I -m vt_mcp`; the script interpreter remains
`/usr/bin/python3`. Changing installed code is a separate trust decision from
checking a policy digest.

First run the local capability check, replacing paths and `POLICY_SHA256`:

```bash
/absolute/versioned/venv/bin/python -I -m vt_mcp guard doctor \
  --policy /absolute/private/guard.json --policy-sha256 POLICY_SHA256
```

Doctor verifies the pinned policy, credential readability and local sealed-data
capability. It performs no HTTP request and executes no target script. Its success
states `host_activation: unverified`, `network: not_checked` and
`access: not_checked`. It cannot establish hook trust, VTAI authorization,
revocation state, quota, reachability or actual host interception.

Merge [codex-pretool.toml](../examples/hooks/codex-pretool.toml), with its paths and
digest replaced, into one active Codex configuration layer. The documented user
location is `~/.codex/config.toml`; a project `.codex/config.toml` also requires
project trust. Inspect `/hooks`, review the exact definition and trust it through
the normal interface. Restart Codex, inspect its source and trust state again,
then perform a harmless execution check in the actual available permission
profile. An untrusted or modified definition is skipped. The helper does not
write personal configuration or alter hook trust.

Codex loads all matching hook sources, rather than replacing a lower layer.
Avoid multiple rewriters for this command. Review changes to the definition,
policy pin, installed artifact and any other matching hooks. The example's
`|| exit 2` converts command launch failure into an explicit hook failure; it does
not establish behavior when Codex skips, times out, or never invokes the hook.
Do not use a hook-trust bypass as installation evidence.
[Official Codex hook configuration and trust](https://learn.chatgpt.com/docs/hooks)
(reviewed for CLI 0.153.4 on 2026-09-06).

The runner queries VTAI **inside the tool's permissions**. It does not request
broader permissions or change cwd, limits or other tool-input fields. If the host
cannot read the policy/credential or reach VTAI, control blocks. Configure access
appropriate to that host and report the actual tested profile; this guide does
not recommend bypassing its sandbox. Normal `/hooks` trust and real host execution
remain separate acceptance requirements; a simulated event or doctor success
does not satisfy them.

## Output, limits and lifecycle

`guard hook` accepts one JSON object from stdin, up to 64 KiB. It handles
`PreToolUse` / `Bash`, preserves the other tool-input fields, and returns either a
bounded `updatedInput.command`, a fixed denial, or `{}` for an uncovered command.
It does no remote lookup and does not print the event, environment or traceback
for errors. Its configured host timeout is five seconds. Successful rewriting
does not mean the script was checked yet: the runner performs that check.

`guard run --policy PATH --policy-sha256 DIGEST -- /absolute/script.py` opens the
source once, copies at most 8 MiB, checks size and modification metadata, seals the
copy, and computes SHA-256 from the sealed copy. Changes to the original path
after sealing do not change the executed bytes. Changes detected during copying
block. This is not an atomic historical snapshot of a file arbitrarily modified
by another process; the guarantee attaches to the bytes actually copied and
sealed. Preparation uses a three-second deadline checked between file operations;
it cannot interrupt a kernel-blocked filesystem operation.

The existing VTAI client bounds its single lookup to fifteen seconds, caps the
response at 256 KiB, and follows no redirects. HTTP closes before interpreter
start. The new environment omits **every `VTAI_*` variable**, not just known token
names. Other inherited descriptors are marked non-inheritable; only the sealed
data descriptor and normal stdin/stdout/stderr are retained through `exec`.
The runner is replaced by Python instead of leaving a daemon or detached child.

Before start, stderr receives small JSON statuses with a closed reason code,
mode, `starting` or `blocked`, and the SHA-256 when a snapshot exists. Check results
also identify the source as VirusTotal via VTAI, with the analysis date and engine
count when available. Missing evidence is `null`; an oversized engine count is
omitted with `coverage_omitted: true` to keep the status within 2 KiB. `starting`
records intent to hand over to Python, not proof the program ran. It includes no
credential, report body, original pathname or upstream exception text. After
`exec`, stdout/stderr and exit status belong to the script. A blocked policy exits
77; preparation/configuration/exec failure exits 78 (an exec failure adds a
failure status after `starting`); a handled interrupt exits
130. Termination by the host can instead appear as a signal exit.

This is not isolation from another process running as the same user. A permitted
script keeps the host's ordinary permissions and could read a credential file
that those permissions expose. Environment cleanup and a sealed main script do
not certify later filesystem, network, import or process behavior.

## Diagnose, update and remove

For `invalid_policy` or `policy_changed`, review the file and pin without printing
its credential file. For `unsupported_platform`, check the actual kernel,
descriptor capability and fixed interpreter. For `credential_unavailable`, check
the file's type, access and format. `access_denied`, `rate_limited`, `not_found`,
`timeout` and `insufficient_evidence` remain distinct check results; none implies
the script is safe. Doctor cannot resolve remote failures. Do not paste a token
or raw configuration into model context for diagnosis.

Disable the specific non-managed hook in `/hooks` or remove its fragment from its
source, then restart and verify it is no longer active. This removes interception;
it does not revoke the VTAI credential. Revoke separately using the
[access workflow](access.md), then remove any no-longer-needed local credential.
An update requires a reviewed artifact, policy and hook definition; re-check trust
and the harmless execution case after restarting. Never describe protection as
active after the host has skipped or removed the hook.

## Observed host evidence

Acceptance records must distinguish the exact artifact, Codex version, normal
trust flow, actual permission profile, check reason, queried SHA-256 and observed
execution marker. Doctor success or a simulated hook event does not establish
that the host applied a control.

These host checks were completed during private development. Commit IDs and
artifact hashes below refer to that history. Each public release requires its own
verified CI run and checksums.

| Earlier artifact | Observed checks | Environment and limit |
|---|---|---|
| Local guard source `9e72b2a`, wheel SHA256 `5f01f769d70e61b0e627367c4c728a25180acfa231d65610a1d46d3e029ec7b7` | 20 accepted real Codex cases: control/observe outcomes, source replacement, disabled hooks and changed definitions requiring renewed trust | Codex CLI 0.153.4, gpt-6-astra xhigh, runner and script interpreter Python 3.12.3; harmless scripts and loopback VTAI |
| Corrected source `e76dc2f`, earlier CI 0.6 wheel SHA256 `0b2be56e7af9f4685fdc22ef7231e5b1a2af07acc4f7134d05e2a536f609bb70` | Two real control cases: qualified executes with the queried SHA and seals; synthetic suspicious result exits 77 without a marker | Same Codex version/model; runner Python 3.14.7 lacking CPython seal exports, script interpreter remains `/usr/bin/python3` 3.12.3 |

Both checks used normal UI hook review/trust, Linux kernel 6.8.0-139-generic and
the available `danger-full-access` test profile. This describes the observed
profile; it is not a setup recommendation or validation of a restrictive sandbox.
The earlier 20 cases were not repeated for the UAPI correction. The two corrected
CI cases each recorded one rewritten command and one GET of the sealed copy's
SHA; qualified exited 0 and flagged exited 77. The model session's own successful
exit did not turn a blocked command into an allowed one.

The corrected artifact also passed 189 source/archive/install comparisons and
32 selected installed platform/subprocess tests on Python 3.14.7. Its earlier candidate CI
passed Python 3.12, 3.13 and 3.14. These results concern those earlier artifacts;
they do not establish that every later build has been exercised in the host.

The fixtures did not query real VTAI/VirusTotal or submit scripts. The evidence
does not establish a published release or coverage beyond the command form.
In observation mode, adverse evidence is recorded in the guard summary even
when the script exits 0; a model may omit that reason from its final answer.
Inspect the tool summary when making a decision.

Verify the installed wheel against its release checksums and repeat the harmless
execution check after changing the artifact, policy or hook definition. The
[validation matrix](clients.md#service-and-workflow-validation) keeps host evidence
separate from analysis deployment and versioned release verification.
