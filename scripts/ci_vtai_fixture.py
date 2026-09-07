"""Reference CI gate for two explicitly public fixtures, never private distributions."""

import argparse
import hashlib
import importlib.metadata
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from vt_mcp.analyses import (
    format_analysis_response,
    format_submission_response,
    unknown_submission,
    validate_analysis_id,
)
from vt_mcp.reports import VTAIError

ROOT = Path(__file__).resolve().parents[1]
SERVICE = "https://ai.virustotal.com/api/v3"
POLICY = "public-fixture-v1"
MINIMUM_COMPLETED_ENGINES = 1
MAX_ENGINES = 4096
TOTAL_SECONDS = 350.0
READ_SECONDS = 40.0
SUBMIT_SECONDS = 150.0  # Includes the CLI's 15s copy and 130s POST, never renews total.
CLEANUP_SECONDS = 2.0
MAX_OUTPUT = 512 * 1024
DECISIVE = {"malicious", "suspicious", "harmless", "undetected"}
PARTIAL = {"timeout", "confirmed-timeout", "failure", "type-unsupported"}
EXITS = {"allow": 0, "review": 10, "block": 11, "pending": 12, "unknown": 13, "error": 2}
FIXTURES = {
    "1.0.0": ("v1", "cdf61469f070b50910a2dcb123311956149ac9175f9a3cefbdb0a7a671532397"),
    "1.0.1": ("v2", "e21dd34159d74531c304ebfd58c177b1be9e073f0a6457fbfccdc9d1706aa657"),
}
ERROR_REASONS = {
    "not_found": "recovery_unavailable",
    "submission_unknown": "submission_unknown",
    "access_denied": "access_denied",
    "rate_limited": "rate_limited",
    "timeout": "deadline_exceeded",
    "unavailable": "service_unavailable",
    "capacity_exceeded": "service_unavailable",
    "configuration_error": "configuration_error",
    "local_state_unavailable": "recovery_unavailable",
}
ERROR_CODES = set(ERROR_REASONS) | {
    "invalid_input",
    "consent_required",
    "body_too_large",
    "hash_mismatch",
    "receipt_conflict",
    "invalid_response",
    "response_too_large",
    "invalid_arguments",
    "invalid_file",
    "snapshot_changed",
    "snapshot_timeout",
    "confirmation_declined",
    "cancelled",
    "local_failure",
}


class GateError(Exception):
    """Only fixed codes leave this boundary; exception text is never published."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _unique(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def _constant(value):
    raise ValueError("Non-finite JSON value")


def read_json(raw):
    if len(raw) > MAX_OUTPUT:
        raise GateError("invalid_evidence")
    try:
        return json.loads(raw, object_pairs_hook=_unique, parse_constant=_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise GateError("invalid_evidence") from None


def _read_regular(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise GateError("configuration_error")
        raw = os.read(fd, maximum + 1)
        if len(raw) > maximum or len(raw) != info.st_size:
            raise GateError("configuration_error")
        return raw
    finally:
        os.close(fd)


def fixture(version):
    public = ROOT / "tests/fixtures/public"
    expected = []
    for v, (directory, checksum) in FIXTURES.items():
        expected.append(
            {
                "version": v,
                "path": f"tests/fixtures/public/{directory}/vtai-ci-public-fixture/SKILL.md",
                "size": 488,
                "sha256": checksum,
            }
        )
    raw = _read_regular(public / "manifest.json", 4096)
    expected_manifest = {
        "schema_version": 1,
        "kind": "agent-skill",
        "name": "vtai-ci-public-fixture",
        "mode": "standard",
        "publicly_shareable": True,
        "fixtures": expected,
    }
    if raw != (json.dumps(expected_manifest, indent=2) + "\n").encode():
        raise GateError("configuration_error")
    # A closed tree of only these public bytes. Never discover submission paths.
    allowed = {
        "manifest.json",
        "v1",
        "v2",
        "v1/vtai-ci-public-fixture",
        "v2/vtai-ci-public-fixture",
        "v1/vtai-ci-public-fixture/SKILL.md",
        "v2/vtai-ci-public-fixture/SKILL.md",
    }
    if (
        public.is_symlink()
        or {p.relative_to(public).as_posix() for p in public.rglob("*")} != allowed
    ):
        raise GateError("configuration_error")
    for path in public.rglob("*"):
        if path.is_symlink():
            raise GateError("configuration_error")
    selected = next(item for item in expected if item["version"] == version)
    for item in expected:
        data = _read_regular(ROOT / item["path"], 489)
        if len(data) != item["size"] or hashlib.sha256(data).hexdigest() != item["sha256"]:
            raise GateError("configuration_error")
    return selected, hashlib.sha256(raw).hexdigest()


def decision(state, reason, *, completed=None, partial=()):
    return {
        "policy": POLICY,
        "state": state,
        "reason": reason,
        "minimum_completed_engines": MINIMUM_COMPLETED_ENGINES,
        "completed_engines": completed,
        "partial": bool(partial),
        "partial_reasons": sorted(partial),
    }


def policy(response, kind, *, now):
    """One policy for live and synthetic, after binding the response to its fixture."""
    if kind == "receipt":
        if response["status"] == "submission_unknown":
            return decision("unknown", "submission_unknown")
        return decision("pending", "analysis_pending")
    if kind == "analysis" and response["status"] == "pending":
        stats = response.get("stats") or {}
        partial = [key for key in PARTIAL if type(stats.get(key)) is int and stats[key] > 0]
        return decision("pending", "analysis_pending", partial=partial)
    data = response if kind == "analysis" else response["data"]
    stats = data.get("stats" if kind == "analysis" else "last_analysis_stats")
    coverage = data.get("coverage")
    if not isinstance(stats, dict) or not DECISIVE <= stats.keys():
        return decision("review", "insufficient_coverage")
    if not stats.keys() <= DECISIVE | PARTIAL:
        return decision("review", "unknown_category")
    if any(type(value) is not int or value < 0 for value in stats.values()):
        return decision("review", "invalid_evidence")
    if not isinstance(coverage, dict):
        return decision("review", "insufficient_coverage")
    engines, categories = coverage.get("engines"), coverage.get("categories")
    if type(engines) is not int or not 0 < engines <= MAX_ENGINES:
        return decision("review", "insufficient_coverage")
    observed = sorted(key for key, value in stats.items() if value > 0)
    if categories != observed or sum(stats.values()) != engines:
        return decision("review", "inconsistent_coverage")
    if kind == "analysis":
        results = data.get("results")
        if not isinstance(results, dict) or len(results) != engines:
            return decision("review", "inconsistent_coverage")
        counts = Counter()
        for result in results.values():
            category = result.get("category") if isinstance(result, dict) else None
            if not isinstance(category, str) or category not in DECISIVE | PARTIAL:
                return decision("review", "unknown_category")
            counts[category] += 1
        if dict(counts) != {key: value for key, value in stats.items() if value > 0}:
            return decision("review", "inconsistent_coverage")
    completed = stats["harmless"] + stats["undetected"]
    partial = sorted(key for key in PARTIAL if stats.get(key, 0) > 0)
    detail = {"completed": completed, "partial": partial}
    if stats["malicious"] > 0:
        return decision("block", "detected_malicious", **detail)
    if stats["suspicious"] > 0:
        return decision("review", "suspicious_evidence", **detail)
    if completed < MINIMUM_COMPLETED_ENGINES:
        return decision("review", "insufficient_coverage", **detail)
    try:
        date = data["analysis_date"]
        if not isinstance(date, str) or not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|\+00:00)", date
        ):
            raise ValueError
        measured = datetime.fromisoformat(date)
        if measured.timestamp() < 0 or (measured - now).total_seconds() > 300:
            raise ValueError
    except (ValueError, TypeError, KeyError, OverflowError):
        return decision("review", "invalid_analysis_date", **detail)
    return decision("allow", "final_no_detections_with_coverage", **detail)


def _error(raw):
    if (
        not isinstance(raw, dict)
        or not isinstance(raw.get("code"), str)
        or raw["code"] not in ERROR_CODES
    ):
        raise GateError("invalid_evidence")
    retry = raw.get("retry_after_seconds")
    if retry is not None and (type(retry) is not int or not 0 <= retry <= 86400):
        raise GateError("invalid_evidence")
    return {
        "code": raw["code"],
        "message": "The CLI did not produce final usable evidence.",
        "retry_after_seconds": retry,
    }


def evaluate(raw, item, *, now, forbidden=()):
    """Bind identity first; retain only the existing CLI's public formatted models."""
    if not isinstance(raw, dict):
        raise GateError("invalid_evidence")
    status = raw.get("status")
    if not isinstance(status, str):
        raise GateError("invalid_evidence")
    if status == "error":
        error = _error(raw.get("error"))
        recovery = raw.get("submission")
        if recovery is not None:
            if (
                not isinstance(recovery, dict)
                or not isinstance(recovery.get("status"), str)
                or recovery["status"] not in {"submitted", "submission_unknown"}
            ):
                raise GateError("invalid_evidence")
            result, kind, _, _ = evaluate(recovery, item, now=now, forbidden=forbidden)
            return result, kind, decision("unknown", "submission_unknown"), error
        reason = ERROR_REASONS.get(error["code"], "invalid_evidence")
        return (
            None,
            "none",
            decision(
                "unknown" if reason in {"submission_unknown", "recovery_unavailable"} else "error",
                reason,
            ),
            error,
        )
    if status not in {"submitted", "submission_unknown", "exists", "pending", "completed"}:
        raise GateError("invalid_evidence")
    if raw.get("sha256") != item["sha256"]:
        raise GateError("invalid_evidence")
    if status in {"pending", "completed"}:
        if raw.get("source") != "VirusTotal via VTAI":
            raise GateError("invalid_evidence")
        validate_analysis_id(raw.get("analysis_id"))
        kind = "analysis"
    else:
        if (
            raw.get("submission_id") != item["sha256"]
            or raw.get("size") != 488
            or type(raw.get("size")) is not int
            or raw.get("mode") != "standard"
            or raw.get("can_resubmit") is not False
        ):
            raise GateError("invalid_evidence")
        kind = "file_report" if status == "exists" else "receipt"
        if kind == "file_report":
            report = raw.get("report")
            data = report.get("data") if isinstance(report, dict) else None
            if not isinstance(data, dict) or data.get("id") != item["sha256"]:
                raise GateError("invalid_evidence")
    try:
        if kind == "analysis":
            result = format_analysis_response(raw, raw["analysis_id"], forbidden_values=forbidden)
            wait = raw.get("wait")
            if wait is not None:
                if (
                    not isinstance(wait, dict)
                    or set(wait) != {"status", "last_error"}
                    or wait["status"]
                    != ("completed" if status == "completed" else "budget_exhausted")
                    or (status == "completed" and wait["last_error"] is not None)
                ):
                    raise GateError("invalid_evidence")
                result["wait"] = {
                    "status": wait["status"],
                    "last_error": _error(wait["last_error"])
                    if wait["last_error"] is not None
                    else None,
                }
        else:
            result = format_submission_response(
                raw, item["sha256"], size=488, forbidden_values=forbidden
            )
            if kind == "file_report":
                result = result["report"]
    except VTAIError:
        return None, "none", decision("review", "invalid_evidence"), None
    return result, kind, policy(result, kind, now=now), None


def _stop(process, stop_at):
    if process.poll() is None:
        process.send_signal(signal.SIGINT)
        try:
            process.wait(timeout=max(0.01, min(0.5, stop_at - time.monotonic())))
        except subprocess.TimeoutExpired:
            process.kill()
    try:
        process.wait(timeout=max(0.01, stop_at - time.monotonic()))
    except subprocess.TimeoutExpired:
        raise GateError("deadline_exceeded") from None


def run_cli(arguments, *, deadline, limit):
    """Bounded pipe capture, no shell, no inherited stdin or stderr output."""
    stop_at = min(deadline, time.monotonic() + limit)
    work_until = stop_at - CLEANUP_SECONDS
    if work_until <= time.monotonic():
        raise GateError("deadline_exceeded")
    process = subprocess.Popen(
        [sys.executable, "-m", "vt_mcp", *arguments],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    output = bytearray()
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = work_until - time.monotonic()
                if remaining <= 0:
                    raise GateError("deadline_exceeded")
                for key, _ in selector.select(min(remaining, 0.1)):
                    part = os.read(key.fileobj.fileno(), 65536)
                    if not part:
                        selector.unregister(key.fileobj)
                    else:
                        output.extend(part)
                        if len(output) > MAX_OUTPUT:
                            raise GateError("invalid_evidence")
        code = process.wait(timeout=max(0.01, work_until - time.monotonic()))
        if code in {130, -signal.SIGINT, -signal.SIGTERM}:
            raise KeyboardInterrupt
        raw = read_json(output)
        status = raw.get("status") if isinstance(raw, dict) else None
        if not isinstance(status, str):
            raise GateError("invalid_evidence")
        valid = (
            (code == 0 and status in {"submitted", "exists", "pending", "completed"})
            or (
                code == 3
                and (
                    status == "submission_unknown"
                    or (
                        status == "error"
                        and isinstance(raw.get("error"), dict)
                        and raw["error"].get("code") == "submission_unknown"
                    )
                )
            )
            or (code == 2 and status == "error")
        )
        if not valid:
            raise GateError("invalid_evidence")
        if status == "error":
            _error(raw.get("error"))
        return raw
    except subprocess.TimeoutExpired:
        raise GateError("deadline_exceeded") from None
    finally:
        _stop(process, stop_at)
        process.stdout.close()


def live(item, *, state_dir, seconds, token, deadline):
    def call(args, limit):
        return run_cli(args, deadline=deadline, limit=limit)

    receipt = call(["submission", item["sha256"]], READ_SECONDS)
    evaluate(receipt, item, now=datetime.now(UTC), forbidden=(token,))
    # Only an explicit initial404 from the CLI allows the consent-bound submit.
    if (
        receipt.get("status") == "error"
        and receipt.get("error", {}).get("code") == "not_found"
        and receipt["error"].get("http_status") == 404
        and "submission" not in receipt
    ):
        try:
            receipt = call(
                [
                    "submit",
                    str(ROOT / item["path"]),
                    "--mode",
                    "standard",
                    "--accept-standard",
                    "--expected-sha256",
                    item["sha256"],
                    "--state-dir",
                    str(state_dir),
                ],
                SUBMIT_SECONDS,
            )
        except (GateError, OSError, subprocess.SubprocessError):
            receipt = unknown_submission(item["sha256"], 488)
        ambiguous = receipt.get("status") == "submission_unknown" or (
            receipt.get("status") == "error" and "submission" in receipt
        )
        if ambiguous and deadline - time.monotonic() > CLEANUP_SECONDS + 1:
            try:
                recovered = call(["submission", item["sha256"]], READ_SECONDS)
                evaluate(recovered, item, now=datetime.now(UTC), forbidden=(token,))
                if recovered.get("status") == "submitted":
                    receipt = recovered
            except (GateError, VTAIError):
                pass
    normalized, kind, _, _ = evaluate(receipt, item, now=datetime.now(UTC), forbidden=(token,))
    if kind == "receipt" and normalized["status"] == "submitted":
        wait = min(seconds, max(0, int(deadline - time.monotonic() - 5)))
        if wait < 1:
            return receipt
        result = call(["analysis", "--wait", str(wait), "--", normalized["analysis_id"]], wait + 4)
        if (
            result.get("status") in {"pending", "completed"}
            and result.get("analysis_id") != normalized["analysis_id"]
        ):
            raise GateError("invalid_evidence")
        return result
    return receipt


def provenance(mode):
    commit = (
        subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, timeout=5, stderr=subprocess.DEVNULL
        )
        .decode()
        .strip()
    )
    if not re.fullmatch(r"[a-f0-9]{40}", commit):
        raise GateError("configuration_error")
    candidate_hash = os.environ.get("MANIFEST_SHA256") if mode == "live" else None
    if mode == "live":
        if (
            os.environ.get("GITHUB_REPOSITORY") != "king-tero/vt-mcp"
            or os.environ.get("GITHUB_SHA") != commit
            or not re.fullmatch(r"[a-f0-9]{64}", candidate_hash or "")
        ):
            raise GateError("configuration_error")
        if (
            hashlib.sha256(_read_regular(ROOT / "dist/SHA256SUMS", 4096)).hexdigest()
            != candidate_hash
        ):
            raise GateError("configuration_error")
    run_id, attempt = os.environ.get("GITHUB_RUN_ID"), os.environ.get("GITHUB_RUN_ATTEMPT", "1")
    if (
        (mode == "live" and run_id is None)
        or (run_id is not None and not re.fullmatch(r"[1-9][0-9]{0,19}", run_id))
        or not re.fullmatch(r"[1-9][0-9]{0,5}", attempt)
    ):
        raise GateError("configuration_error")
    return {
        "repository": "king-tero/vt-mcp",
        "commit": commit,
        "workflow_run_id": run_id,
        "run_attempt": int(attempt),
        "client_version": importlib.metadata.version("vt-mcp"),
        "candidate_manifest_sha256": candidate_hash,
    }


def write_evidence(path, report):
    if not path.is_absolute():
        raise GateError("configuration_error")
    encoded = json.dumps(report, ensure_ascii=True, allow_nan=False).encode() + b"\n"
    if len(encoded) > MAX_OUTPUT:
        raise GateError("invalid_evidence")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    for name in ("evaluate", "live"):
        command = sub.add_parser(name)
        command.add_argument("--fixture-version", choices=tuple(FIXTURES), required=True)
        command.add_argument("--evidence", type=Path, required=True)
        if name == "evaluate":
            command.add_argument("--input", type=Path, required=True)
        else:
            command.add_argument("--state-dir", type=Path, required=True)
            command.add_argument("--wait", type=int, choices=range(1, 181), default=180)
    args = parser.parse_args(argv)
    deadline = time.monotonic() + TOTAL_SECONDS
    report = {
        "schema_version": 1,
        "mode": "synthetic" if args.mode == "evaluate" else "live",
        "scope": "public-fixture-only",
        "artifact": None,
        "provenance": None,
        "evidence": {
            "kind": "none",
            "observed_at": datetime.now(UTC).isoformat(),
            "analysis_id": None,
            "response": None,
        },
        "decision": decision("error", "configuration_error"),
        "error": None,
    }
    exit_code = 2
    started = False
    previous_signal = signal.getsignal(signal.SIGTERM)

    def interrupted(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    try:
        item, manifest_hash = fixture(args.fixture_version)
        report["artifact"] = {
            "name": "vtai-ci-public-fixture",
            "version": item["version"],
            "sha256": item["sha256"],
            "size": item["size"],
            "manifest_sha256": manifest_hash,
        }
        report["provenance"] = provenance(args.mode)
        token = None
        if args.mode == "live":
            token = os.environ.get("VTAI_TOKEN")
            if (
                not token
                or len(token) > 4096
                or any(c.isspace() for c in token)
                or "VTAI_TOKEN_FILE" in os.environ
                or os.environ.get("VTAI_BASE_URL") != SERVICE
                or not args.state_dir.is_absolute()
            ):
                raise GateError("configuration_error")
            started = True
            raw = live(
                item, state_dir=args.state_dir, seconds=args.wait, token=token, deadline=deadline
            )
        else:
            raw = read_json(_read_regular(args.input, MAX_OUTPUT))
        response, kind, result, error = evaluate(
            raw, item, now=datetime.now(UTC), forbidden=(token,) if token else ()
        )
        report["evidence"].update(
            observed_at=datetime.now(UTC).isoformat(),
            kind=kind,
            analysis_id=response.get("analysis_id")
            if response and kind in {"analysis", "receipt"}
            else None,
            response=response,
        )
        report["decision"], report["error"] = result, error
        exit_code = EXITS[result["state"]]
    except KeyboardInterrupt:
        if started:
            report["evidence"].update(
                kind="receipt", response=unknown_submission(item["sha256"], 488)
            )
        report["decision"] = decision("unknown", "submission_unknown")
        exit_code = 130
    except (
        GateError,
        VTAIError,
        OSError,
        ValueError,
        subprocess.SubprocessError,
        importlib.metadata.PackageNotFoundError,
    ) as exc:
        code = exc.code if isinstance(exc, GateError) else "invalid_evidence"
        report["decision"] = decision("error", code)
        report["error"] = {
            "code": code,
            "message": "The fixture gate could not establish valid evidence.",
            "retry_after_seconds": None,
        }
    finally:
        signal.signal(signal.SIGTERM, previous_signal)
    try:
        write_evidence(args.evidence, report)
    except (OSError, ValueError, GateError):
        return 130 if exit_code == 130 else 2
    print(
        json.dumps(
            {
                "scope": report["scope"],
                "mode": report["mode"],
                "artifact": report["artifact"],
                "decision": report["decision"],
            },
            ensure_ascii=True,
        )
    )
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
