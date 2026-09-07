"""Offline policy/orchestration checks: only inert fixtures and isolated child processes."""

import copy
import importlib.util
import json
import shutil
import signal
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "ci_vtai_fixture", Path(__file__).resolve().parents[1] / "scripts/ci_vtai_fixture.py"
)
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)
NOW = datetime(2026, 9, 6, 12, tzinfo=UTC)
ITEM = {
    "version": "1.0.0",
    "path": "tests/fixtures/public/v1/vtai-ci-public-fixture/SKILL.md",
    "size": 488,
    "sha256": gate.FIXTURES["1.0.0"][1],
}
ID = "-opaque/analysis?literal%#é"


def report(categories=("undetected",), *, status="completed"):
    results = {
        f"Synthetic engine {n}": {
            "engine_name": f"Synthetic engine {n}",
            "engine_version": None,
            "engine_update": None,
            "category": category,
            "result": None,
            "method": None,
        }
        for n, category in enumerate(categories)
    }
    stats = dict.fromkeys(("malicious", "suspicious", "harmless", "undetected"), 0)
    for category in categories:
        stats[category] = stats.get(category, 0) + 1
    return {
        "status": status,
        "analysis_id": ID,
        "analysis_status": "completed" if status == "completed" else "in-progress",
        "sha256": ITEM["sha256"],
        "source": "VirusTotal via VTAI",
        "retrieved_at": "2026-09-06T12:00:00+00:00",
        "analysis_date": "2026-09-05T12:00:00+00:00",
        "stats": stats,
        "results": results,
        "detections": [],
        "coverage": {"engines": len(results), "categories": sorted(set(categories))},
        "report_url": f"https://www.virustotal.com/gui/file/{ITEM['sha256']}",
        "next_poll_after_seconds": None if status == "completed" else 5,
        "pending_reason": None if status == "completed" else "processing",
    }


def receipt(status="submitted", *, item=None):
    item = item or ITEM
    value = gate.unknown_submission(item["sha256"], 488)
    value["status"] = status
    if status == "submitted":
        value.update(analysis_id=ID, next_poll_after_seconds=5)
    if status == "exists":
        analysis = report()
        value["report"] = {
            "data": {
                "id": item["sha256"],
                "source": "VirusTotal",
                "last_analysis_stats": analysis["stats"],
                "detections": [],
                "type_description": "ASCII text",
                "ai_insights": None,
                "analysis_date": analysis["analysis_date"],
                "coverage": analysis["coverage"],
                "report_url": f"https://www.virustotal.com/gui/file/{item['sha256']}",
            }
        }
    return value


def error(code="not_found", status=404):
    return {
        "status": "error",
        "error": {
            "code": code,
            "message": "inert untrusted message",
            "http_status": status,
            "retryable": False,
            "retry_after_seconds": None,
        },
    }


def outcome(value):
    return gate.evaluate(value, ITEM, now=NOW)[2]


@pytest.mark.parametrize(
    "categories,state",
    [
        (("undetected",), "allow"),
        (("harmless",), "allow"),
        (("undetected", "timeout"), "allow"),
        (("harmless", "confirmed-timeout", "failure", "type-unsupported"), "allow"),
        (("malicious",), "block"),
        (("malicious", "timeout"), "block"),
        (("suspicious", "undetected"), "review"),
        (("failure",), "review"),
        (("unrecognized", "undetected"), "review"),
        ((), "review"),
    ],
)
def test_policy_decisions_and_partial_coverage(categories, state):
    value = report(categories)
    result = outcome(value)
    assert result["state"] == state
    assert result["policy"] == "public-fixture-v1"
    assert result["minimum_completed_engines"] == 1
    if state in {"allow", "block"}:
        assert result["partial_reasons"] == sorted(set(categories) & gate.PARTIAL)
        assert result["partial"] is bool(set(categories) & gate.PARTIAL)
        assert gate.evaluate(value, ITEM, now=NOW)[0]["stats"] == value["stats"]


@pytest.mark.parametrize("key", sorted(gate.DECISIVE))
def test_decisive_counters_are_never_defaulted(key):
    value = report()
    del value["stats"][key]
    assert outcome(value)["state"] == "review"


@pytest.mark.parametrize("value", [True, -1, 1.0, "0", None])
def test_invalid_decisive_types_require_review(value):
    raw = report()
    raw["stats"]["malicious"] = value
    assert outcome(raw)["state"] == "review"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda r: r["stats"].update(undetected=2),
        lambda r: r["coverage"].update(engines=2),
        lambda r: r["coverage"].update(categories=["harmless"]),
        lambda r: r["results"]["Synthetic engine 0"].update(category="harmless"),
        lambda r: r["stats"].update(unrecognized=0),
        lambda r: r["coverage"].update(engines=None),
    ],
)
def test_incoherent_evidence_cannot_allow(mutation):
    raw = report()
    mutation(raw)
    assert outcome(raw)["state"] == "review"


@pytest.mark.parametrize("date", [None, "bad-date", "2026-09-06T12:05:01Z", "1969-12-31T23:59:59Z"])
def test_missing_invalid_future_dates_require_review(date):
    raw = report()
    raw["analysis_date"] = date
    assert outcome(raw)["state"] == "review"


def test_valid_malicious_final_precedes_absent_date_but_pending_stays_pending():
    raw = report(("malicious", "failure"))
    raw["analysis_date"] = None
    assert outcome(raw)["state"] == "block"
    pending = report(("malicious", "failure"), status="pending")
    result = outcome(pending)
    assert result["state"] == "pending" and result["partial_reasons"] == ["failure"]


def test_exists_preserves_file_report_without_claiming_a_new_analysis():
    value, kind, decision, error_value = gate.evaluate(receipt("exists"), ITEM, now=NOW)
    assert kind == "file_report" and decision["state"] == "allow"
    assert error_value is None and set(value) == {"data"}
    assert "analysis_id" not in value
    value["data"]["coverage"]["categories"] = ["harmless"]
    assert gate.policy(value, kind, now=NOW)["state"] == "review"


@pytest.mark.parametrize(
    "status,expected", [("submitted", "pending"), ("submission_unknown", "unknown")]
)
def test_receipts_are_never_final_reports(status, expected):
    assert outcome(receipt(status))["state"] == expected


@pytest.mark.parametrize(
    "mutation",
    [
        lambda r: r.update(sha256="0" * 64),
        lambda r: r.update(source="other service"),
        lambda r: r.update(analysis_id="bad id"),
    ],
)
def test_wrong_identity_never_reaches_policy(mutation):
    raw = report()
    mutation(raw)
    with pytest.raises((gate.GateError, gate.VTAIError)):
        outcome(raw)


def test_wrong_existing_file_identity_is_error():
    raw = receipt("exists")
    raw["report"]["data"]["id"] = "0" * 64
    with pytest.raises(gate.GateError):
        outcome(raw)


def test_opaque_id_and_wait_metadata_preserved_without_shell_interpretation():
    raw = report()
    raw["wait"] = {"status": "completed", "last_error": None}
    result = gate.evaluate(raw, ITEM, now=NOW)[0]
    assert result["analysis_id"] == ID and result["wait"] == raw["wait"]
    raw["wait"]["status"] = "budget_exhausted"
    with pytest.raises(gate.GateError):
        outcome(raw)


@pytest.mark.parametrize(
    "payload",
    [
        b'{"status":"x","status":"y"}',
        b'{"n":NaN}',
        b'{"n":Infinity}',
        b"{}{}",
        b"x",
        b" " * (gate.MAX_OUTPUT + 1),
    ],
)
def test_bounded_single_strict_json(payload):
    with pytest.raises(gate.GateError):
        gate.read_json(payload)


def test_fixture_hash_and_tree_are_closed(monkeypatch, tmp_path):
    root = tmp_path / "repo"
    shutil.copytree(gate.ROOT / "tests/fixtures/public", root / "tests/fixtures/public")
    monkeypatch.setattr(gate, "ROOT", root)
    first, _ = gate.fixture("1.0.0")
    second, _ = gate.fixture("1.0.1")
    assert first["size"] == second["size"] == 488 and first["sha256"] != second["sha256"]
    (root / "tests/fixtures/public/extra.txt").write_text("extra innocent bytes")
    with pytest.raises(gate.GateError):
        gate.fixture("1.0.0")
    (root / "tests/fixtures/public/extra.txt").unlink()
    path = root / first["path"]
    path.write_text("different innocent bytes")
    with pytest.raises(gate.GateError):
        gate.fixture("1.0.0")
    path.unlink()
    path.symlink_to(root / second["path"])
    with pytest.raises(gate.GateError):
        gate.fixture("1.0.0")


class Sequence:
    def __init__(self, monkeypatch, responses):
        self.responses = list(responses)
        self.calls = []
        monkeypatch.setattr(gate, "run_cli", self)

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        value = self.responses.pop(0)
        if isinstance(value, BaseException):
            raise value
        return copy.deepcopy(value)


def run_live():
    return gate.live(
        ITEM,
        state_dir=Path("/private/state"),
        seconds=180,
        token="inert-token",
        deadline=time.monotonic() + 350,
    )


def test_live_one_explicit_submit_then_owned_analysis(monkeypatch):
    sequence = Sequence(monkeypatch, [error(), receipt(), report()])
    assert run_live()["status"] == "completed"
    assert [a[0] for a, _ in sequence.calls] == ["submission", "submit", "analysis"]
    submit = sequence.calls[1][0]
    assert submit[submit.index("--expected-sha256") + 1] == ITEM["sha256"]
    assert "--accept-standard" in submit and submit[submit.index("--mode") + 1] == "standard"
    assert sequence.calls[2][0] == ["analysis", "--wait", "180", "--", ID]
    assert len({kw["deadline"] for _, kw in sequence.calls}) == 1
    assert "inert-token" not in repr(sequence.calls)


@pytest.mark.parametrize(
    "response",
    [
        receipt("submission_unknown"),
        error("access_denied", 403),
        error("rate_limited", 429),
        error("unavailable", 503),
    ],
)
def test_initial_unknown_or_failure_never_submits(monkeypatch, response):
    sequence = Sequence(monkeypatch, [response])
    assert run_live() == response
    assert len(sequence.calls) == 1


@pytest.mark.parametrize(
    "ambiguous",
    [
        receipt("submission_unknown"),
        gate.GateError("deadline_exceeded"),
        gate.GateError("invalid_evidence"),
    ],
)
def test_ambiguous_submit_only_recovers_get_once(monkeypatch, ambiguous):
    sequence = Sequence(monkeypatch, [error(), ambiguous, error()])
    result = run_live()
    assert result["status"] == "submission_unknown"
    assert [a[0] for a, _ in sequence.calls] == ["submission", "submit", "submission"]


def test_recovered_owned_id_can_poll_without_resubmission(monkeypatch):
    sequence = Sequence(monkeypatch, [error(), receipt("submission_unknown"), receipt(), report()])
    assert run_live()["status"] == "completed"
    assert sum(a[0] == "submit" for a, _ in sequence.calls) == 1


def test_prior_receipt_never_reissues_submit(monkeypatch):
    sequence = Sequence(monkeypatch, [receipt(), report()])
    assert run_live()["status"] == "completed"
    assert [a[0] for a, _ in sequence.calls] == ["submission", "analysis"]


def test_exists_does_not_poll_or_associate_analysis(monkeypatch):
    sequence = Sequence(monkeypatch, [error(), receipt("exists")])
    assert run_live()["status"] == "exists"
    assert len(sequence.calls) == 2


def test_submission_cancel_is_preserved_without_get_or_new_post(monkeypatch):
    sequence = Sequence(monkeypatch, [error(), KeyboardInterrupt()])
    with pytest.raises(KeyboardInterrupt):
        run_live()
    assert len(sequence.calls) == 2


def test_wrong_selected_analysis_cannot_be_used(monkeypatch):
    value = report()
    value["analysis_id"] = "different-id"
    Sequence(monkeypatch, [receipt(), value])
    with pytest.raises(gate.GateError):
        run_live()


def child(monkeypatch, code):
    original = subprocess.Popen
    observed = []

    def start(argv, **kwargs):
        observed.append((argv, kwargs))
        process = original([sys.executable, "-c", code], **kwargs)
        observed.append(process)
        return process

    monkeypatch.setattr(gate.subprocess, "Popen", start)
    return observed


def test_real_child_capture_uses_argv_without_shell_or_stderr(monkeypatch):
    observed = child(
        monkeypatch,
        'import sys; print("{\\"status\\":\\"pending\\"}"); print("private-error",file=sys.stderr)',
    )
    assert (
        gate.run_cli(["analysis", "--", ID], deadline=time.monotonic() + 4, limit=4)["status"]
        == "pending"
    )
    argv, kwargs = observed[0]
    assert argv[-1] == ID and "shell" not in kwargs
    assert kwargs["stdin"] is subprocess.DEVNULL and kwargs["stderr"] is subprocess.DEVNULL
    assert observed[1].poll() == 0


@pytest.mark.parametrize(
    "code",
    [
        'print("{}" * 300000)',
        "import time; time.sleep(20)",
        'print("{\\"status\\":\\"completed\\"}"); raise SystemExit(2)',
    ],
)
def test_child_overflow_deadline_and_exit_disagreement_fail_closed(monkeypatch, code):
    observed = child(monkeypatch, code)
    started = time.monotonic()
    with pytest.raises(gate.GateError):
        gate.run_cli(["analysis", "--", ID], deadline=started + 2.2, limit=2.2)
    assert observed[1].poll() is not None
    assert time.monotonic() - started < 2.5


def test_child_cancellation_reaped(monkeypatch):
    observed = child(monkeypatch, "raise SystemExit(130)")
    with pytest.raises(KeyboardInterrupt):
        gate.run_cli(["submission", ITEM["sha256"]], deadline=time.monotonic() + 3, limit=3)
    assert observed[1].poll() == 130


def test_evidence_is_exclusive_private_and_does_not_contain_error_text(tmp_path):
    value = error("unavailable", 503)
    response, kind, result, sanitized = gate.evaluate(value, ITEM, now=NOW)
    path = tmp_path / "evidence.json"
    gate.write_evidence(
        path, {"response": response, "kind": kind, "decision": result, "error": sanitized}
    )
    assert path.stat().st_mode & 0o777 == 0o600
    assert "inert untrusted message" not in path.read_text()
    with pytest.raises(FileExistsError):
        gate.write_evidence(path, {})


def test_evaluate_main_never_calls_cli_or_uses_a_token(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("VTAI_TOKEN", "private-synthetic-token")
    monkeypatch.setattr(
        gate, "run_cli", lambda *a, **kw: pytest.fail("offline evaluate called CLI")
    )
    path, evidence = tmp_path / "input.json", tmp_path / "evidence.json"
    path.write_text(json.dumps(report()))
    assert (
        gate.main(
            [
                "evaluate",
                "--fixture-version",
                "1.0.0",
                "--input",
                str(path),
                "--evidence",
                str(evidence),
            ]
        )
        == 0
    )
    result = json.loads(evidence.read_text())
    assert result["mode"] == "synthetic" and result["scope"] == "public-fixture-only"
    assert "private-synthetic-token" not in capsys.readouterr().out + evidence.read_text()


def test_missing_live_credential_blocks_before_any_cli(monkeypatch, tmp_path):
    monkeypatch.delenv("VTAI_TOKEN", raising=False)
    monkeypatch.setattr(gate, "provenance", lambda mode: {})
    monkeypatch.setattr(gate, "run_cli", lambda *a, **kw: pytest.fail("missing token called CLI"))
    evidence = tmp_path / "evidence.json"
    code = gate.main(
        [
            "live",
            "--fixture-version",
            "1.0.0",
            "--state-dir",
            str(tmp_path / "state"),
            "--evidence",
            str(evidence),
        ]
    )
    assert code == 2
    assert json.loads(evidence.read_text())["decision"]["reason"] == "configuration_error"


def test_main_cancellation_keeps_minimal_recovery(monkeypatch, tmp_path):
    monkeypatch.setenv("VTAI_TOKEN", "inert-token")
    monkeypatch.setenv("VTAI_BASE_URL", gate.SERVICE)
    monkeypatch.delenv("VTAI_TOKEN_FILE", raising=False)
    monkeypatch.setattr(gate, "provenance", lambda mode: {})
    monkeypatch.setattr(gate, "live", lambda *a, **kw: (_ for _ in ()).throw(KeyboardInterrupt()))
    evidence = tmp_path / "evidence.json"
    assert (
        gate.main(
            [
                "live",
                "--fixture-version",
                "1.0.0",
                "--state-dir",
                str(tmp_path / "state"),
                "--evidence",
                str(evidence),
            ]
        )
        == 130
    )
    result = json.loads(evidence.read_text())
    assert result["evidence"]["response"] == gate.unknown_submission(ITEM["sha256"], 488)
    assert "inert-token" not in evidence.read_text()
    assert signal.getsignal(signal.SIGTERM) is not None


@pytest.mark.parametrize(
    "raw",
    [
        {"status": []},
        {"status": "error", "error": None},
        {"status": "error", "error": {"code": []}},
    ],
)
def test_malformed_discriminators_are_controlled(raw):
    with pytest.raises(gate.GateError):
        outcome(raw)


@pytest.mark.parametrize(
    "case,state,code,version",
    [
        ("allow", "allow", 0, "1.0.0"),
        ("allow-partial", "allow", 0, "1.0.0"),
        ("allow-v2", "allow", 0, "1.0.1"),
        ("review", "review", 10, "1.0.0"),
        ("block", "block", 11, "1.0.0"),
        ("pending", "pending", 12, "1.0.0"),
        ("unknown", "unknown", 13, "1.0.0"),
        ("error", "error", 2, "1.0.0"),
    ],
)
def test_workflow_cases_run_real_evaluate_entrypoint(tmp_path, case, state, code, version):
    evidence = tmp_path / "evidence.json"
    args = [
        "evaluate",
        "--fixture-version",
        version,
        "--input",
        str(gate.ROOT / f"tests/fixtures/ci-policy/{case}.json"),
        "--evidence",
        str(evidence),
    ]
    assert gate.main(args) == code
    saved = json.loads(evidence.read_text())
    assert saved["mode"] == "synthetic"
    assert saved["decision"]["state"] == state
    assert saved["artifact"]["sha256"] == gate.FIXTURES[version][1]
    if case == "allow-partial":
        assert saved["decision"]["partial_reasons"] == ["failure", "timeout"]


def test_short_remaining_budget_keeps_receipt_pending_without_polling(monkeypatch):
    sequence = Sequence(monkeypatch, [receipt()])
    value = gate.live(
        ITEM,
        state_dir=Path("/private/state"),
        seconds=180,
        token="inert",
        deadline=time.monotonic() + 4,
    )
    assert value["status"] == "submitted" and len(sequence.calls) == 1


def test_child_ignoring_sigint_is_killed_and_reaped(monkeypatch):
    observed = child(
        monkeypatch,
        "import signal,time; signal.signal(signal.SIGINT,signal.SIG_IGN); time.sleep(20)",
    )
    started = time.monotonic()
    with pytest.raises(gate.GateError):
        gate.run_cli(["analysis", "--", ID], deadline=started + 2.2, limit=2.2)
    assert observed[1].poll() == -signal.SIGKILL
    assert time.monotonic() - started < 2.5


def test_malformed_recovery_discriminator_cannot_escape_as_type_error():
    raw = error("submission_unknown", 503)
    raw["submission"] = {"status": []}
    with pytest.raises(gate.GateError):
        outcome(raw)
