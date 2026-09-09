import base64
import copy
import importlib.util
import json
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import unquote

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("registry", ROOT / "scripts/registry.py")
registry = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(registry)
CORPORATE, PERSONAL = registry.IDENTITIES
SHA = "a" * 40
MARKER = "SYNTHETIC_SECRET_MUST_NOT_ESCAPE"


def manifest(repository):
    result = json.loads((ROOT / "server.json").read_text())
    selected = registry.IDENTITIES[repository]
    result.update(name=selected["name"], version=selected["version"])
    result.pop("repository", None)
    if repository == PERSONAL:
        result["repository"] = {
            "url": f"https://github.com/{PERSONAL}",
            "source": "github",
            "id": "1359828317",
        }
    return result


def entry(repository, status):
    if status == "absent":
        return None
    official = {"status": status}
    if status != "active":
        official["statusMessage"] = "Previous public lifecycle message"
    return {"server": manifest(repository), "_meta": {registry.OFFICIAL: official}}


def token(repository, **changes):
    now = int(time.time())
    claims = {
        "iss": "mcp-registry",
        "auth_method": "github-oidc",
        "auth_method_sub": f"repo:{repository}:ref:refs/heads/main",
        "permissions": [
            {
                "action": "publish",
                "resource": registry.IDENTITIES[repository]["name"].split("/")[0] + "/*",
            }
        ],
        "iat": now,
        "nbf": now,
        "exp": now + 1800,
        **changes,
    }

    def encode(value):
        return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")

    return {
        "token": encode({"alg": "EdDSA"}) + "." + encode(claims) + ".synthetic",
        "method": "github-oidc",
        "registry": registry.REGISTRY,
    }


@pytest.fixture
def harness(tmp_path, monkeypatch):
    cwd, home, temporary = (tmp_path / name for name in ("checkout", "home", "runner"))
    for path in (cwd, home, temporary):
        path.mkdir()
    monkeypatch.chdir(cwd)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    env = {
        "HOME": str(home),
        "RUNNER_TEMP": str(temporary),
        "PATH": "/usr/bin",
        "GITHUB_REPOSITORY": CORPORATE,
        "GITHUB_REPOSITORY_ID": "1361592455",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_WORKFLOW_REF": f"{CORPORATE}/.github/workflows/mcp-registry.yml@refs/heads/main",
        "GITHUB_SHA": SHA,
        "REVIEWED_SHA": SHA,
        "REGISTRY_OPERATION": "verify-identity",
        "GH_TOKEN": MARKER,
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN": MARKER,
        "ACTIONS_ID_TOKEN_REQUEST_URL": "https://synthetic.invalid/oidc",
        "GH_DEBUG": "api",
        "GH_FORCE_TTY": "1",
        "HTTPS_PROXY": "https://synthetic.invalid",
    }
    monkeypatch.setattr(registry.os, "environ", env)
    state = SimpleNamespace(
        env=env,
        cwd=cwd,
        home=home,
        temporary=temporary,
        calls=[],
        reads=[],
        entries={CORPORATE: None, PERSONAL: entry(PERSONAL, "active")},
        gh_override={},
        claims={},
        saved_changes={},
        credential_mode=0o600,
        fail=None,
        apply=True,
        after_mutation=None,
    )

    def select(repository, operation="verify-identity"):
        env.update(
            GITHUB_REPOSITORY=repository,
            GITHUB_REPOSITORY_ID=str(registry.IDENTITIES[repository]["id"]),
            GITHUB_WORKFLOW_REF=f"{repository}/.github/workflows/mcp-registry.yml@refs/heads/main",
            REGISTRY_OPERATION=operation,
        )
        (cwd / "server.json").write_text(json.dumps(manifest(repository)))

    def read(path):
        state.reads.append(path)
        assert path.endswith("?include_deleted=true")
        repository = next(r for r, s in registry.IDENTITIES.items() if s["name"] in unquote(path))
        current = copy.deepcopy(state.entries[repository])
        if path.endswith("/versions?include_deleted=true"):
            return {
                "servers": [current] if current else [],
                "metadata": {"count": int(current is not None)},
            }
        return current

    def run(argv, *, env, capture_output, timeout, check, stdin):
        state.calls.append((argv, env, timeout))
        assert capture_output and check is False and stdin == subprocess.DEVNULL
        assert MARKER not in json.dumps(argv)
        assert not {"GH_DEBUG", "GH_FORCE_TTY", "HTTPS_PROXY"} & env.keys()
        repository = state.env["GITHUB_REPOSITORY"]
        selected = registry.IDENTITIES[repository]
        if argv[0] == "gh":
            assert argv[1:7] == ["api", "--hostname", "github.com", "--method", "GET", argv[6]]
            prefix = f"repos/{repository}"
            base_repo = {"id": selected["id"], "full_name": repository}
            responses = {
                prefix: {**base_repo, "private": repository == CORPORATE},
                prefix + "/git/ref/heads/main": {"object": {"sha": SHA}},
                prefix
                + f"/actions/workflows/ci.yml/runs?head_sha={SHA}"
                + "&event=push&branch=main&per_page=100": {
                    "workflow_runs": [
                        {
                            "head_sha": SHA,
                            "head_branch": "main",
                            "event": "push",
                            "status": "completed",
                            "conclusion": "success",
                            "path": ".github/workflows/ci.yml",
                            "repository": base_repo,
                            "head_repository": base_repo,
                        }
                    ]
                },
            }
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps(state.gh_override.get(argv[6], responses[argv[6]])).encode(),
                stderr=b"",
            )
        assert "GH_TOKEN" not in env
        operation = argv[1]
        credential = home / ".config/mcp-publisher/token.json"
        if operation == "login":
            assert len([c for c in state.calls if c[0][0] == "gh"]) == 3
            credential.parent.mkdir(parents=True, exist_ok=True)
            credential.write_text(
                json.dumps({**token(repository, **state.claims), **state.saved_changes})
            )
            credential.chmod(state.credential_mode)
        if operation in ("publish", "status"):
            intent = json.loads((temporary / "registry-mutation-intent.json").read_text())
            assert intent["sha"] == SHA and intent["operation"] == state.env["REGISTRY_OPERATION"]
            assert "--all-versions" not in argv
            if state.apply:
                if operation == "publish":
                    state.entries[repository] = entry(repository, "active")
                else:
                    assert argv[2:4] in (["--status", "active"], ["--status", "deleted"])
                    new_status = argv[3]
                    state.entries[repository] = entry(repository, new_status)
                    if new_status == "deleted":
                        assert argv[4:6] == ["--message", registry.RETIRE_MESSAGES[repository]]
                        state.entries[repository]["_meta"][registry.OFFICIAL]["statusMessage"] = (
                            registry.RETIRE_MESSAGES[repository]
                        )
                    else:
                        assert "--message" not in argv
                    assert argv[-2:] == [selected["name"], selected["version"]]
            if state.after_mutation:
                state.after_mutation()
        if operation == state.fail:
            raise subprocess.TimeoutExpired(
                argv, timeout, output=MARKER.encode(), stderr=MARKER.encode()
            )
        return SimpleNamespace(returncode=0, stdout=MARKER.encode(), stderr=MARKER.encode())

    select(CORPORATE)
    monkeypatch.setattr(registry, "registry_get", read)
    monkeypatch.setattr(registry.subprocess, "run", run)
    state.select = select
    state.result = lambda: json.loads((temporary / "registry-result.json").read_text())
    state.mutations = lambda: [c[0] for c in state.calls if c[0][1] in {"publish", "status"}]
    return state


def test_verify_identity_authenticates_but_never_changes_entries(harness, capsys):
    assert registry.main([]) == 0
    result = harness.result()
    assert result["status"] == "verified" and result["identity_verified"]
    assert result["before"] == result["after"] and len(harness.reads) == 8
    assert not result["mutation_attempted"] and not harness.mutations()
    assert result["credential_cleanup"] == "removed"
    assert not registry.credential_paths()[0].exists()
    assert MARKER not in capsys.readouterr().out
    assert MARKER not in json.dumps(result)


def test_validation_keeps_official_publisher_and_requires_no_identity_token(harness):
    assert registry.main(["validate"]) == 0
    assert [c[0][1:] for c in harness.calls] == [["validate", "server.json"]]
    assert not harness.reads and harness.result()["status"] == "validated"


@pytest.mark.parametrize(
    "key,value",
    [
        ("GITHUB_REPOSITORY", "untrusted/repo"),
        ("GITHUB_REPOSITORY_ID", "1"),
        ("REVIEWED_SHA", "a" * 39),
        ("GITHUB_REF", "refs/heads/other"),
        ("GITHUB_EVENT_NAME", "pull_request"),
        ("GITHUB_WORKFLOW_REF", "wrong"),
        ("REGISTRY_OPERATION", "delete-everything"),
    ],
)
def test_context_rejected_before_any_authentication(harness, key, value):
    harness.env[key] = value
    assert registry.main([]) == 1
    assert not harness.calls and not harness.reads


@pytest.mark.parametrize("change", ["id", "main", "ci", "private"])
def test_github_preflight_precedes_oidc(harness, change):
    if change == "private":
        harness.select(PERSONAL)
    prefix = f"repos/{harness.env['GITHUB_REPOSITORY']}"
    if change in ("id", "private"):
        harness.gh_override[prefix] = {
            "id": 1 if change == "id" else 1359828317,
            "full_name": harness.env["GITHUB_REPOSITORY"],
            "private": True,
        }
    elif change == "main":
        harness.gh_override[prefix + "/git/ref/heads/main"] = {"object": {"sha": "b" * 40}}
    else:
        harness.gh_override[
            prefix
            + f"/actions/workflows/ci.yml/runs?head_sha={SHA}&event=push&branch=main&per_page=100"
        ] = {"workflow_runs": []}
    assert registry.main([]) == 1
    assert all(c[0][0] == "gh" for c in harness.calls)


@pytest.mark.parametrize(
    "field,value",
    [
        ("repository", {"url": "https://private.invalid"}),
        ("packages", []),
        ("version", "0.8.3"),
        ("remotes", [{"url": "https://other.invalid"}]),
    ],
)
def test_contract_pins_entire_remote_manifest(harness, field, value):
    data = manifest(CORPORATE)
    data[field] = value
    (harness.cwd / "server.json").write_text(json.dumps(data))
    assert registry.main([]) == 1 and not harness.calls


@pytest.mark.parametrize(
    "repository,operation,own,counterpart,outcome",
    [
        (CORPORATE, "publish", "absent", "deleted", "completed"),
        (CORPORATE, "publish", "active", "deleted", "noop"),
        (PERSONAL, "retire", "active", "absent", "completed"),
        (PERSONAL, "retire", "deprecated", "active", "completed"),
        (PERSONAL, "retire", "deleted", "active", "noop"),
        (PERSONAL, "restore", "deleted", "absent", "completed"),
        (PERSONAL, "restore", "deprecated", "deleted", "completed"),
        (CORPORATE, "restore", "deleted", "deleted", "completed"),
        (CORPORATE, "restore", "active", "deleted", "noop"),
    ],
)
def test_success_and_same_status_idempotence(
    harness, repository, operation, own, counterpart, outcome
):
    harness.select(repository, operation)
    other = next(r for r in registry.IDENTITIES if r != repository)
    harness.entries = {repository: entry(repository, own), other: entry(other, counterpart)}
    assert registry.main([]) == 0
    result = harness.result()
    assert result["status"] == outcome and len(harness.mutations()) == (outcome == "completed")
    assert result["after"][other] == result["before"][other]
    assert result["credential_cleanup"] == "removed"


@pytest.mark.parametrize(
    "operation,own,counterpart,error",
    [
        ("publish", "absent", "active", "counterpart_reserves_remote_url"),
        ("publish", "absent", "deprecated", "counterpart_reserves_remote_url"),
        ("restore", "deleted", "active", "counterpart_reserves_remote_url"),
        ("restore", "deleted", "deprecated", "counterpart_reserves_remote_url"),
        ("publish", "deleted", "deleted", "existing_version_requires_restore"),
        ("publish", "deprecated", "deleted", "existing_version_requires_restore"),
        ("retire", "absent", "deleted", "own_version_missing"),
        ("restore", "absent", "deleted", "own_version_missing"),
    ],
)
def test_invalid_transitions_do_not_mutate(harness, operation, own, counterpart, error):
    harness.select(CORPORATE, operation)
    harness.entries = {CORPORATE: entry(CORPORATE, own), PERSONAL: entry(PERSONAL, counterpart)}
    assert registry.main([]) == 1
    assert harness.result()["error"] == error and not harness.mutations()
    assert not registry.credential_paths()[0].exists()


@pytest.mark.parametrize(
    "problem", ["extra_version", "wrong_manifest", "count", "cursor", "disagreement"]
)
def test_inventory_drift_fails_closed(harness, monkeypatch, problem):
    original = registry.registry_get

    def changed(path):
        value = original(path)
        if "king-tero" not in path:
            return value
        if "servers" in (value or {}):
            if problem == "extra_version":
                value["servers"] *= 2
                value["metadata"]["count"] = 2
            if problem == "wrong_manifest":
                value["servers"][0]["server"]["version"] = "0.8.1"
            if problem == "count":
                value["metadata"]["count"] = 0
            if problem == "cursor":
                value["metadata"]["nextCursor"] = "unfinished"
        elif problem == "disagreement":
            return None
        return value

    monkeypatch.setattr(registry, "registry_get", changed)
    assert registry.main([]) == 1 and not harness.mutations()
    assert harness.result()["credential_cleanup"] == "removed"


@pytest.mark.parametrize(
    "claims",
    [
        {"auth_method_sub": "repo:other/repo:ref:refs/heads/main"},
        {"auth_method": "github"},
        {"permissions": [{"action": "edit", "resource": "*"}]},
        {"iat": True},
        {"exp": 1},
        {"nbf": 9999999999},
    ],
)
def test_oidc_claims_must_match_this_job(harness, claims):
    harness.claims = claims
    assert registry.main([]) == 1
    assert harness.result()["error"] == "credential_rejected" and not harness.reads
    assert not registry.credential_paths()[0].exists()


@pytest.mark.parametrize("problem", ["mode", "registry", "method", "malformed"])
def test_new_credential_rejected_and_cleaned(harness, problem):
    if problem == "mode":
        harness.credential_mode = 0o644
    else:
        harness.saved_changes = (
            {"registry": "https://other.invalid"}
            if problem == "registry"
            else {"method": "github"}
            if problem == "method"
            else {"token": MARKER}
        )
    assert registry.main([]) == 1 and not registry.credential_paths()[0].exists()
    assert not harness.mutations()


@pytest.mark.parametrize("index", [0, 1, 2, 4])
def test_existing_credentials_never_read_overwritten_or_logged_out(harness, index):
    path = registry.credential_paths()[index]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(MARKER)
    assert registry.main([]) == 1
    assert path.read_text() == MARKER
    assert all(c[0][0] == "gh" for c in harness.calls)


@pytest.mark.parametrize("failure", ["login", "logout", "publish"])
def test_timeout_cleanup_privacy_and_no_ambiguous_retry(harness, capsys, failure):
    harness.select(CORPORATE, "publish")
    harness.entries[PERSONAL] = entry(PERSONAL, "deleted")
    harness.fail = failure
    code = registry.main([])
    assert code == (0 if failure == "logout" else 1)
    result = harness.result()
    assert not registry.credential_paths()[0].exists()
    assert result["credential_cleanup"] == "removed"
    assert len(harness.mutations()) == (failure != "login")
    if failure == "publish":
        assert result["reconciliation_required"] and result["mutation_attempted"]
        assert "after" not in result
        before = len(harness.calls)
        assert registry.main([]) == 1 and len(harness.calls) == before
    assert MARKER not in capsys.readouterr().out and MARKER not in json.dumps(result)


def test_post_read_stale_state_requires_reconciliation_not_retry(harness):
    harness.select(CORPORATE, "publish")
    harness.entries[PERSONAL] = entry(PERSONAL, "deleted")
    harness.apply = False
    assert registry.main([]) == 1
    assert harness.result()["error"] == "postcondition_failed"
    assert harness.result()["reconciliation_required"] and len(harness.mutations()) == 1


def test_counterpart_changed_after_mutation_is_preserved_error(harness):
    harness.select(CORPORATE, "publish")
    harness.entries[PERSONAL] = entry(PERSONAL, "deleted")
    harness.after_mutation = lambda: harness.entries.update({PERSONAL: entry(PERSONAL, "active")})
    assert registry.main([]) == 1
    assert harness.result()["error"] == "counterpart_changed" and len(harness.mutations()) == 1


def test_workflow_keeps_publisher_pin_scoped_oidc_and_sanitized_artifact():
    text = (ROOT / ".github/workflows/mcp-registry.yml").read_text()
    assert text.count("a06c9096dcb9727c13555b6be26c7effa707b01f06a4c561ba7a3635443cf2cc") == 2
    assert "options: [verify-identity, publish, retire, restore]" in text
    assert (
        text.count("id-token: write") == 1 and "id-token: write" not in text.split("  registry:")[0]
    )
    assert '"$RUNNER_TEMP/mcp-publisher"' not in text
    assert "registry-mutation-intent.json" in text and "token.json" not in text
