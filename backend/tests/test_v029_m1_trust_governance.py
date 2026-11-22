"""Comprehensive Milestone M1 regression suite for trust, git, plugins, governance, & diff."""

from __future__ import annotations

import importlib.metadata
import json
import subprocess
import sysconfig
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.adapters.base import (
    DisplayExtractionResult,
    FrontendHttpCall,
    ManipulatorExtractionResult,
    RawCandidateFinding,
    RouteDescriptor,
    TruthExtractionResult,
)
from app.adapters.plugin_registry import (
    ENTRY_POINT_GROUP,
    WythePluginSpec,
    discover_plugins,
    run_manipulator_plugins,
    run_post_scan_plugins,
)
from app.cli import main as cli_main
from app.core.clock import utc_now
from app.core.safe_git import SafeGitError, run_safe_git, validate_git_dir_containment
from app.models import AuditRuling, RatchetBaseline
from app.schemas.atlas import (
    AtlasNode,
    AuditRulingCreate,
    PortableGovernanceBundle,
    PortableRatchetItem,
    PortableReferenceExemplar,
    PortableRulingItem,
    StorePurposeDeclaration,
    TargetProjectCreate,
)
from app.services import scanner_service
from app.services.diff_and_sarif_service import run_target_diff
from app.services.governance_service import (
    get_target_by_slug,
    list_ratchet_baselines,
    list_rulings,
    record_audit_ruling,
    register_target,
)
from app.services.portable_config_service import (
    load_target_governance_allowlist,
    load_target_governance_overrides,
    sync_portable_bundle_from_disk,
)
from app.services.ruling_metadata import apply_rulings_and_store_purpose_checks
from app.services.scanner_service import _solve_cross_tier_lineage, run_target_scan


def _git_env() -> dict[str, str]:
    return {
        "GIT_AUTHOR_NAME": "Test",
        "GIT_AUTHOR_EMAIL": "test@example.com",
        "GIT_COMMITTER_NAME": "Test",
        "GIT_COMMITTER_EMAIL": "test@example.com",
        "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
    }


def _init_git(repo: Path) -> str:
    env = _git_env()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True, env=env, capture_output=True)
    subprocess.run(["git", "add", "."], cwd=repo, check=True, env=env, capture_output=True)
    subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", "commit", "-m", "init"],
        cwd=repo,
        check=True,
        env=env,
        capture_output=True,
    )
    return subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=repo, env=env, text=True
    ).strip()


# ---------------------------------------------------------------------------
# P0-1: Safe Git containment, worktree back-pointers, config directives, -uall
# ---------------------------------------------------------------------------


def test_p0_1_real_release_029_worktree_passes_safe_git() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    proc = run_safe_git(repo_root, "rev-parse", "HEAD", text=True)
    assert len(str(proc.stdout).strip()) == 40


@pytest.mark.parametrize(
    "bad_cfg",
    [
        '[include]\n\tpath = /etc/passwd\n',
        '[includeIf "gitdir:/"]\n\tpath = /tmp/evil\n',
        '[filter "evil"]\n\tclean = touch /tmp/pwn\n',
        '[diff "evil"]\n\texternal = touch /tmp/pwn\n',
        '[diff "evil"]\n\ttextconv = touch /tmp/pwn\n',
        '[protocol "http"]\n\tallow = always\n',
        '[extensions]\n\tpartialClone = origin\n',
        '[remote "origin"]\n\tpromisor = true\n',
        '[remote "origin"]\n\tvcs = evil\n',
        '[core]\n\twork\\\ntree = /etc\n',
        '[core] gitproxy = touch /tmp/pwn\n',
        '[core]\n\tworktree = /etc\n',
    ],
)
def test_p0_1_rejects_malicious_git_config_directives(tmp_path: Path, bad_cfg: str) -> None:
    repo = tmp_path / "bad_git_cfg"
    repo.mkdir()
    (repo / "README.md").write_text("hi\n", encoding="utf-8")
    _init_git(repo)
    cfg = repo / ".git" / "config"
    cfg.write_text(cfg.read_text(encoding="utf-8") + "\n" + bad_cfg, encoding="utf-8")
    with pytest.raises(SafeGitError):
        validate_git_dir_containment(repo)


def test_p0_1_rejects_bad_worktree_backpointer_and_symlink_attributes(tmp_path: Path) -> None:
    repo = tmp_path / "wt_main"
    repo.mkdir()
    (repo / "a.txt").write_text("hello\n", encoding="utf-8")
    _init_git(repo)

    wt_dir = tmp_path / "wt_checkout"
    wt_dir.mkdir()
    wt_git_meta = repo / ".git" / "worktrees" / "wt_checkout"
    wt_git_meta.mkdir(parents=True)
    (wt_git_meta / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (wt_git_meta / "commondir").write_text("../..\n", encoding="utf-8")
    (wt_git_meta / "gitdir").write_text(str(tmp_path / "wrong" / ".git") + "\n", encoding="utf-8")
    (wt_dir / ".git").write_text(f"gitdir: {wt_git_meta}\n", encoding="utf-8")

    with pytest.raises(SafeGitError):
        validate_git_dir_containment(wt_dir)

    # Fix back-pointer -> passes; then poison info/attributes symlink -> fails
    (wt_git_meta / "gitdir").write_text(str(wt_dir / ".git") + "\n", encoding="utf-8")
    assert validate_git_dir_containment(wt_dir) == wt_git_meta.resolve()
    (wt_git_meta / "info").mkdir()
    (wt_git_meta / "info" / "attributes").symlink_to("/etc/hosts")
    with pytest.raises(SafeGitError):
        validate_git_dir_containment(wt_dir)


def test_p0_1_dirty_path_count_enumerates_untracked_dir_files(
    db_session: Session, tmp_path: Path
) -> None:
    repo = tmp_path / "uall_repo"
    (repo / "backend" / "app").mkdir(parents=True)
    (repo / "backend" / "app" / "main.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8"
    )
    _init_git(repo)
    (repo / "new_dir").mkdir()
    (repo / "new_dir" / "one.py").write_text("x = 1\n", encoding="utf-8")
    (repo / "new_dir" / "two.py").write_text("y = 2\n", encoding="utf-8")

    register_target(
        db_session, TargetProjectCreate(slug="uall-repo", name="Uall", repo_path=str(repo))
    )
    target = get_target_by_slug(db_session, "uall-repo")
    assert target is not None
    rep = run_target_scan(db_session, target, strict_gate=True, persist_snapshot=False)
    assert rep.dirty_path_count == 2


def test_p0_1_trusted_ref_propagates_safe_git_error(db_session: Session, tmp_path: Path) -> None:
    repo = tmp_path / "poison_trusted_ref"
    repo.mkdir()
    (repo / "README.md").write_text("hi\n", encoding="utf-8")
    _init_git(repo)
    register_target(
        db_session, TargetProjectCreate(slug="poison-ref", name="Poison", repo_path=str(repo))
    )
    target = get_target_by_slug(db_session, "poison-ref")
    assert target is not None
    cfg = repo / ".git" / "config"
    cfg.write_text(cfg.read_text() + '\n[filter "bad"]\n\tclean = echo pwn\n', encoding="utf-8")
    with pytest.raises(SafeGitError):
        sync_portable_bundle_from_disk(db_session, target, trusted_git_ref="HEAD")


# ---------------------------------------------------------------------------
# P0-2 & P1-12: Plugin trust, sys.path shadowing, & coverage_complete fail-closed
# ---------------------------------------------------------------------------


def test_p0_2_rejects_missing_dist_and_repo_root_before_trusted(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # 1. ep.dist is None must be blocked when allow_local_plugins=False
    ep_no_dist = importlib.metadata.EntryPoint(
        name="no_dist_plug",
        value="wythe_plugin_apple_ipc.plugin:APPLE_IPC_PLUGIN",
        group=ENTRY_POINT_GROUP,
    )
    monkeypatch.setattr(
        importlib.metadata,
        "entry_points",
        lambda **kw: (ep_no_dist,) if kw.get("group") == ENTRY_POINT_GROUP else (),
    )
    notes: list[str] = []
    specs = discover_plugins(include_builtins=False, allow_local_plugins=False, notes_out=notes)
    assert specs == []
    assert any("missing distribution metadata" in n for n in notes)

    # 2. dist inside Wythe repo's own plugins/ dir must still be blocked when scanning Wythe
    wythe_root = Path(__file__).resolve().parents[2]

    class _RepoDist:
        version = "0.1.0"
        _path = wythe_root / "plugins" / "evil-0.1.0.dist-info"

        def locate_file(self, p: str) -> Path:
            return self._path.parent / p

    ep_in_repo = importlib.metadata.EntryPoint(
        name="evil_in_repo",
        value="wythe_plugin_apple_ipc.plugin:APPLE_IPC_PLUGIN",
        group=ENTRY_POINT_GROUP,
    )._for(_RepoDist())
    monkeypatch.setattr(
        importlib.metadata,
        "entry_points",
        lambda **kw: (ep_in_repo,) if kw.get("group") == ENTRY_POINT_GROUP else (),
    )
    notes2: list[str] = []
    specs2 = discover_plugins(
        repo_root=wythe_root, include_builtins=False, allow_local_plugins=False, notes_out=notes2
    )
    assert specs2 == []
    assert any("resides inside scanned repository" in n for n in notes2)

    # 3. sys.path shadowing attack (trusted .dist-info + untrusted module on sys.path)
    evil_repo = tmp_path / "shadow_repo"
    evil_repo.mkdir()
    sentinel = tmp_path / "SHADOW_EXECUTED"
    (evil_repo / "shadow_evil_mod.py").write_text(
        f"from pathlib import Path\nPath({str(sentinel)!r}).write_text('pwn')\n", encoding="utf-8"
    )
    purelib = Path(sysconfig.get_path("purelib"))

    class _TrustedDist:
        version = "0.1.0"
        _path = purelib / "shadow_evil_mod-0.1.0.dist-info"

        def locate_file(self, p: str) -> Path:
            return self._path.parent / p

    ep_shadow = importlib.metadata.EntryPoint(
        name="shadow_evil",
        value="shadow_evil_mod:PLUG",
        group=ENTRY_POINT_GROUP,
    )._for(_TrustedDist())
    monkeypatch.syspath_prepend(str(evil_repo))
    monkeypatch.setattr(
        importlib.metadata,
        "entry_points",
        lambda **kw: (ep_shadow,) if kw.get("group") == ENTRY_POINT_GROUP else (),
    )
    notes3: list[str] = []
    specs3 = discover_plugins(
        repo_root=evil_repo, include_builtins=False, allow_local_plugins=False, notes_out=notes3
    )
    assert specs3 == []
    assert not sentinel.exists()
    assert any("failed to load and was isolated" in n for n in notes3)


def test_p1_12_entry_point_plugin_failures_force_incomplete_preserve_z1_digest(
    db_session: Session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manip = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
    ep_spec = WythePluginSpec(
        name="broken-ep-manip",
        kind="manipulator_augmenter",
        origin="entry_point",
        manipulator_hook=lambda *_a: (_ for _ in ()).throw(RuntimeError("boom manip")),
    )
    run_manipulator_plugins(tmp_path, "backend", manip, plugins=[ep_spec], strict_plugins=False)
    assert manip.coverage_complete is False

    # Post-scan stratum_inspector failure under entry_point must force INCOMPLETE & keep Z1 digest
    repo = tmp_path / "stratum_fail_repo"
    (repo / "backend" / "app").mkdir(parents=True)
    (repo / "frontend" / "src" / "app").mkdir(parents=True)
    (repo / "backend" / "app" / "main.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8"
    )
    (repo / "frontend" / "src" / "app" / "page.tsx").write_text(
        "export default function P() { return <main>ok</main>; }\n", encoding="utf-8"
    )
    register_target(
        db_session, TargetProjectCreate(slug="stratum-fail", name="Stratum Fail", repo_path=str(repo))
    )
    target = get_target_by_slug(db_session, "stratum-fail")
    assert target is not None

    baseline_rep = run_target_scan(db_session, target, strict_gate=True, persist_snapshot=False)
    assert baseline_rep.gate.verdict == "PASS"

    broken_stratum = WythePluginSpec(
        name="broken-stratum-post",
        kind="stratum_inspector",
        origin="entry_point",
        supported_zooms=(2,),
        post_scan_hook=lambda *_a: (_ for _ in ()).throw(RuntimeError("boom stratum")),
        stratum_expand_hook=lambda *_a: None,
    )
    monkeypatch.setattr(
        scanner_service,
        "discover_plugins",
        lambda **_kw: [broken_stratum],
    )
    rep_fail = run_target_scan(db_session, target, strict_gate=True, persist_snapshot=False)
    assert rep_fail.coverage_complete is False
    assert rep_fail.gate.coverage_complete is False
    assert rep_fail.gate.verdict == "INCOMPLETE"
    assert rep_fail.content_digest == baseline_rep.content_digest

    # Direct unit check of run_post_scan_plugins with entry_point failure
    rep_copy = baseline_rep.model_copy(deep=True)
    run_post_scan_plugins(tmp_path, rep_copy, plugins=[broken_stratum], strict_plugins=False)
    assert rep_copy.coverage_complete is False


# ---------------------------------------------------------------------------
# P0-4 & P1-13: Strict ruling immunity, revocation/commit staleness, sync prune, action.yml
# ---------------------------------------------------------------------------


def test_p0_4_strict_gate_ignores_accepted_clean_and_persistent_config_waivers(
    db_session: Session, tmp_path: Path
) -> None:
    repo = tmp_path / "strict_ruling_repo"
    (repo / "backend" / "app" / "services").mkdir(parents=True)
    (repo / "frontend" / "src" / "app").mkdir(parents=True)
    (repo / "backend" / "schema.sql").write_text(
        "CREATE TABLE items (id INTEGER PRIMARY KEY);\n", encoding="utf-8"
    )
    (repo / "backend" / "app" / "services" / "cfg.py").write_text(
        "import redis\nredis_client = redis.Redis()\nSHADOW_WORKLOAD_CAP = 5\ndef run():\n    redis_client.set('feature_cfg:1', 'x')\n    return 1\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "main.py").write_text(
        "from fastapi import FastAPI\nfrom app.services.cfg import run\napp = FastAPI()\n_ = run\n",
        encoding="utf-8",
    )
    (repo / "frontend" / "src" / "app" / "page.tsx").write_text(
        "export default function P() { return <main>ok</main>; }\n", encoding="utf-8"
    )
    commit_sha = _init_git(repo)
    register_target(
        db_session, TargetProjectCreate(slug="strict-rulings", name="Strict", repo_path=str(repo))
    )
    target = get_target_by_slug(db_session, "strict-rulings")
    assert target is not None

    initial = run_target_scan(db_session, target, strict_gate=False)
    assert any(n.id == "t:redis:feature_cfg" for n in initial.nodes)
    svc_node = next(n for n in initial.nodes if "cfg.py" in n.source_file)
    record_audit_ruling(
        db_session,
        target.id,
        audited_commit=commit_sha,
        payload=AuditRulingCreate(
            node_id=svc_node.id,
            disposition="accepted_clean",
            summary="Waive service policy in code.",
            recorded_by="reviewer",
        ),
    )
    record_audit_ruling(
        db_session,
        target.id,
        audited_commit=commit_sha,
        payload=AuditRulingCreate(
            node_id="t:redis:feature_cfg",
            disposition="accepted_clean",
            summary="Persistent config.",
            store_purpose=StorePurposeDeclaration(
                intended_use="persistent_config",
                recovery_expectation="Daily backup",
            ),
            recorded_by="reviewer",
        ),
    )

    non_strict = run_target_scan(db_session, target, strict_gate=False)
    assert non_strict.gate.verdict == "PASS"

    strict = run_target_scan(db_session, target, strict_gate=True)
    assert strict.gate.verdict == "FAIL"
    assert any(f.rule_code == "MANIP-001" for f in strict.findings)
    redis_node = next(n for n in strict.nodes if n.id == "t:redis:feature_cfg")
    assert redis_node.status != "clean"


def test_p1_13_revoked_and_needs_review_block_inheritance_and_commit_staleness() -> None:
    node = AtlasNode(
        id="t:redis:catalog",
        tier="truth",
        subkind="cache_store",
        label="catalog",
        source_file="app/cache.py",
        line=10,
        status="duplicated_truth",
        summary="unbounded redis writes",
    )
    finding = RawCandidateFinding(
        rule_code="TRUTH-004",
        node_id="m:svc",
        target_node_id="t:redis:catalog",
        source_file="app/cache.py",
        line=10,
        title="Unbounded cache",
        detail="Second authority conflict for catalog.",
        remediation="Add TTL",
    )
    now = utc_now()
    today = now.date()

    # Older accepted_clean persistent_config overridden by newer needs_review / revoked
    from app.schemas.atlas import AuditRulingRead

    old_r = AuditRulingRead(
        id=1,
        target_id=1,
        node_id="t:redis:catalog",
        disposition="accepted_clean",
        summary="Old waiver",
        store_purpose=StorePurposeDeclaration(
            intended_use="persistent_config",
            recovery_expectation="Backup",
        ),
        audited_commit="aaaaaaa1111111",
        audited_at=today,
        effective_from=today,
        recorded_by="arch",
        created_at=now,
    )
    for disp in ("needs_review", "revoked", "rejected"):
        n_copy = node.model_copy(deep=True)
        newer_r = AuditRulingRead(
            id=2,
            target_id=1,
            node_id="t:redis:catalog",
            disposition=disp,
            summary=f"Status {disp}",
            audited_commit="aaaaaaa1111111",
            audited_at=today,
            effective_from=today,
            recorded_by="arch",
            created_at=now,
        )
        rem = apply_rulings_and_store_purpose_checks(
            [n_copy], [], [finding], [old_r, newer_r], strict_gate=False, current_commit="aaaaaaa1111111"
        )
        assert len(rem) == 1
        assert n_copy.store_purpose is None
        assert n_copy.status != "clean"

    # Commit staleness: concrete current_commit differs from audited_commit -> refuses waiver
    n_stale = node.model_copy(deep=True)
    rem_stale = apply_rulings_and_store_purpose_checks(
        [n_stale], [], [finding], [old_r], strict_gate=False, current_commit="bbbbbbb2222222"
    )
    assert len(rem_stale) == 1
    assert "(stale @ aaaaaaa11111)" in (n_stale.ruling_summary or "")
    assert n_stale.status != "clean"

    # Concrete matching hex prefix passes in non-strict mode
    n_match = node.model_copy(deep=True)
    rem_match = apply_rulings_and_store_purpose_checks(
        [n_match], [], [finding], [old_r], strict_gate=False, current_commit="aaaaaaa11111119999"
    )
    assert rem_match == []
    assert n_match.status == "clean"


def test_p0_4_trusted_ref_clears_stale_db_state_and_prunes_removed_items(
    db_session: Session, tmp_path: Path
) -> None:
    repo = tmp_path / "sync_prune_repo"
    (repo / ".wythe").mkdir(parents=True)
    (repo / "README.md").write_text("v1\n", encoding="utf-8")
    _init_git(repo)
    base_sha = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=repo, env=_git_env(), text=True
    ).strip()

    register_target(
        db_session, TargetProjectCreate(slug="sync-prune", name="Sync Prune", repo_path=str(repo))
    )
    target = get_target_by_slug(db_session, "sync-prune")
    assert target is not None

    # Sync bundle v1 with 1 baseline and 1 ruling
    bundle_v1 = PortableGovernanceBundle(
        target_slug="sync-prune",
        exported_at=utc_now(),
        ratchet_baselines=[
            PortableRatchetItem(
                rule_code="MANIP-001",
                max_allowed_count=3,
                recorded_commit=base_sha,
                recorded_by="ci",
            ),
            PortableRatchetItem(
                rule_code="DISP-004",
                max_allowed_count=1,
                recorded_commit=base_sha,
                recorded_by="ci",
            ),
        ],
        audit_rulings=[
            PortableRulingItem(
                node_id="m:a",
                disposition="accepted_clean",
                summary="Keep A",
                audited_commit=base_sha,
                recorded_by="ci",
            ),
            PortableRulingItem(
                node_id="m:b",
                disposition="accepted_clean",
                summary="Remove B later",
                audited_commit=base_sha,
                recorded_by="ci",
            ),
        ],
        fabricated_fallback_allowlist=["src/demo.tsx"],
    )
    sync_portable_bundle_from_disk(db_session, target, bundle=bundle_v1)
    assert len(list_ratchet_baselines(db_session, target.id)) == 2
    assert len(list_rulings(db_session, target.id)) == 2
    assert "src/demo.tsx" in load_target_governance_allowlist(db_session, target.id)

    # Bundle v2 removes DISP-004 baseline & m:b ruling -> must prune
    bundle_v2 = PortableGovernanceBundle(
        target_slug="sync-prune",
        exported_at=utc_now(),
        ratchet_baselines=[bundle_v1.ratchet_baselines[0]],
        audit_rulings=[bundle_v1.audit_rulings[0]],
    )
    sync_portable_bundle_from_disk(db_session, target, bundle=bundle_v2)
    assert [b.rule_code for b in list_ratchet_baselines(db_session, target.id)] == ["MANIP-001"]
    assert [r.node_id for r in list_rulings(db_session, target.id)] == ["m:a"]

    # Trusted git ref with NO governance.json clears all DB overrides/baselines/rulings for target
    receipt = sync_portable_bundle_from_disk(db_session, target, trusted_git_ref=base_sha)
    assert receipt.rules_synced == 0
    assert list_ratchet_baselines(db_session, target.id) == []
    assert list_rulings(db_session, target.id) == []
    assert load_target_governance_overrides(db_session, target.id) == ({}, [])
    assert load_target_governance_allowlist(db_session, target.id) == set()
    assert db_session.scalars(select(RatchetBaseline).where(RatchetBaseline.target_id == target.id)).all() == []
    assert db_session.scalars(select(AuditRuling).where(AuditRuling.target_id == target.id)).all() == []


def test_p0_4_action_yml_trusted_ref_events_and_fail_closed(tmp_path: Path) -> None:
    action_path = Path(__file__).resolve().parents[2] / "action.yml"
    doc = yaml.safe_load(action_path.read_text(encoding="utf-8"))
    step = doc["runs"]["steps"][1]
    script = step["run"]

    # Intercept `uvx` with a fake shim that records passed args
    shim_dir = tmp_path / "bin"
    shim_dir.mkdir()
    args_file = tmp_path / "captured_args.json"
    shim = shim_dir / "uvx"
    shim.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, sys\n"
        f"open({str(args_file)!r}, 'w').write(json.dumps(sys.argv[1:]))\n",
        encoding="utf-8",
    )
    shim.chmod(0o755)

    def _run_action(**extra_env: str) -> subprocess.CompletedProcess[str]:
        if args_file.exists():
            args_file.unlink()
        env = {
            "PATH": f"{shim_dir}:/usr/bin:/bin",
            "TA_TARGET": ".",
            "TA_PROFILE": "auto",
            "TA_MODE": "gate",
            "TA_BASE": "origin/main",
            "TA_STRICT": "false",
            "TA_SYNC": "true",
            "TA_SARIF": "",
            "TA_ACTION_PATH": str(action_path.parent),
            "TA_EVENT_NAME": "",
            "TA_GITHUB_BASE_REF": "",
            "TA_MERGE_GROUP_BASE_SHA": "",
            "TA_DEFAULT_BRANCH": "main",
            "TA_REF": "refs/heads/main",
            **extra_env,
        }
        return subprocess.run(
            ["/bin/bash", "-c", script],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    # 1. pull_request_target uses --trusted-config-ref origin/<base_ref>
    p1 = _run_action(TA_EVENT_NAME="pull_request_target", TA_GITHUB_BASE_REF="release")
    assert p1.returncode == 0, p1.stderr
    assert ["--trusted-config-ref", "origin/release"] == [
        a for a in json.loads(args_file.read_text()) if a in ("--trusted-config-ref", "origin/release")
    ]

    # 2. merge_group uses --trusted-config-ref <base_sha>
    p2 = _run_action(TA_EVENT_NAME="merge_group", TA_MERGE_GROUP_BASE_SHA="deadbeef1234")
    assert p2.returncode == 0, p2.stderr
    assert "--trusted-config-ref" in json.loads(args_file.read_text())
    assert "deadbeef1234" in json.loads(args_file.read_text())

    # 3. non-default push uses --trusted-config-ref origin/main
    p3 = _run_action(TA_EVENT_NAME="push", TA_REF="refs/heads/feature-x", TA_DEFAULT_BRANCH="main")
    assert p3.returncode == 0, p3.stderr
    assert "--trusted-config-ref" in json.loads(args_file.read_text())

    # 4. empty resolved base ref on pull_request fails closed with exit 2
    p4 = _run_action(TA_EVENT_NAME="pull_request", TA_BASE="", TA_GITHUB_BASE_REF="")
    assert p4.returncode == 2

    # 5. leading '-' in base ref fails closed with exit 2
    p5 = _run_action(TA_EVENT_NAME="pull_request", TA_BASE="--upload-pack=evil")
    assert p5.returncode == 2


# ---------------------------------------------------------------------------
# P1-3: Clean & pure-addition `wythe diff` and `base_target` symmetry
# ---------------------------------------------------------------------------


def test_p1_3_clean_and_pure_addition_diff_and_base_target_symmetry(
    db_session: Session, tmp_path: Path
) -> None:
    repo = tmp_path / "diff_p1_3"
    (repo / "backend" / "app" / "services").mkdir(parents=True)
    (repo / "frontend" / "src" / "app").mkdir(parents=True)
    (repo / "backend" / "schema.sql").write_text(
        "CREATE TABLE items (id INTEGER PRIMARY KEY);\n", encoding="utf-8"
    )
    (repo / "backend" / "app" / "services" / "legacy.py").write_text(
        "LEGACY_WORKLOAD_CAP = 10\n", encoding="utf-8"
    )
    (repo / "backend" / "app" / "main.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8"
    )
    (repo / "frontend" / "src" / "app" / "page.tsx").write_text(
        "export default function P() { return <main>ok</main>; }\n", encoding="utf-8"
    )
    _init_git(repo)

    register_target(
        db_session, TargetProjectCreate(slug="diff-p1-3", name="Diff P1-3", repo_path=str(repo))
    )
    target = get_target_by_slug(db_session, "diff-p1-3")
    assert target is not None

    # 1. Clean repo diff: pre-existing MANIP-001 must NOT fail `wythe diff`
    rep_clean = run_target_scan(db_session, target, strict_gate=True, persist_snapshot=False)
    diff_clean = run_target_diff(db_session, target, rep_clean, "HEAD")
    assert diff_clean.base_graph_status == "not_needed"
    assert diff_clean.new_findings == []
    assert diff_clean.diff_verdict == "PASS"

    # 2. Pure-addition diff (new clean page only): pre-existing MANIP-001 must NOT be flagged
    (repo / "frontend" / "src" / "app" / "about").mkdir(parents=True)
    (repo / "frontend" / "src" / "app" / "about" / "page.tsx").write_text(
        "export default function About() { return <main>about</main>; }\n", encoding="utf-8"
    )
    rep_add_clean = run_target_scan(db_session, target, strict_gate=True, persist_snapshot=False)
    diff_add_clean = run_target_diff(db_session, target, rep_add_clean, "HEAD")
    assert diff_add_clean.new_findings == []
    assert diff_add_clean.diff_verdict == "PASS"

    # 3. Pure-addition diff introducing new violation -> flags ONLY the new hunk violation
    (repo / "backend" / "app" / "services" / "bad_new.py").write_text(
        "NEW_WORKLOAD_CAP = 99\n", encoding="utf-8"
    )
    rep_add_bad = run_target_scan(db_session, target, strict_gate=True, persist_snapshot=False)
    diff_add_bad = run_target_diff(db_session, target, rep_add_bad, "HEAD")
    assert diff_add_bad.diff_verdict == "FAIL"
    assert any(
        f.rule_code == "MANIP-001" and f.source_file == "backend/app/services/bad_new.py"
        for f in diff_add_bad.new_findings
    )
    assert all(f.source_file != "backend/app/services/legacy.py" for f in diff_add_bad.new_findings)

    # 4. Modify legacy.py cleanly while another file had a change -> verify base_target preserves id & kwargs
    (repo / "backend" / "app" / "services" / "bad_new.py").unlink()
    (repo / "frontend" / "src" / "app" / "about" / "page.tsx").unlink()
    (repo / "backend" / "app" / "services" / "legacy.py").write_text(
        "LEGACY_WORKLOAD_CAP = 10\n\ndef extra():\n    return 2\n", encoding="utf-8"
    )
    captured_calls: list[dict[str, object]] = []
    orig_scan = scanner_service.run_target_scan

    def _spy_scan(sess, tgt, **kw):
        captured_calls.append({"id": tgt.id, **kw})
        return orig_scan(sess, tgt, **kw)

    with patch("app.services.diff_and_sarif_service.run_target_scan", side_effect=_spy_scan):
        rep_mod = orig_scan(db_session, target, strict_gate=True, persist_snapshot=False)
        run_target_diff(
            db_session,
            target,
            rep_mod,
            "HEAD",
            pg_dsn="postgresql://user:pass@localhost/db",
            redis_dsn="redis://127.0.0.1:6379/0",
            allow_local_plugins=True,
            local_plugin_modules=["mod_a"],
        )
    assert len(captured_calls) == 1
    assert captured_calls[0]["id"] == target.id
    assert captured_calls[0]["pg_dsn"] == "postgresql://user:pass@localhost/db"
    assert captured_calls[0]["redis_dsn"] == "redis://127.0.0.1:6379/0"
    assert captured_calls[0]["allow_local_plugins"] is True
    assert captured_calls[0]["local_plugin_modules"] == ["mod_a"]


# ---------------------------------------------------------------------------
# P1-4: DYNAMIC, HEAD, and OPTIONS cross-tier matching
# ---------------------------------------------------------------------------


def test_p1_4_dynamic_head_and_options_route_matching() -> None:
    truth = TruthExtractionResult(
        nodes=[], table_symbol_map={}, function_symbol_map={}, notes=[]
    )
    routes = [
        RouteDescriptor(
            node_id="m:route:single",
            http_method="POST",
            full_path="/api/v1/single",
            path_regex=r"^/api/v1/single/?$",
            source_file="app/api.py",
            line=10,
            called_symbols=[],
            imported_modules=[],
        ),
        RouteDescriptor(
            node_id="m:route:multi_get",
            http_method="GET",
            full_path="/api/v1/multi",
            path_regex=r"^/api/v1/multi/?$",
            source_file="app/api.py",
            line=20,
            called_symbols=[],
            imported_modules=[],
        ),
        RouteDescriptor(
            node_id="m:route:multi_post",
            http_method="POST",
            full_path="/api/v1/multi",
            path_regex=r"^/api/v1/multi/?$",
            source_file="app/api.py",
            line=30,
            called_symbols=[],
            imported_modules=[],
        ),
        RouteDescriptor(
            node_id="m:route:item_id",
            http_method="DELETE",
            full_path="/api/v1/items/{item_id}",
            path_regex=r"^/api/v1/items/\d+/?$",
            source_file="app/api.py",
            line=40,
            called_symbols=[],
            imported_modules=[],
        ),
    ]
    manip = ManipulatorExtractionResult(
        nodes=[
            AtlasNode(
                id="m:route:single",
                tier="manipulate",
                subkind="route",
                label="POST /api/v1/single",
                source_file="app/api.py",
                line=10,
                summary="single",
            ),
            AtlasNode(
                id="m:route:multi_get",
                tier="manipulate",
                subkind="route",
                label="GET /api/v1/multi",
                source_file="app/api.py",
                line=20,
                summary="multi get",
            ),
            AtlasNode(
                id="m:route:multi_post",
                tier="manipulate",
                subkind="route",
                label="POST /api/v1/multi",
                source_file="app/api.py",
                line=30,
                summary="multi post",
            ),
        ],
        edges=[],
        routes=routes,
        coverage_complete=True,
    )
    disp = DisplayExtractionResult(
        nodes=[
            AtlasNode(
                id="d:page:test",
                tier="display",
                subkind="page",
                label="TestPage",
                source_file="src/page.tsx",
                line=1,
                summary="page",
            )
        ],
        edges=[],
        http_calls=[
            # 1. DYNAMIC matching single POST route -> mutates_endpoint / write
            FrontendHttpCall(
                caller_node_id="d:page:test",
                caller_symbol="TestPage",
                http_method="DYNAMIC",
                raw_path="/api/v1/single",
                normalized_path="/api/v1/single",
                source_file="src/page.tsx",
                line=5,
            ),
            # 2. DYNAMIC matching >1 routes -> DISP-006 (not DISP-004)
            FrontendHttpCall(
                caller_node_id="d:page:test",
                caller_symbol="TestPage",
                http_method="DYNAMIC",
                raw_path="/api/v1/multi",
                normalized_path="/api/v1/multi",
                source_file="src/page.tsx",
                line=6,
            ),
            # 3. DYNAMIC matching {param} wildcard -> DISP-006
            FrontendHttpCall(
                caller_node_id="d:page:test",
                caller_symbol="TestPage",
                http_method="DYNAMIC",
                raw_path="/api/v1/items/${itemId}",
                normalized_path="/api/v1/items/{param}",
                source_file="src/page.tsx",
                line=7,
            ),
            # 4. DYNAMIC matching zero routes -> DISP-004
            FrontendHttpCall(
                caller_node_id="d:page:test",
                caller_symbol="TestPage",
                http_method="DYNAMIC",
                raw_path="/api/v1/missing",
                normalized_path="/api/v1/missing",
                source_file="src/page.tsx",
                line=8,
            ),
            # 5. HEAD matching GET route -> queries_endpoint / read
            FrontendHttpCall(
                caller_node_id="d:page:test",
                caller_symbol="TestPage",
                http_method="HEAD",
                raw_path="/api/v1/multi",
                normalized_path="/api/v1/multi",
                source_file="src/page.tsx",
                line=9,
            ),
            # 6. OPTIONS matching POST route -> queries_endpoint / read
            FrontendHttpCall(
                caller_node_id="d:page:test",
                caller_symbol="TestPage",
                http_method="OPTIONS",
                raw_path="/api/v1/single",
                normalized_path="/api/v1/single",
                source_file="src/page.tsx",
                line=10,
            ),
        ],
    )
    edges, chains, findings = _solve_cross_tier_lineage(truth, manip, disp)
    edge_pairs = {(e.kind, e.target_id) for e in edges}
    assert ("mutates_endpoint", "m:route:single") in edge_pairs
    assert ("queries_endpoint", "m:route:multi_get") in edge_pairs
    assert ("queries_endpoint", "m:route:single") in edge_pairs
    assert any(c.http_method == "HEAD" and c.operation == "read" for c in chains)
    assert any(c.http_method == "OPTIONS" and c.operation == "read" for c in chains)
    assert any(c.http_method == "DYNAMIC" and c.operation == "write" for c in chains)
    by_line = {f.line: f.rule_code for f in findings}
    assert by_line == {6: "DISP-006", 7: "DISP-006", 8: "DISP-004"}


# ---------------------------------------------------------------------------
# R2.2 CLI --version & M1 -> M3 trusted_allowlist / epistemic coverage contract
# ---------------------------------------------------------------------------


def test_r2_2_cli_version_flag(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        cli_main(["--version"])
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert "wythe 0.2.9" in captured.out


def test_m1_to_m3_trusted_allowlist_and_epistemic_coverage_propagation(
    db_session: Session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "m1_m3_contract"
    (repo / "backend" / "app").mkdir(parents=True)
    (repo / "frontend" / "src" / "app").mkdir(parents=True)
    (repo / "backend" / "app" / "main.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8"
    )
    (repo / "frontend" / "src" / "app" / "page.tsx").write_text(
        "export default function P() { return <main>ok</main>; }\n", encoding="utf-8"
    )
    commit_sha = _init_git(repo)
    register_target(
        db_session, TargetProjectCreate(slug="m1-m3-contract", name="M1 M3", repo_path=str(repo))
    )
    target = get_target_by_slug(db_session, "m1-m3-contract")
    assert target is not None

    bundle = PortableGovernanceBundle(
        target_slug="m1-m3-contract",
        exported_at=utc_now(),
        fabricated_fallback_allowlist=["src/demo.tsx"],
        reference_exemplars=[
            PortableReferenceExemplar(
                title="Fixture exemplar",
                pointer="src/fixture.tsx",
                rationale="Approved DISP-009 fixture",
            )
        ],
        audit_rulings=[
            PortableRulingItem(
                node_id="d:page:root",
                disposition="intentional_exception",
                summary="Allow intentional mock",
                evidence_scope=["file:src/intentional.tsx"],
                audited_commit=commit_sha,
                recorded_by="arch",
            )
        ],
    )
    sync_portable_bundle_from_disk(db_session, target, bundle=bundle)

    seen_calls: list[dict[str, object]] = []

    def _fake_eval(
        _repo_root,
        _backend_sub,
        _frontend_sub,
        _manip,
        _disp,
        *,
        strict: bool = False,
        trusted_allowlist: frozenset[str] | set[str] | None = None,
        coverage_out: list[bool] | None = None,
    ):
        seen_calls.append(
            {
                "strict": strict,
                "trusted_allowlist": set(trusted_allowlist or ()),
                "has_coverage_out": coverage_out is not None,
            }
        )
        if not strict and coverage_out is not None:
            coverage_out.append(False)
            return [], ["epistemic_coverage_incomplete: simulated read error"]
        return [], []

    monkeypatch.setattr(scanner_service, "evaluate_epistemic_confabulation", _fake_eval)

    # strict_gate=True passes empty trusted_allowlist
    rep_strict = run_target_scan(db_session, target, strict_gate=True, persist_snapshot=False)
    assert rep_strict.gate.verdict == "PASS"
    assert seen_calls[-1]["strict"] is True
    assert seen_calls[-1]["trusted_allowlist"] == set()

    # strict_gate=False hydrates DB allowlist + exemplar + ruling scope, and epistemic coverage_out=[False] -> INCOMPLETE
    rep_nonstrict = run_target_scan(db_session, target, strict_gate=False, persist_snapshot=False)
    assert seen_calls[-1]["strict"] is False
    assert seen_calls[-1]["trusted_allowlist"] == {
        "src/demo.tsx",
        "src/fixture.tsx",
        "src/intentional.tsx",
    }
    assert rep_nonstrict.coverage_complete is False
    assert rep_nonstrict.gate.verdict == "INCOMPLETE"

    # Updating DB governance invalidates _EXTRACTION_CACHE even when git worktree is unchanged
    bundle2 = PortableGovernanceBundle(
        target_slug="m1-m3-contract",
        exported_at=utc_now(),
        fabricated_fallback_allowlist=["src/updated.tsx"],
    )
    sync_portable_bundle_from_disk(db_session, target, bundle=bundle2)
    run_target_scan(db_session, target, strict_gate=False, persist_snapshot=False)
    assert seen_calls[-1]["trusted_allowlist"] == {"src/updated.tsx"}


# ---------------------------------------------------------------------------
# Iteration 2 Regressions: safe_git commondir/quotes/ancestor, allowlist, CLI
# ---------------------------------------------------------------------------


def test_p0_1_rejects_commondir_in_standard_and_intra_repo_gitdir(tmp_path: Path) -> None:
    ext_git = tmp_path / "ext_git"
    ext_git.mkdir()
    sentinel = tmp_path / "COMMONDIR_RCE"
    (ext_git / "config").write_text(
        f'[core]\n\trepositoryformatversion = 0\n[filter "pwn"]\n\tclean = touch {sentinel}\n',
        encoding="utf-8",
    )

    # 1. Standard `.git/` directory with `.git/commondir`
    repo = tmp_path / "direct_cd_repo"
    repo.mkdir()
    (repo / ".gitattributes").write_text("* filter=pwn\n", encoding="utf-8")
    (repo / "f.txt").write_text("hi\n", encoding="utf-8")
    _init_git(repo)
    (repo / "f.txt").write_text("dirty\n", encoding="utf-8")
    (repo / ".git" / "commondir").write_text(str(ext_git) + "\n", encoding="utf-8")

    with pytest.raises(SafeGitError, match="commondir"):
        validate_git_dir_containment(repo)
    with pytest.raises(SafeGitError, match="commondir"):
        run_safe_git(repo, "status", "--porcelain=v1", text=True)
    assert not sentinel.exists()

    # Symlinked `.git/commondir` must also be rejected
    (repo / ".git" / "commondir").unlink()
    (repo / ".git" / "commondir").symlink_to(ext_git)
    with pytest.raises(SafeGitError, match="commondir"):
        validate_git_dir_containment(repo)

    # 2. Intra-repo `.git` file (`gitdir: inner_git`) + `inner_git/commondir`
    repo2 = tmp_path / "intra_cd_repo"
    repo2.mkdir()
    (repo2 / ".gitattributes").write_text("* filter=pwn\n", encoding="utf-8")
    (repo2 / "f.txt").write_text("hi\n", encoding="utf-8")
    _init_git(repo2)
    (repo2 / "f.txt").write_text("dirty\n", encoding="utf-8")
    (repo2 / ".git").rename(repo2 / "inner_git")
    (repo2 / ".git").write_text("gitdir: inner_git\n", encoding="utf-8")
    (repo2 / "inner_git" / "commondir").write_text(str(ext_git) + "\n", encoding="utf-8")

    with pytest.raises(SafeGitError, match="commondir"):
        validate_git_dir_containment(repo2)
    with pytest.raises(SafeGitError, match="commondir"):
        run_safe_git(repo2, "status", "--porcelain=v1", text=True)
    assert not sentinel.exists()


@pytest.mark.parametrize(
    "cfg_snippet",
    [
        '[core]\n\tsomething = "[notcore]"\n\tworktree = /etc\n',
        '[core]\n\tsomething = "a [benign] b"\n\tgitproxy = touch /tmp/pwn\n',
        '[core]\n\tsomething = "a \\\\" [notcore]"\n\tworktree = /etc\n',
        '[remote "origin"]\n\turl = http://[::1]:3000/repo.git\n\tuploadpack = /tmp/pwn\n',
    ],
)
def test_p0_1_config_quote_aware_brackets_rejects_bypass_and_allows_ipv6(
    tmp_path: Path, cfg_snippet: str
) -> None:
    repo = tmp_path / "quote_cfg_repo"
    repo.mkdir()
    (repo / "README.md").write_text("hi\n", encoding="utf-8")
    _init_git(repo)
    cfg = repo / ".git" / "config"
    base_cfg = cfg.read_text(encoding="utf-8")
    cfg.write_text(base_cfg + "\n" + cfg_snippet, encoding="utf-8")
    with pytest.raises(SafeGitError):
        validate_git_dir_containment(repo)

    # Valid IPv6 remote URL must continue to pass cleanly
    ipv6_repo = tmp_path / "ipv6_ok_repo"
    ipv6_repo.mkdir()
    (ipv6_repo / "README.md").write_text("hi\n", encoding="utf-8")
    _init_git(ipv6_repo)
    ipv6_cfg = ipv6_repo / ".git" / "config"
    ipv6_cfg.write_text(
        ipv6_cfg.read_text(encoding="utf-8")
        + '\n[remote "origin"]\n\turl = http://[::1]:3000/repo.git\n',
        encoding="utf-8",
    )
    assert validate_git_dir_containment(ipv6_repo) == (ipv6_repo / ".git").resolve()
    proc = run_safe_git(ipv6_repo, "rev-parse", "HEAD", text=True)
    assert len(str(proc.stdout).strip()) == 40


def test_p0_1_rejects_symlinked_grandparent_above_git_dir(tmp_path: Path) -> None:
    real_parent = tmp_path / "real_parent"
    real_repo = real_parent / "real_repo"
    real_repo.mkdir(parents=True)
    (real_repo / "README.md").write_text("hi\n", encoding="utf-8")
    _init_git(real_repo)

    sym_grandparent = tmp_path / "sym_grandparent"
    sym_grandparent.symlink_to(real_parent)
    aliased_repo = sym_grandparent / "real_repo"

    with pytest.raises(SafeGitError, match="symlinked repository ancestor"):
        validate_git_dir_containment(aliased_repo)
    with pytest.raises(SafeGitError, match="symlinked repository ancestor"):
        run_safe_git(aliased_repo, "rev-parse", "HEAD", text=True)


def test_m1_to_m3_revoked_and_stale_ruling_do_not_allowlist_disp010(
    db_session: Session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "disp10_revoke_repo"
    (repo / "backend" / "app").mkdir(parents=True)
    (repo / "frontend" / "src" / "app").mkdir(parents=True)
    (repo / "backend" / "app" / "main.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8"
    )
    (repo / "frontend" / "src" / "app" / "widget.js").write_text(
        "export function Widget() { return null; }\n", encoding="utf-8"
    )
    commit_sha = _init_git(repo)

    register_target(
        db_session,
        TargetProjectCreate(slug="disp10-revoke", name="Disp10 Revoke", repo_path=str(repo)),
    )
    target = get_target_by_slug(db_session, "disp10-revoke")
    assert target is not None

    seen_allowlists: list[set[str]] = []

    def _capture_eval(
        _repo_root,
        _backend_sub,
        _frontend_sub,
        _manip,
        _disp,
        *,
        strict: bool = False,
        trusted_allowlist: frozenset[str] | set[str] | None = None,
        coverage_out: list[bool] | None = None,
    ):
        _ = (strict, coverage_out)
        seen_allowlists.append(set(trusted_allowlist or ()))
        return [], []

    monkeypatch.setattr(scanner_service, "evaluate_epistemic_confabulation", _capture_eval)

    # 1. Stale audited_commit ruling must NOT be added to trusted_allowlist
    record_audit_ruling(
        db_session,
        target.id,
        audited_commit="deadbeef12345678",
        payload=AuditRulingCreate(
            node_id="d:page:src.app.stale",
            disposition="intentional_exception",
            summary="Stale exception",
            evidence_scope=["file:frontend/src/app/stale.js"],
            recorded_by="arch",
        ),
    )
    scanner_service._EXTRACTION_CACHE.clear()
    run_target_scan(db_session, target, strict_gate=False, persist_snapshot=False)
    assert seen_allowlists[-1] == set()

    # 2. Current-commit intentional_exception allowlists widget.js
    record_audit_ruling(
        db_session,
        target.id,
        audited_commit=commit_sha,
        payload=AuditRulingCreate(
            node_id="d:page:src.app.widget",
            disposition="intentional_exception",
            summary="Allow widget",
            evidence_scope=["file:frontend/src/app/widget.js"],
            recorded_by="arch",
        ),
    )
    scanner_service._EXTRACTION_CACHE.clear()
    run_target_scan(db_session, target, strict_gate=False, persist_snapshot=False)
    assert seen_allowlists[-1] == {"frontend/src/app/widget.js"}

    # 3. Newer revoked ruling on the same node_id must remove widget.js from trusted_allowlist
    record_audit_ruling(
        db_session,
        target.id,
        audited_commit=commit_sha,
        payload=AuditRulingCreate(
            node_id="d:page:src.app.widget",
            disposition="revoked",
            summary="Revoke widget waiver",
            recorded_by="arch",
        ),
    )
    scanner_service._EXTRACTION_CACHE.clear()
    run_target_scan(db_session, target, strict_gate=False, persist_snapshot=False)
    assert len(seen_allowlists) == 3
    assert seen_allowlists[-1] == set()

    # 4. Also verify without clearing cache: cache key distinguishes allowlist={'widget.js'} vs set()
    #    and a newer needs_review ruling on a fresh node keeps trusted_allowlist empty even on cache hit.
    record_audit_ruling(
        db_session,
        target.id,
        audited_commit=commit_sha,
        payload=AuditRulingCreate(
            node_id="d:page:src.app.widget",
            disposition="needs_review",
            summary="Needs review",
            recorded_by="arch",
        ),
    )
    rep_after_review = run_target_scan(db_session, target, strict_gate=False, persist_snapshot=False)
    assert rep_after_review.gate.verdict == "PASS"


def test_p0_4_cli_empty_and_dash_trusted_config_ref_fail_closed(
    isolated_db_url: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert isolated_db_url.startswith("sqlite:")
    monkeypatch.setenv("WYTHE_STATE_DIR", str(tmp_path / "cli_state"))
    repo = tmp_path / "empty_ref_repo"
    (repo / "backend" / "app" / "services").mkdir(parents=True)
    (repo / "frontend" / "src" / "app").mkdir(parents=True)
    (repo / ".wythe").mkdir()
    (repo / "backend" / "schema.sql").write_text(
        "CREATE TABLE items (id INTEGER PRIMARY KEY);\n", encoding="utf-8"
    )
    (repo / "backend" / "app" / "services" / "cfg.py").write_text(
        "SHADOW_WORKLOAD_CAP = 5\n", encoding="utf-8"
    )
    (repo / "backend" / "app" / "main.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8"
    )
    (repo / "frontend" / "src" / "app" / "page.tsx").write_text(
        "export default function P() { return <main>ok</main>; }\n", encoding="utf-8"
    )
    bundle = PortableGovernanceBundle(
        target_slug="empty-ref-repo",
        exported_at=utc_now(),
        fabricated_fallback_allowlist=["src/evil_disk_bypass.tsx"],
    )
    (repo / ".wythe" / "governance.json").write_text(
        bundle.model_dump_json(indent=2), encoding="utf-8"
    )
    _init_git(repo)

    for bad_ref in ("", "   "):
        assert (
            cli_main(["gate", str(repo), "--sync-config", "--trusted-config-ref", bad_ref]) == 2
        )
        assert cli_main(["sync-config", str(repo), "--trusted-config-ref", bad_ref]) == 2

    # Dash-prefixed refs fail closed whether passed as `--opt=-val` or `--opt -val`
    assert cli_main(["gate", str(repo), "--sync-config", "--trusted-config-ref=--upload-pack=evil"]) == 2
    assert cli_main(["sync-config", str(repo), "--trusted-config-ref=--upload-pack=evil"]) == 2
    with pytest.raises(SystemExit) as exc_info:
        cli_main(["gate", str(repo), "--sync-config", "--trusted-config-ref", "--upload-pack=evil"])
    assert exc_info.value.code == 2

    from app.db.session import get_session_factory

    with get_session_factory()() as sess:
        tgt = get_target_by_slug(sess, "empty-ref-repo")
        if tgt is not None:
            assert load_target_governance_allowlist(sess, tgt.id) == set()


# ---------------------------------------------------------------------------
# Iteration 3 Regressions: comment-backslash lexer, symlink/.. traversal, sync
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("case_name", "cfg_template"),
    [
        (
            "hash_comment_cont",
            '# comment \\\n[filter "pwn"]\n\tclean = touch "{sentinel}"\n',
        ),
        (
            "semicolon_comment_cont",
            '[core]\n; comment \\\nworktree = /etc\n',
        ),
        (
            "inline_hash_comment_cont",
            '[core]\n\tbare = false # ignore \\\n[filter "pwn"]\n\tclean = touch "{sentinel}"\n',
        ),
        (
            "escaped_quote_before_comment",
            '[core]\n\ta = \\" ; comment\n[filter "pwn"]\n\tclean = touch "{sentinel}"\n',
        ),
        (
            "double_backslash_quote_before_comment",
            '[core]\n\ta = \\\\" ; comment"\n[filter "pwn"]\n\tclean = touch "{sentinel}"\n',
        ),
        (
            "continuation_ended_by_comment",
            '[core]\n\ta = bar \\\n# comment\nworktree = /etc\n',
        ),
    ],
)
def test_p0_1_comment_backslash_continuations_rejected_before_git_or_diff(
    isolated_db_url: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case_name: str,
    cfg_template: str,
) -> None:
    assert isolated_db_url.startswith("sqlite:")
    monkeypatch.setenv("WYTHE_STATE_DIR", str(tmp_path / f"state_{case_name}"))
    repo = tmp_path / f"repo_{case_name}"
    (repo / "backend" / "app").mkdir(parents=True)
    (repo / "frontend" / "src" / "app").mkdir(parents=True)
    (repo / "backend" / "app" / "main.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8"
    )
    (repo / "frontend" / "src" / "app" / "page.tsx").write_text(
        "export default function P() { return <main>ok</main>; }\n", encoding="utf-8"
    )
    (repo / ".gitattributes").write_text("* filter=pwn\n", encoding="utf-8")
    _init_git(repo)
    (repo / "backend" / "app" / "main.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\nx = 1\n", encoding="utf-8"
    )

    sentinel = tmp_path / f"SENTINEL_{case_name}"
    cfg = repo / ".git" / "config"
    cfg.write_text(
        cfg.read_text(encoding="utf-8") + "\n" + cfg_template.format(sentinel=sentinel),
        encoding="utf-8",
    )

    with pytest.raises(SafeGitError):
        validate_git_dir_containment(repo)
    with pytest.raises(SafeGitError):
        run_safe_git(repo, "status", "--porcelain=v1", text=True)
    assert cli_main(["diff", str(repo), "--base", "HEAD"]) == 2
    assert not sentinel.exists()


def test_p0_1_valid_multiline_quoted_hash_and_ipv6_allowed(tmp_path: Path) -> None:
    repo = tmp_path / "valid_multiline_repo"
    repo.mkdir()
    (repo / "README.md").write_text("hi\n", encoding="utf-8")
    _init_git(repo)
    cfg = repo / ".git" / "config"
    cfg.write_text(
        cfg.read_text(encoding="utf-8")
        + '\n[core]\n\ta = "hello \\\n# inside quote"\n'
        + '[remote "origin"]\n\turl = http://[::1]:3000/repo.git\n',
        encoding="utf-8",
    )
    assert validate_git_dir_containment(repo) == (repo / ".git").resolve()
    proc = run_safe_git(repo, "rev-parse", "HEAD", text=True)
    assert len(str(proc.stdout).strip()) == 40


def test_p0_1_rejects_symlink_dotdot_traversal_before_abspath_collapse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dir1 = tmp_path / "dir1"
    clean_repo = dir1 / "evil_repo"
    clean_repo.mkdir(parents=True)
    (clean_repo / "a.txt").write_text("clean\n", encoding="utf-8")
    _init_git(clean_repo)

    deep_sub = tmp_path / "deep" / "sub"
    deep_sub.mkdir(parents=True)
    evil_repo = tmp_path / "deep" / "evil_repo"
    evil_repo.mkdir(parents=True)
    (evil_repo / ".gitattributes").write_text("* filter=pwn\n", encoding="utf-8")
    (evil_repo / "a.txt").write_text("hi\n", encoding="utf-8")
    _init_git(evil_repo)
    (evil_repo / "a.txt").write_text("dirty\n", encoding="utf-8")

    sentinel = tmp_path / "SENTINEL_DOTDOT"
    evil_cfg = evil_repo / ".git" / "config"
    evil_cfg.write_text(
        evil_cfg.read_text(encoding="utf-8")
        + f'\n[filter "pwn"]\n\tclean = touch "{sentinel}"\n',
        encoding="utf-8",
    )

    sym_to_deep = dir1 / "sym_to_deep"
    sym_to_deep.symlink_to(deep_sub)
    traversed = sym_to_deep / ".." / "evil_repo"

    with pytest.raises(SafeGitError, match="symlinked repository"):
        validate_git_dir_containment(traversed)
    with pytest.raises(SafeGitError, match="symlinked repository"):
        run_safe_git(traversed, "status", "--porcelain=v1", text=True)

    # Also verify relative symlink/.. traversal from dir1
    monkeypatch.chdir(dir1)
    rel_traversed = Path("sym_to_deep") / ".." / "evil_repo"
    with pytest.raises(SafeGitError, match="symlinked repository"):
        run_safe_git(rel_traversed, "status", "--porcelain=v1", text=True)
    assert not sentinel.exists()


def test_p0_4_direct_sync_portable_bundle_empty_or_dash_trusted_ref_fails_closed(
    db_session: Session, tmp_path: Path
) -> None:
    repo = tmp_path / "direct_empty_ref"
    (repo / ".wythe").mkdir(parents=True)
    (repo / "README.md").write_text("hi\n", encoding="utf-8")
    _init_git(repo)
    bundle = PortableGovernanceBundle(
        target_slug="direct-empty-ref",
        exported_at=utc_now(),
        fabricated_fallback_allowlist=["src/should_not_sync.tsx"],
    )
    (repo / ".wythe" / "governance.json").write_text(
        bundle.model_dump_json(indent=2), encoding="utf-8"
    )
    register_target(
        db_session,
        TargetProjectCreate(slug="direct-empty-ref", name="Direct Empty Ref", repo_path=str(repo)),
    )
    target = get_target_by_slug(db_session, "direct-empty-ref")
    assert target is not None

    for bad_ref in ("", "   ", "-HEAD", "--upload-pack=evil"):
        with pytest.raises(ValueError, match="trusted_git_ref"):
            sync_portable_bundle_from_disk(db_session, target, trusted_git_ref=bad_ref)
    assert load_target_governance_allowlist(db_session, target.id) == set()


# ---------------------------------------------------------------------------
# Iteration 4 Regressions: UTF-8 BOM (\xef\xbb\xbf) in .git/config & config.worktree
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("cfg_filename", ["config", "config.worktree"])
@pytest.mark.parametrize(
    ("case_name", "bom_prefix_template"),
    [
        (
            "bom_filter_pwn",
            b'\xef\xbb\xbf[filter "pwn"]\n\tclean = touch "{sentinel}"\n',
        ),
        (
            "bom_comment_filter_pwn",
            b'\xef\xbb\xbf# leading comment\n[filter "pwn"]\n\tclean = touch "{sentinel}"\n',
        ),
        (
            "bom_core_worktree",
            b'\xef\xbb\xbf[core]\n\tworktree = {outside}\n',
        ),
    ],
)
def test_p0_1_rejects_utf8_bom_malicious_git_config_and_worktree_config(
    isolated_db_url: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    cfg_filename: str,
    case_name: str,
    bom_prefix_template: bytes,
) -> None:
    assert isolated_db_url.startswith("sqlite:")
    monkeypatch.setenv("WYTHE_STATE_DIR", str(tmp_path / f"state_{cfg_filename}_{case_name}"))
    outside = tmp_path / f"outside_{cfg_filename}_{case_name}"
    outside.mkdir()
    (outside / "secret.txt").write_text("secret\n", encoding="utf-8")

    repo = tmp_path / f"bom_repo_{cfg_filename}_{case_name}"
    (repo / "backend" / "app").mkdir(parents=True)
    (repo / "frontend" / "src" / "app").mkdir(parents=True)
    (repo / "backend" / "app" / "main.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8"
    )
    (repo / "frontend" / "src" / "app" / "page.tsx").write_text(
        "export default function P() { return <main>ok</main>; }\n", encoding="utf-8"
    )
    (repo / ".gitattributes").write_text("* filter=pwn\n", encoding="utf-8")
    _init_git(repo)
    (repo / "backend" / "app" / "main.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\nx = 1\n", encoding="utf-8"
    )

    sentinel = tmp_path / f"SENTINEL_{cfg_filename}_{case_name}"
    target_cfg = repo / ".git" / cfg_filename
    existing = target_cfg.read_bytes() if target_cfg.exists() else b""
    prefix_bytes = (
        bom_prefix_template.replace(b"{sentinel}", str(sentinel).encode("utf-8")).replace(
            b"{outside}", str(outside).encode("utf-8")
        )
    )
    target_cfg.write_bytes(prefix_bytes + existing)

    with pytest.raises(SafeGitError):
        validate_git_dir_containment(repo)
    with pytest.raises(SafeGitError):
        run_safe_git(repo, "status", "--porcelain=v1", text=True)
    assert cli_main(["diff", str(repo), "--base", "HEAD"]) == 2
    assert not sentinel.exists()


@pytest.mark.parametrize("cfg_filename", ["config", "config.worktree"])
def test_p0_1_allows_harmless_utf8_bom_git_config(tmp_path: Path, cfg_filename: str) -> None:
    repo = tmp_path / f"bom_valid_{cfg_filename}"
    repo.mkdir()
    (repo / "README.md").write_text("hi\n", encoding="utf-8")
    _init_git(repo)
    if cfg_filename == "config.worktree":
        subprocess.run(
            ["git", "config", "extensions.worktreeConfig", "true"],
            cwd=repo,
            check=True,
            env=_git_env(),
            capture_output=True,
        )
    target_cfg = repo / ".git" / cfg_filename
    existing = target_cfg.read_bytes() if target_cfg.exists() else b""
    target_cfg.write_bytes(b"\xef\xbb\xbf[user]\n\tname = tester\n" + existing)

    assert validate_git_dir_containment(repo) == (repo / ".git").resolve()
    proc = run_safe_git(repo, "rev-parse", "HEAD", text=True)
    assert len(str(proc.stdout).strip()) == 40
    name_proc = run_safe_git(repo, "config", "--get", "user.name", text=True)
    assert str(name_proc.stdout).strip() == "tester"
