"""Lane A regression suite for Wythe v0.2.9 post-bd2a609 remediation (P0-2, P1-1, P1-7, P1-8)."""

from __future__ import annotations

import http.server
import importlib.metadata
import json
import subprocess
import sys
import sysconfig
import threading
from datetime import timedelta
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest
import yaml
from sqlalchemy.orm import Session

from app.adapters.base import AdapterRegistry, ManipulatorExtractionResult, RawCandidateFinding
from app.adapters.plugin_registry import (
    _PLUGIN_IMPORT_LOCK,
    ENTRY_POINT_GROUP,
    WythePluginSpec,
    _sanitized_plugin_sys_path,
    _verify_entry_point_module_origin,
    discover_plugins,
    register_plugin_tier_adapters,
    run_manipulator_plugins,
    run_post_scan_plugins,
    run_stratum_badge_plugins,
    run_stratum_expand_plugins,
)
from app.cli import main as cli_main
from app.core.clock import utc_now, utc_today
from app.core.safe_git import (
    SAFE_GIT_CONFIG_ARGS,
    SafeGitError,
    build_safe_git_env,
    run_safe_git,
    validate_git_dir_containment,
)
from app.models import AuditRuling
from app.schemas.atlas import (
    AtlasNode,
    AuditRulingCreate,
    AuditRulingRead,
    BoundaryFinding,
    PortableGovernanceBundle,
    PortableRulingItem,
    StorePurposeDeclaration,
    TargetProjectCreate,
)
from app.services import scanner_service
from app.services.diff_and_sarif_service import compute_diff_and_blast_radius, run_target_diff
from app.services.git_diff import GitChanges
from app.services.governance_service import get_target_by_slug, record_audit_ruling, register_target
from app.services.portable_config_service import (
    export_portable_bundle_to_disk,
    load_target_governance_allowlist,
    sync_portable_bundle_from_disk,
)
from app.services.ruling_metadata import (
    _is_ruling_commit_stale,
    apply_rulings_and_store_purpose_checks,
)
from app.services.scanner_service import run_target_scan


def _git_env() -> dict[str, str]:
    return {
        "GIT_AUTHOR_NAME": "Tester",
        "GIT_AUTHOR_EMAIL": "tester@example.com",
        "GIT_COMMITTER_NAME": "Tester",
        "GIT_COMMITTER_EMAIL": "tester@example.com",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
    }


def _init_git(repo: Path) -> str:
    env = _git_env()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True, env=env, capture_output=True)
    subprocess.run(["git", "add", "."], cwd=repo, check=True, env=env, capture_output=True)
    subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", "commit", "-q", "-m", "init"],
        cwd=repo,
        check=True,
        env=env,
        capture_output=True,
    )
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, env=env, text=True).strip()


def _make_min_3tier_repo(repo: Path) -> None:
    (repo / "backend" / "app" / "services").mkdir(parents=True, exist_ok=True)
    (repo / "frontend" / "src" / "app").mkdir(parents=True, exist_ok=True)
    (repo / "backend" / "schema.sql").write_text(
        "CREATE TABLE items (id INTEGER PRIMARY KEY);\n", encoding="utf-8"
    )
    (repo / "backend" / "app" / "main.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8"
    )
    (repo / "frontend" / "src" / "app" / "page.tsx").write_text(
        "export default function P() { return <main>ok</main>; }\n", encoding="utf-8"
    )


def test_p0_2_blocks_promisor_lazy_fetch_ssrf_and_remote_vcs_helper(tmp_path: Path) -> None:
    hits: list[str] = []

    class _ProbeHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            hits.append(self.path)
            self.send_response(404)
            self.end_headers()

        def log_message(self, *_args: object) -> None:
            return

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _ProbeHandler)
    port = srv.server_address[1]
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        safe_env = build_safe_git_env()
        assert safe_env["GIT_NO_LAZY_FETCH"] == "1"
        assert safe_env["GIT_ALLOW_PROTOCOL"] == ""

        repo = tmp_path / "prom_repo"
        repo.mkdir()
        (repo / "a.txt").write_text("secret-blob-content\n", encoding="utf-8")
        _init_git(repo)
        blob_sha = subprocess.check_output(
            ["git", "rev-parse", "HEAD:a.txt"], cwd=repo, env=_git_env(), text=True
        ).strip()
        obj_file = repo / ".git" / "objects" / blob_sha[:2] / blob_sha[2:]
        if obj_file.exists():
            obj_file.chmod(0o644)
            obj_file.unlink()

        base_cfg = (repo / ".git" / "config").read_text(encoding="utf-8")
        for snippet in (
            f'[protocol "http"]\n\tallow = always\n[remote "origin"]\n\turl = http://127.0.0.1:{port}/ssrf\n',
            f'[extensions]\n\tpartialClone = origin\n[remote "origin"]\n\turl = http://127.0.0.1:{port}/ssrf\n',
            f'[remote "origin"]\n\turl = http://127.0.0.1:{port}/ssrf\n\tpromisor = true\n',
            '[remote "origin"]\n\tvcs = evil\n',
            f'[remote "origin"]\n\tproxy = http://127.0.0.1:{port}\n',
        ):
            (repo / ".git" / "config").write_text(base_cfg + "\n" + snippet, encoding="utf-8")
            with pytest.raises(SafeGitError):
                validate_git_dir_containment(repo)
            with pytest.raises(SafeGitError):
                run_safe_git(repo, "show", "HEAD:a.txt")

        # Defense-in-depth: even direct git invocation with build_safe_git_env() never hits HTTP
        (repo / ".git" / "config").write_text(
            base_cfg
            + f'\n[extensions]\n\tpartialClone = origin\n[remote "origin"]\n\turl = http://127.0.0.1:{port}/ssrf\n\tpromisor = true\n[protocol "http"]\n\tallow = always\n',
            encoding="utf-8",
        )
        direct = subprocess.run(
            ["git", "--no-pager", *SAFE_GIT_CONFIG_ARGS, "show", "HEAD:a.txt"],
            cwd=repo,
            env=safe_env,
            capture_output=True,
            check=False,
        )
        assert direct.returncode != 0
        assert hits == []
    finally:
        srv.shutdown()
        srv.server_close()


def test_p0_2_rejects_git_dir_symlinks_and_external_alternates_allows_internal(
    tmp_path: Path,
) -> None:
    private_repo = tmp_path / "private_repo"
    private_repo.mkdir()
    (private_repo / "secret.txt").write_text("PRIVATE_REPO_SECRET_42\n", encoding="utf-8")
    _init_git(private_repo)

    evil = tmp_path / "evil_repo"
    evil.mkdir()
    (evil / "pub.txt").write_text("public\n", encoding="utf-8")
    _init_git(evil)

    # 1. External objects/info/alternates + symlinked refs rejected
    alt_file = evil / ".git" / "objects" / "info" / "alternates"
    alt_file.parent.mkdir(parents=True, exist_ok=True)
    alt_file.write_text(f"{private_repo / '.git' / 'objects'}\n", encoding="utf-8")
    with pytest.raises(SafeGitError, match="alternates"):
        run_safe_git(evil, "show", "HEAD:secret.txt")
    alt_file.unlink()

    # 2. External objects/info/http-alternates rejected
    http_alt = evil / ".git" / "objects" / "info" / "http-alternates"
    http_alt.write_text("http://127.0.0.1:9/objects\n", encoding="utf-8")
    with pytest.raises(SafeGitError, match="http-alternates"):
        validate_git_dir_containment(evil)
    http_alt.unlink()

    # 3. Internal alternates strictly inside verified repo .git directory is allowed
    internal_alt = evil / ".git" / "objects_internal_pack"
    internal_alt.mkdir()
    alt_file.write_text("../objects_internal_pack\n", encoding="utf-8")
    assert validate_git_dir_containment(evil) == (evil / ".git").resolve()
    alt_file.unlink()

    # 4. Symlink checks on .git/{objects,refs,packed-refs,index,logs,hooks,info} & nested entries
    for entry_name in ("objects", "refs", "packed-refs", "index", "logs", "hooks", "info"):
        r_sym = tmp_path / f"sym_{entry_name}"
        r_sym.mkdir()
        (r_sym / "a.txt").write_text("x\n", encoding="utf-8")
        _init_git(r_sym)
        target_p = r_sym / ".git" / entry_name
        if target_p.is_dir():
            import shutil

            shutil.rmtree(target_p)
        elif target_p.exists():
            target_p.unlink()
        target_p.symlink_to(private_repo / ".git" / "refs")
        with pytest.raises(SafeGitError):
            validate_git_dir_containment(r_sym)

    nested_ref_sym = evil / ".git" / "refs" / "heads" / "ext_branch"
    nested_ref_sym.symlink_to(private_repo / ".git" / "HEAD")
    with pytest.raises(SafeGitError, match="symlink"):
        validate_git_dir_containment(evil)
    nested_ref_sym.unlink()


def test_p1_1_permits_neutralized_developer_git_configs_and_submodules(
    isolated_db_url: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert isolated_db_url.startswith("sqlite:")
    monkeypatch.setenv("WYTHE_STATE_DIR", str(tmp_path / "p1_1_state"))
    repo = tmp_path / "dev_repo"
    _make_min_3tier_repo(repo)
    sub_sha = _init_git(repo)

    # Register a 160000 submodule gitlink in index + commit 1, then advance to commit 2
    subprocess.run(
        ["git", "update-index", "--add", "--cacheinfo", f"160000,{sub_sha},vendor/submod"],
        cwd=repo,
        check=True,
        env=_git_env(),
    )
    subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", "commit", "-q", "-m", "add gitlink"],
        cwd=repo,
        check=True,
        env=_git_env(),
    )
    (repo / "frontend" / "src" / "app" / "page.tsx").write_text(
        "export default function P() { return <main>v2</main>; }\n", encoding="utf-8"
    )
    subprocess.run(["git", "add", "."], cwd=repo, check=True, env=_git_env())
    subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", "commit", "-q", "-m", "v2"],
        cwd=repo,
        check=True,
        env=_git_env(),
    )

    sentinel = tmp_path / "NEUTRALIZED_EXEC"
    cfg = repo / ".git" / "config"
    cfg.write_text(
        cfg.read_text(encoding="utf-8")
        + f"""
[core]
\tfsmonitor = touch {sentinel}
\thooksPath = {tmp_path}
\tpager = touch {sentinel}
\tattributesFile = {tmp_path / "attrs"}
\talternateRefsCommand = touch {sentinel}
\tsshCommand = touch {sentinel}
\taskPass = touch {sentinel}
[credential]
\thelper = !touch {sentinel}
[credential "https://git.example.com"]
\tusername = dev
[submodule "vendor/submod"]
\turl = https://git.example.com/sub.git
\tactive = true
[filter "lfs"]
\tclean = git-lfs clean -- %f
\tsmudge = git-lfs smudge -- %f
\tprocess = git-lfs filter-process
\trequired = true
[gpg]
\tprogram = touch {sentinel}
[gpg "ssh"]
\tprogram = touch {sentinel}
[alias]
\tst = !touch {sentinel}
[pager]
\tdiff = touch {sentinel}
[http]
\tsslVerify = true
""",
        encoding="utf-8",
    )

    assert validate_git_dir_containment(repo) == (repo / ".git").resolve()
    rev = run_safe_git(repo, "rev-parse", "HEAD", text=True)
    assert len(str(rev.stdout).strip()) == 40
    assert cli_main(["diff", "--base", "HEAD~1", str(repo)]) == 0
    assert not sentinel.exists()

    # Case-mismatched [filter "LFS"] & diff.command remain blocked
    base_dev_cfg = cfg.read_text(encoding="utf-8")
    for blocked in (
        '[filter "LFS"]\n\tclean = touch /tmp/x\n',
        '[diff "custom"]\n\tcommand = touch /tmp/x\n',
    ):
        cfg.write_text(base_dev_cfg + "\n" + blocked, encoding="utf-8")
        with pytest.raises(SafeGitError):
            validate_git_dir_containment(repo)


def test_p1_1_ruling_commit_stale_fails_closed_on_sentinels_and_broken_git(
    db_session: Session, tmp_path: Path
) -> None:
    now = utc_now()
    today = utc_today()
    ruling_read = AuditRulingRead(
        id=1,
        target_id=1,
        node_id="m:svc",
        disposition="accepted_clean",
        summary="Waived at abc1234",
        audited_commit="abc1234567890",
        audited_at=today,
        effective_from=today,
        recorded_by="arch",
        created_at=now,
    )
    for bad_cur in ("unavailable", "unknown", "uncommitted", "", None):
        assert _is_ruling_commit_stale("abc1234", bad_cur) is True
        assert _is_ruling_commit_stale(ruling_read, bad_cur) is True

    repo = tmp_path / "revival_chain_repo"
    _make_min_3tier_repo(repo)
    (repo / "backend" / "app" / "services" / "pol.py").write_text(
        "SHADOW_WORKLOAD_CAP = 5\n", encoding="utf-8"
    )
    (repo / "backend" / "app" / "main.py").write_text(
        "from fastapi import FastAPI\nfrom app.services import pol\napp = FastAPI()\n_ = pol\n",
        encoding="utf-8",
    )
    sha1 = _init_git(repo)
    register_target(
        db_session,
        TargetProjectCreate(slug="revival-chain", name="Revival", repo_path=str(repo)),
    )
    target = get_target_by_slug(db_session, "revival-chain")
    assert target is not None
    rep1 = run_target_scan(db_session, target, strict_gate=False, persist_snapshot=False)
    svc_node = next(n for n in rep1.nodes if "pol.py" in n.source_file)

    record_audit_ruling(
        db_session,
        target.id,
        audited_commit=sha1,
        payload=AuditRulingCreate(
            node_id=svc_node.id,
            disposition="accepted_clean",
            summary="Approved at sha1",
            evidence_scope=[
                f"MANIP-001@{svc_node.source_file}:1",
                "file:frontend/src/app/page.tsx",
            ],
            recorded_by="arch",
        ),
    )
    assert run_target_scan(db_session, target, strict_gate=False, persist_snapshot=False).gate.verdict == "PASS"

    # Poison .git/config -> SafeGitError -> source_commit == "unavailable" -> MUST fail closed (stale)!
    cfg = repo / ".git" / "config"
    cfg.write_text(cfg.read_text(encoding="utf-8") + "\n[core]\n\tworktree = /etc\n", encoding="utf-8")
    scanner_service._EXTRACTION_CACHE.clear()
    rep_broken = run_target_scan(db_session, target, strict_gate=False, persist_snapshot=False)
    assert rep_broken.source_commit == "unavailable"
    assert rep_broken.gate.verdict == "FAIL"
    assert any(f.rule_code == "MANIP-001" for f in rep_broken.findings)


def test_p1_7_plugin_failures_force_incomplete_across_discover_tier_stratum_and_optin(
    db_session: Session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "p1_7_repo"
    _make_min_3tier_repo(repo)
    _init_git(repo)
    register_target(
        db_session, TargetProjectCreate(slug="p1-7-repo", name="P1-7", repo_path=str(repo))
    )
    target = get_target_by_slug(db_session, "p1-7-repo")
    assert target is not None

    clean_rep = run_target_scan(db_session, target, strict_gate=True, persist_snapshot=False)
    assert clean_rep.gate.verdict == "PASS"

    # 1. Broken entry_point during discover_plugins -> coverage_complete=False / INCOMPLETE
    class _BrokenLoadEp:
        name = "broken-ep-load"
        value = "pkg_broken:PLUG"
        group = ENTRY_POINT_GROUP
        dist = SimpleNamespace(version="0.1.0")

        def load(self) -> object:
            raise ImportError("missing runtime library")

    monkeypatch.setattr(
        importlib.metadata,
        "entry_points",
        lambda **kw: (_BrokenLoadEp(),) if kw.get("group") == ENTRY_POINT_GROUP else (),
    )
    scanner_service._EXTRACTION_CACHE.clear()
    rep_disc_fail = run_target_scan(db_session, target, strict_gate=True, persist_snapshot=False)
    assert rep_disc_fail.coverage_complete is False
    assert rep_disc_fail.gate.verdict == "INCOMPLETE"
    assert any("broken-ep-load" in n for n in rep_disc_fail.scan_notes)

    # 2. Broken local_opt_in loader -> failures_out + INCOMPLETE on scan
    monkeypatch.setattr(importlib.metadata, "entry_points", lambda **_kw: ())
    scanner_service._EXTRACTION_CACHE.clear()
    rep_optin_fail = run_target_scan(
        db_session,
        target,
        strict_gate=True,
        persist_snapshot=False,
        allow_local_plugins=True,
        local_plugin_modules=[str(tmp_path / "nonexistent_plugin.py")],
    )
    assert rep_optin_fail.coverage_complete is False
    assert rep_optin_fail.gate.verdict == "INCOMPLETE"

    # 3. register_plugin_tier_adapters failure -> failures_out + INCOMPLETE
    class _BadTierAdapter:
        name = "bad-tier"

        def __init__(self) -> None:
            raise RuntimeError("tier adapter init boom")

        def extract(self, *_a: object) -> None:
            return None

    bad_tier_spec = WythePluginSpec(name="bad-tier-plug", kind="stack_adapter")
    object.__setattr__(bad_tier_spec, "truth_adapters", (_BadTierAdapter,))
    reg_notes: list[str] = []
    reg_fails: list[str] = []
    register_plugin_tier_adapters(
        AdapterRegistry(), plugins=[bad_tier_spec], notes_out=reg_notes, failures_out=reg_fails
    )
    assert len(reg_fails) == 1 and "bad-tier-plug" in reg_fails[0]

    # 4. Stratum badge & expand hook failures + local_opt_in manip/post failures -> INCOMPLETE
    badge_crash_spec = WythePluginSpec(
        name="crash-badge",
        kind="stratum_inspector",
        origin="entry_point",
        supported_zooms=(2,),
        stratum_badge_hook=lambda *_a: (_ for _ in ()).throw(RuntimeError("badge boom")),
        stratum_expand_hook=lambda *_a: (_ for _ in ()).throw(RuntimeError("expand boom")),
    )
    monkeypatch.setattr(scanner_service, "discover_plugins", lambda **_kw: [badge_crash_spec])
    scanner_service._EXTRACTION_CACHE.clear()
    rep_badge_fail = run_target_scan(db_session, target, strict_gate=True, persist_snapshot=False)
    assert rep_badge_fail.coverage_complete is False
    assert rep_badge_fail.gate.verdict == "INCOMPLETE"
    assert any("crash-badge" in n for n in rep_badge_fail.scan_notes)

    rep_exp = clean_rep.model_copy(deep=True)
    run_stratum_badge_plugins(repo, rep_exp, plugins=[badge_crash_spec], strict_plugins=False)
    assert rep_exp.coverage_complete is False and rep_exp.gate.verdict == "INCOMPLETE"

    rep_exp2 = clean_rep.model_copy(deep=True)
    run_stratum_expand_plugins(
        repo, rep_exp2, rep_exp2.nodes[0].id, 2, plugins=[badge_crash_spec], strict_plugins=False
    )
    assert rep_exp2.coverage_complete is False and rep_exp2.gate.verdict == "INCOMPLETE"

    manip = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
    optin_manip = WythePluginSpec(
        name="optin-manip-boom",
        kind="manipulator_augmenter",
        origin="local_opt_in",
        manipulator_hook=lambda *_a: (_ for _ in ()).throw(RuntimeError("optin manip")),
    )
    run_manipulator_plugins(repo, "backend", manip, plugins=[optin_manip], strict_plugins=False)
    assert manip.coverage_complete is False

    rep_post = clean_rep.model_copy(deep=True)
    optin_post = WythePluginSpec(
        name="optin-post-boom",
        kind="post_scan_check",
        origin="local_opt_in",
        post_scan_hook=lambda *_a: (_ for _ in ()).throw(RuntimeError("optin post")),
    )
    run_post_scan_plugins(repo, rep_post, plugins=[optin_post], strict_plugins=False)
    assert rep_post.coverage_complete is False and rep_post.gate.verdict == "INCOMPLETE"


def test_p1_7_allowlist_sys_path_lock_pep660_symlinks_and_preloaded_sys_modules(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert isinstance(_PLUGIN_IMPORT_LOCK, type(threading.RLock()))

    # 1. Untrusted PYTHONPATH & parent directory stripped even when repo_root=None
    untrusted_dir = tmp_path / "untrusted_pythonpath"
    untrusted_dir.mkdir()
    monkeypatch.syspath_prepend(str(untrusted_dir))
    monkeypatch.syspath_prepend(str(tmp_path))
    sanitized = _sanitized_plugin_sys_path(None)
    assert str(untrusted_dir.resolve()) not in sanitized
    assert str(tmp_path.resolve()) not in sanitized

    # 2. PEP 660 editable install via direct_url.json from trusted site-packages dist-info works
    purelib = Path(sysconfig.get_path("purelib")).resolve()
    ed_proj = tmp_path / "pep660_pkg"
    (ed_proj / "src" / "pep660_demo_plug").mkdir(parents=True)
    (ed_proj / "src" / "pep660_demo_plug" / "__init__.py").write_text(
        "class P:\n    name = 'pep660-demo'\n    def check_report(self, r, rep): return []\nPLUG = P()\n",
        encoding="utf-8",
    )
    fake_dist_dir = tmp_path / "trusted_site" / "pep660_demo-0.1.0.dist-info"
    fake_dist_dir.mkdir(parents=True)
    (fake_dist_dir / "direct_url.json").write_text(
        json.dumps({"url": ed_proj.resolve().as_uri(), "dir_info": {"editable": True}}),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "app.adapters.plugin_registry._trusted_plugin_install_roots",
        lambda **_kw: (purelib, (tmp_path / "trusted_site").resolve()),
    )

    class _EditableDist:
        version = "0.1.0"
        _path = fake_dist_dir

        def locate_file(self, p: str) -> Path:
            return self._path.parent / p

    ep_ed = importlib.metadata.EntryPoint(
        name="pep660_demo", value="pep660_demo_plug:PLUG", group=ENTRY_POINT_GROUP
    )._for(_EditableDist())
    monkeypatch.setattr(
        importlib.metadata,
        "entry_points",
        lambda **kw: (ep_ed,) if kw.get("group") == ENTRY_POINT_GROUP else (),
    )
    try:
        ed_specs = discover_plugins(include_builtins=False, allow_local_plugins=False)
        assert [s.name for s in ed_specs] == ["pep660-demo"]
    finally:
        sys.modules.pop("pep660_demo_plug", None)

    # 3. Symlinked module inside trusted root rejected BEFORE .resolve(), and preloaded sys.modules checked
    trusted_site = tmp_path / "trusted_site"
    outside_mod = tmp_path / "outside_evil.py"
    outside_mod.write_text("X = 1\n", encoding="utf-8")
    (trusted_site / "sym_plug.py").symlink_to(outside_mod)
    ep_sym = importlib.metadata.EntryPoint(
        name="sym_plug", value="sym_plug:X", group=ENTRY_POINT_GROUP
    )._for(_EditableDist())
    with pytest.raises(PermissionError, match="[Ss]ymlink"):
        _verify_entry_point_module_origin(ep_sym, [str(trusted_site.resolve())], repo_root=None)

    (trusted_site / "clean_preloaded.py").write_text("PLUG = 1\n", encoding="utf-8")
    evil_preloaded = ModuleType("clean_preloaded")
    evil_preloaded.__file__ = str(outside_mod)
    monkeypatch.setitem(sys.modules, "clean_preloaded", evil_preloaded)
    ep_pre = importlib.metadata.EntryPoint(
        name="clean_preloaded", value="clean_preloaded:PLUG", group=ENTRY_POINT_GROUP
    )._for(_EditableDist())
    with pytest.raises(PermissionError, match="outside trusted"):
        _verify_entry_point_module_origin(ep_pre, [str(trusted_site.resolve())], repo_root=None)


def test_p1_8_cli_trusted_ref_ignores_invalid_working_tree_slug_and_sanitizes_fallback(
    isolated_db_url: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert isolated_db_url.startswith("sqlite:")
    monkeypatch.setenv("WYTHE_STATE_DIR", str(tmp_path / "p1_8_cli_state"))
    repo = tmp_path / "slug_dos_repo"
    _make_min_3tier_repo(repo)
    (repo / ".wythe").mkdir(parents=True)
    trusted_bundle = PortableGovernanceBundle(
        target_slug="trusted-app-slug",
        exported_at=utc_now(),
        fabricated_fallback_allowlist=[],
    )
    (repo / ".wythe" / "governance.json").write_text(
        trusted_bundle.model_dump_json(indent=2), encoding="utf-8"
    )
    _init_git(repo)

    # Corrupt working-tree governance.json with invalid slug + malicious allowlist
    (repo / ".wythe" / "governance.json").write_text(
        json.dumps(
            {
                "target_slug": "_invalid_slug",
                "exported_at": utc_now().isoformat(),
                "fabricated_fallback_allowlist": ["src/untrusted_bypass.tsx"],
            }
        ),
        encoding="utf-8",
    )

    # 1. With --trusted-config-ref HEAD, CLI reads slug & bundle from HEAD and never crashes
    assert cli_main(["gate", "--sync-config", "--trusted-config-ref", "HEAD", str(repo)]) == 0
    from app.db.session import get_session_factory

    with get_session_factory()() as sess:
        trusted_t = get_target_by_slug(sess, "trusted-app-slug")
        assert trusted_t is not None
        assert load_target_governance_allowlist(sess, trusted_t.id) == set()
        assert get_target_by_slug(sess, "invalid_slug") is None

    # 2. Without --trusted-config-ref, working-tree {"target_slug": "_invalid_slug"} sanitizes cleanly
    repo2 = tmp_path / "_leading_underscore_dir"
    _make_min_3tier_repo(repo2)
    (repo2 / ".wythe").mkdir(parents=True)
    (repo2 / ".wythe" / "governance.json").write_text(
        json.dumps({"target_slug": "_invalid_slug", "exported_at": utc_now().isoformat()}),
        encoding="utf-8",
    )
    _init_git(repo2)
    assert cli_main(["gate", "--sync-config", str(repo2)]) == 0
    with get_session_factory()() as sess:
        sanitized_t = get_target_by_slug(sess, "invalid_slug")
        assert sanitized_t is not None


def test_p1_8_action_yml_allowlist_semantics_for_all_non_default_events(tmp_path: Path) -> None:
    action_path = Path(__file__).resolve().parents[2] / "action.yml"
    doc = yaml.safe_load(action_path.read_text(encoding="utf-8"))
    script = doc["runs"]["steps"][1]["run"]

    shim_dir = tmp_path / "bin"
    shim_dir.mkdir()
    args_file = tmp_path / "captured.json"
    shim = shim_dir / "uvx"
    shim.write_text(
        "#!/usr/bin/env python3\nimport json, sys\n"
        f"open({str(args_file)!r}, 'w').write(json.dumps(sys.argv[1:]))\n",
        encoding="utf-8",
    )
    shim.chmod(0o755)

    def _run(**extra: str) -> subprocess.CompletedProcess[str]:
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
            "TA_EVENT_NAME": "push",
            "TA_GITHUB_BASE_REF": "",
            "TA_MERGE_GROUP_BASE_SHA": "",
            "TA_DEFAULT_BRANCH": "main",
            "TA_REF": "refs/heads/main",
            **extra,
        }
        return subprocess.run(
            ["/bin/bash", "-c", script], check=False, env=env, capture_output=True, text=True
        )

    # Direct push to default branch is the ONLY case trusting working tree
    ok_push = _run()
    assert ok_push.returncode == 0
    assert "--trusted-config-ref" not in json.loads(args_file.read_text())

    # Every non-default event or missing default branch requires --trusted-config-ref
    for ev in (
        "issue_comment",
        "pull_request_review",
        "workflow_run",
        "workflow_call",
        "workflow_dispatch",
        "schedule",
    ):
        res_ev = _run(TA_EVENT_NAME=ev)
        assert res_ev.returncode == 0, res_ev.stderr
        assert "--trusted-config-ref" in json.loads(args_file.read_text())
        assert _run(TA_EVENT_NAME=ev, TA_BASE="").returncode == 2

    # Push with empty TA_DEFAULT_BRANCH or empty TA_REF also requires --trusted-config-ref
    res_no_def = _run(TA_DEFAULT_BRANCH="")
    assert res_no_def.returncode == 0
    assert "--trusted-config-ref" in json.loads(args_file.read_text())
    res_no_ref = _run(TA_REF="")
    assert res_no_ref.returncode == 0
    assert "--trusted-config-ref" in json.loads(args_file.read_text())


def test_p1_8_pure_addition_diff_ruling_allowlist_and_effective_until_roundtrip(
    db_session: Session, tmp_path: Path
) -> None:
    repo = tmp_path / "pure_add_repo"
    _make_min_3tier_repo(repo)
    sha = _init_git(repo)
    register_target(
        db_session, TargetProjectCreate(slug="pure-add", name="Pure Add", repo_path=str(repo))
    )
    target = get_target_by_slug(db_session, "pure-add")
    assert target is not None

    # 1. Pure-addition PR materializes base_report -> catches new cross-file/line=0 findings!
    (repo / "frontend" / "src" / "app" / "added.tsx").write_text(
        "export function Added() { return <div>added</div>; }\n", encoding="utf-8"
    )
    base_scan = run_target_scan(db_session, target, strict_gate=True, persist_snapshot=False)
    cross_file_finding = BoundaryFinding(
        id="f:cross:unchanged",
        rule_code="MANIP-006",
        tier="manipulate",
        severity="blocking",
        blocks_gate=True,
        source_file="backend/app/main.py",
        line=1,
        title="New cross-file violation anchored on unchanged file",
        detail="Triggered by added file",
        remediation="Fix dependency",
    )
    line0_finding = BoundaryFinding(
        id="f:line0:added",
        rule_code="MANIP-007",
        tier="manipulate",
        severity="blocking",
        blocks_gate=True,
        source_file="frontend/src/app/added.tsx",
        line=0,
        title="File-level line=0 violation",
        detail="Line 0 finding",
        remediation="Fix file",
    )
    head_with_cross = base_scan.model_copy(
        update={"findings": [*base_scan.findings, cross_file_finding, line0_finding]}
    )
    diff_res = run_target_diff(db_session, target, head_with_cross, "HEAD")
    assert diff_res.base_graph_status == "available"
    assert {f.id for f in diff_res.new_findings} == {"f:cross:unchanged", "f:line0:added"}
    assert diff_res.diff_verdict == "FAIL"

    # Also ensure failed base recovery on pure addition fails closed (INCOMPLETE)
    inc_res = compute_diff_and_blast_radius(
        repo,
        base_scan,
        "HEAD",
        base_report=None,
        changes=GitChanges(base_commit=sha, before={}, after={"added.tsx": [(1, 1)]}),
        analysis_notes=["Base graph could not be recovered: simulated failure"],
    )
    assert inc_res.diff_verdict == "INCOMPLETE"

    # 2. Dispositions outside explicit allowlist ("superseded", "open") never inherit store_purpose
    now = utc_now()
    today = utc_today()
    node = AtlasNode(
        id="t:redis:cfg",
        tier="truth",
        subkind="cache_store",
        label="cfg",
        source_file="backend/app/cfg.py",
        summary="redis",
        status="gray_zone",
    )
    raw_t4 = RawCandidateFinding(
        rule_code="TRUTH-004",
        node_id="m:svc",
        target_node_id="t:redis:cfg",
        source_file="backend/app/cfg.py",
        line=5,
        title="Unbounded",
        detail="writes cfg",
        remediation="Add TTL",
    )
    old_waiver = AuditRulingRead(
        id=1,
        target_id=target.id,
        node_id="t:redis:cfg",
        disposition="accepted_clean",
        summary="Old config waiver",
        store_purpose=StorePurposeDeclaration(
            intended_use="persistent_config", recovery_expectation="Daily backup"
        ),
        audited_commit=sha,
        audited_at=today,
        effective_from=today,
        recorded_by="arch",
        created_at=now - timedelta(hours=2),
    )
    for non_active_disp in ("superseded", "open", "revoked", "rejected"):
        n_c = node.model_copy(deep=True)
        newer = old_waiver.model_copy(
            update={"id": 2, "disposition": non_active_disp, "store_purpose": None, "created_at": now}
        )
        rem = apply_rulings_and_store_purpose_checks(
            [n_c], [], [raw_t4], [old_waiver, newer], strict_gate=False, current_commit=sha
        )
        assert len(rem) == 1 and n_c.store_purpose is None

    # 3. PortableRulingItem.effective_until round-trips export -> sync without resurrecting expired rulings
    expired_day = today - timedelta(days=2)
    direct_item = PortableRulingItem(
        node_id="t:redis:cfg",
        disposition="accepted_clean",
        summary="Expired waiver",
        audited_commit=sha,
        effective_until=expired_day,
        recorded_by="arch",
    )
    assert direct_item.effective_until == expired_day
    db_session.add(
        AuditRuling(
            target_id=target.id,
            node_id="t:redis:cfg",
            disposition="accepted_clean",
            summary="Expired waiver",
            audited_commit=sha,
            audited_at=expired_day,
            effective_from=expired_day,
            effective_until=expired_day,
            recorded_by="arch",
            created_at=now,
        )
    )
    db_session.commit()
    bundle_out = tmp_path / "exported_gov.json"
    export_portable_bundle_to_disk(db_session, target, out_path=bundle_out)
    exported_json = json.loads(bundle_out.read_text(encoding="utf-8"))
    assert exported_json["audit_rulings"][0]["effective_until"] == expired_day.isoformat()

    repo_fresh = tmp_path / "fresh_import_repo"
    _make_min_3tier_repo(repo_fresh)
    _init_git(repo_fresh)
    register_target(
        db_session, TargetProjectCreate(slug="fresh-imp", name="Fresh", repo_path=str(repo_fresh))
    )
    fresh_t = get_target_by_slug(db_session, "fresh-imp")
    assert fresh_t is not None
    sync_portable_bundle_from_disk(db_session, fresh_t, in_path=bundle_out)
    from app.services.governance_service import list_rulings

    imported_rulings = list_rulings(db_session, fresh_t.id)
    assert len(imported_rulings) == 1
    assert imported_rulings[0].effective_until == expired_day
    n_exp = node.model_copy(deep=True)
    rem_exp = apply_rulings_and_store_purpose_checks(
        [n_exp], [], [raw_t4], imported_rulings, strict_gate=False, current_commit=sha
    )
    assert len(rem_exp) == 1
