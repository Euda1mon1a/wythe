"""Tests for `wythe-plugin-compiler-ir` (`#77`): Zoom-2 USR/SIL/LLVM IR & Metal `AIR` seams."""

from __future__ import annotations

import json
import struct
import subprocess
import time
from pathlib import Path

import pytest

from app.adapters import plugin_registry
from app.adapters.base import ManipulatorExtractionResult
from app.db.session import get_session_factory
from app.main import initialize_database
from app.models import TargetProject
from app.schemas.atlas import AtlasEdge, AtlasNode
from app.services.scanner_service import run_target_scan
from app.services.stratum_service import (
    attach_zoom1_stratum_badges,
    build_node_stratum_drilldown,
)
from wythe_plugin_compiler_ir import (
    COMPILER_IR_PLUGIN,
    METAL_AIR_EPISTEMIC_NOTE,
    CompilerIrPlugin,
    compiler_ir_artifacts_scope,
    load_bounded_json_or_yaml,
    load_combined_ir_bundle,
    parse_llvm_ir_file,
    parse_llvm_ir_text,
    parse_metal_file,
    parse_metal_source,
    parse_metallib_artifact,
    parse_metallib_bytes,
    parse_sil_file,
    parse_sil_text,
    parse_usr_index,
    upgrade_edges_with_compiler_ir,
    verify_metal_compute_seams,
)


def _build_synthetic_mtlb(entries: list[tuple[str, int, tuple[int, ...]]]) -> bytes:
    """Build a spec-conformant Apple `MTLB` binary container header + function directory."""
    encoded_groups: list[bytes] = []
    for name, shader_type, buf_indices in entries:
        name_bytes = name.encode("utf-8") + b"\x00"
        tags = bytearray()
        tags += b"NAME" + struct.pack("<H", len(name_bytes)) + name_bytes
        tags += b"TYPE" + struct.pack("<H", 1) + bytes([shader_type])
        if buf_indices:
            b_payload = b"".join(struct.pack("<H", b) for b in buf_indices)
            tags += b"BUFF" + struct.pack("<H", len(b_payload)) + b_payload
        tags += b"ENDT\x00\x00"
        encoded_groups.append(struct.pack("<I", len(tags)) + bytes(tags))

    fn_dir = struct.pack("<I", len(entries)) + b"".join(encoded_groups)
    header_size = 88
    total_size = header_size + len(fn_dir)
    header = bytearray(header_size)
    header[0:4] = b"MTLB"
    struct.pack_into("<HHHH", header, 4, 1, 2, 2, 0)
    struct.pack_into("<Q", header, 16, total_size)
    struct.pack_into("<QQ", header, 24, header_size, len(fn_dir))
    return bytes(header) + fn_dir


def _scan_python_metal_repo(
    repo_dir: Path,
    *,
    slug: str,
    with_plugin: bool = True,
    strict_gate: bool = True,
):
    initialize_database()
    factory = get_session_factory()
    plugin_mod = str(
        Path(__file__).resolve().parents[2]
        / "plugins"
        / "wythe-plugin-compiler-ir"
        / "src"
        / "wythe_plugin_compiler_ir"
        / "plugin.py"
    )
    with factory() as session:
        target = TargetProject(
            slug=slug[:48],
            name=f"Target {slug}",
            repo_path=str(repo_dir),
            backend_subdir="backend",
            frontend_subdir="",
            stack_profile_slug="python-services",
        )
        return run_target_scan(
            session,
            target,
            strict_gate=strict_gate,
            persist_snapshot=False,
            allow_local_plugins=with_plugin,
            local_plugin_modules=[f"{plugin_mod}:COMPILER_IR_PLUGIN"] if with_plugin else None,
        )


def test_plugin_spec_metadata_rules_and_active_artifact_scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert COMPILER_IR_PLUGIN.name == "compiler-ir"
    assert COMPILER_IR_PLUGIN.kind == "stratum_inspector"
    assert COMPILER_IR_PLUGIN.supported_zooms == (2,)
    assert [r.rule_code for r in COMPILER_IR_PLUGIN.rules] == [
        "METAL-001",
        "METAL-002",
        "METAL-003",
    ]
    assert all(r.severity == "blocking" and r.blocks_gate for r in COMPILER_IR_PLUGIN.rules)

    meta = COMPILER_IR_PLUGIN.to_metadata()
    assert meta["supported_zooms"] == [2]
    assert meta["rules"] == ["METAL-001", "METAL-002", "METAL-003"]

    usr_file = tmp_path / "index.json"
    usr_file.write_text(
        json.dumps(
            {
                "symbols": [
                    {
                        "usr": "c:@F@container_audit_token_pid",
                        "name": "container_audit_token_pid",
                        "kind": "function",
                        "language": "c",
                        "file": "Sources/CAuditToken/AuditToken.c",
                        "line": 14,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        plugin_registry,
        "get_active_stratum_artifacts",
        lambda: {"index_store": (str(usr_file),)},
        raising=False,
    )
    inst = CompilerIrPlugin()
    collected = inst._collect_artifacts()
    assert collected["index_store"] == (str(usr_file),)


APPLE_CONTAINER_USR_JSON = {
    "symbols": [
        {
            "usr": "s:17ContainerCommands12ContainerRunV3runyyYaKF",
            "name": "ContainerRun.run()",
            "kind": "method",
            "language": "swift",
            "file": "Sources/ContainerCommands/ContainerRun.swift",
            "line": 28,
        },
        {
            "usr": "s:12ContainerXPC9XPCClientC4send5routeySS_tYaKF",
            "name": "XPCClient.send(route:)",
            "kind": "method",
            "language": "swift",
            "file": "Sources/ContainerXPC/XPCClient.swift",
            "line": 44,
        },
        {
            "usr": "s:12ContainerXPC9XPCClientC10verifyPeeryyKF",
            "name": "XPCClient.verifyPeer()",
            "kind": "method",
            "language": "swift",
            "file": "Sources/ContainerXPC/XPCClient.swift",
            "line": 62,
        },
        {
            "usr": "c:@F@container_audit_token_pid",
            "name": "container_audit_token_pid",
            "kind": "function",
            "language": "c",
            "file": "Sources/CAuditToken/AuditToken.c",
            "line": 19,
        },
    ],
    "occurrences": [
        {
            "usr": "s:12ContainerXPC9XPCClientC4send5routeySS_tYaKF",
            "roles": ["reference", "call"],
            "file": "Sources/ContainerCommands/ContainerRun.swift",
            "line": 35,
            "caller_usr": "s:17ContainerCommands12ContainerRunV3runyyYaKF",
            "caller_name": "ContainerRun.run()",
        },
        {
            "usr": "c:@F@container_audit_token_pid",
            "roles": 36,
            "file": "Sources/ContainerXPC/XPCClient.swift",
            "line": 67,
            "relations": [
                {
                    "roles": ["calledBy"],
                    "usr": "s:12ContainerXPC9XPCClientC10verifyPeeryyKF",
                    "name": "XPCClient.verifyPeer()",
                }
            ],
        },
    ],
}

APPLE_CONTAINER_SIL = """\
sil_stage canonical

// ContainerRun.run()
sil @$s17ContainerCommands12ContainerRunV3runyyYaKF : $@convention(method) (@guaranteed ContainerRun) -> () {
bb0(%0 : $ContainerRun):
  %1 = function_ref @swift_retain : $@convention(thin) (Builtin.NativeObject) -> ()
  %2 = apply %1(%0) : $@convention(thin) (Builtin.NativeObject) -> ()
  %3 = witness_method $XPCClient, #XPCTransport.send : <Self where Self : XPCTransport> (Self) -> (String) -> (), loc "Sources/ContainerCommands/ContainerRun.swift":35:12
  %4 = apply %3<XPCClient>(%0) : $@convention(witness_method: XPCTransport) (XPCClient) -> (), loc "Sources/ContainerCommands/ContainerRun.swift":35:12
  return %4 : $()
}

// protocol witness for XPCTransport.send(route:) in conformance XPCClient : XPCTransport in ContainerXPC
sil private [transparent] [thunk] @$s12ContainerXPC9XPCClientCAA12XPCTransportA2aDP4send5routeySS_tYaKFTW : $@convention(witness_method: XPCTransport) (@in_guaranteed XPCClient) -> () {
bb0(%0 : $*XPCClient):
  %1 = class_method %0 : $*XPCClient, #XPCClient.send : (XPCClient) -> (String) -> ()
  %2 = apply %1(%0) : $@convention(method) (XPCClient) -> ()
  return %2 : $()
}

// XPCClient.send(route:)
sil @$s12ContainerXPC9XPCClientC4send5routeySS_tYaKF : $@convention(method) (@guaranteed XPCClient) -> () {
bb0(%0 : $XPCClient):
  %1 = function_ref @$s12ContainerXPC9XPCClientC10verifyPeeryyKF : $@convention(method) (@guaranteed XPCClient) -> (), loc "Sources/ContainerXPC/XPCClient.swift":48:9
  %2 = apply %1(%0) : $@convention(method) (@guaranteed XPCClient) -> (), loc "Sources/ContainerXPC/XPCClient.swift":48:9
  return %2 : $()
}

// XPCClient.verifyPeer()
sil @$s12ContainerXPC9XPCClientC10verifyPeeryyKF : $@convention(method) (@guaranteed XPCClient) -> () {
bb0(%0 : $XPCClient):
  %1 = function_ref @container_audit_token_pid : $@convention(c) () -> Int32, loc "Sources/ContainerXPC/XPCClient.swift":67:14
  %2 = apply %1() : $@convention(c) () -> Int32, loc "Sources/ContainerXPC/XPCClient.swift":67:14
  return %2 : $()
}

sil [clang container_audit_token_pid] @container_audit_token_pid : $@convention(c) () -> Int32
sil @swift_retain : $@convention(thin) (Builtin.NativeObject) -> ()

sil_witness_table XPCClient: XPCTransport module ContainerXPC {
  method #XPCTransport.send: <Self where Self : XPCTransport> (Self) -> (String) -> () : @$s12ContainerXPC9XPCClientCAA12XPCTransportA2aDP4send5routeySS_tYaKFTW
}

sil_vtable XPCClient {
  #XPCClient.send: (XPCClient) -> (String) -> () : @$s12ContainerXPC9XPCClientC4send5routeySS_tYaKF [override]
}
"""

APPLE_CONTAINER_LLVM_IR = """\
source_filename = "Sources/CAuditToken/AuditToken.c"

define i32 @container_audit_token_pid(ptr %tok) !dbg !10 {
entry:
  %obj = call ptr @"\\01-[NSXPCConnection auditToken]"(ptr %tok), !dbg !11
  %h = call i64 @_RNvCs7a8b9c_10rust_crate11verify_hash(ptr %tok), !dbg !12
  call void @_ZTv0_n24_N9container7Runtime4syncEv(ptr %tok), !dbg !13
  call void @objc_release(ptr %obj), !dbg !14
  ret i32 42
}

define ptr @PyInit__container_native() !dbg !20 {
entry:
  %pid = call i32 @container_audit_token_pid(ptr null), !dbg !21
  ret ptr null
}

declare ptr @"\\01-[NSXPCConnection auditToken]"(ptr)
declare i64 @_RNvCs7a8b9c_10rust_crate11verify_hash(ptr)
declare void @_ZTv0_n24_N9container7Runtime4syncEv(ptr)
declare void @objc_release(ptr)

!1 = !DIFile(filename: "AuditToken.c", directory: "Sources/CAuditToken")
!2 = !DIFile(filename: "native_ext.c", directory: "Sources/PythonBridge")
!10 = distinct !DISubprogram(name: "container_audit_token_pid", file: !1, line: 19)
!11 = !DILocation(line: 21, column: 10, scope: !10)
!12 = !DILocation(line: 22, column: 10, scope: !10)
!13 = !DILocation(line: 23, column: 3, scope: !10)
!14 = !DILocation(line: 24, column: 3, scope: !10)
!20 = distinct !DISubprogram(name: "PyInit__container_native", file: !2, line: 8)
!21 = !DILocation(line: 10, column: 12, scope: !20)
"""


def test_apple_container_usr_sil_llvm_ir_zoom2_compaction_and_edge_symbol_links(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "apple_container_repo"
    (repo / "Sources" / "ContainerCommands").mkdir(parents=True)
    (repo / "Sources" / "ContainerXPC").mkdir(parents=True)
    (repo / "Sources" / "CAuditToken").mkdir(parents=True)
    (repo / "backend").mkdir(parents=True)
    (repo / "backend" / "schema.sql").write_text(
        "CREATE TABLE container_records (id TEXT PRIMARY KEY);\n", encoding="utf-8"
    )

    usr_json_path = tmp_path / "index_store.json"
    usr_json_path.write_text(json.dumps(APPLE_CONTAINER_USR_JSON), encoding="utf-8")
    usr_tsv_path = tmp_path / "extra_index.tsv"
    usr_tsv_path.write_text(
        "SYM\tc:@F@container_audit_token_pid\tcontainer_audit_token_pid\tfunction\tc\tSources/CAuditToken/AuditToken.c\t19\n",
        encoding="utf-8",
    )
    sil_path = tmp_path / "container.sil"
    sil_path.write_text(APPLE_CONTAINER_SIL, encoding="utf-8")
    ll_path = tmp_path / "audit_token.ll"
    ll_path.write_text(APPLE_CONTAINER_LLVM_IR, encoding="utf-8")

    report = _scan_python_metal_repo(repo, slug="apple-container-ir", with_plugin=False, strict_gate=False)
    cmd_node = AtlasNode(
        id="m:cmd:container_run",
        tier="manipulate",
        subkind="cli",
        label="ContainerRun",
        source_file="Sources/ContainerCommands/ContainerRun.swift",
        line=28,
        summary="ContainerRun CLI command",
    )
    xpc_node = AtlasNode(
        id="m:xpc:client",
        tier="manipulate",
        subkind="service",
        label="XPCClient",
        source_file="Sources/ContainerXPC/XPCClient.swift",
        line=44,
        summary="ContainerXPC client",
    )
    c_node = AtlasNode(
        id="m:ffi:audit_token",
        tier="manipulate",
        subkind="service",
        label="AuditToken",
        source_file="Sources/CAuditToken/AuditToken.c",
        line=19,
        summary="C audit_token shim",
    )
    e1 = AtlasEdge(
        id="e:cmd->xpc",
        source_id=cmd_node.id,
        target_id=xpc_node.id,
        kind="calls_helper",
        verification="declared",
        evidence_note="CLI calls XPCClient",
    )
    e2 = AtlasEdge(
        id="e:xpc->c",
        source_id=xpc_node.id,
        target_id=c_node.id,
        kind="calls_helper",
        verification="declared",
        evidence_note="XPCClient calls AuditToken.c",
    )
    report.nodes.extend([cmd_node, xpc_node, c_node])
    report.edges.extend([e1, e2])

    ir_bundle = load_combined_ir_bundle(
        repo,
        index_store=[usr_json_path, usr_tsv_path],
        sil=[sil_path],
        llvm_ir=[ll_path],
    )
    upgraded_cnt = upgrade_edges_with_compiler_ir(report.edges, report.nodes, ir_bundle)
    assert upgraded_cnt == 2
    assert "ContainerRun.run()->XPCClient.send(route:)" in e1.symbol_links
    assert (
        "s:17ContainerCommands12ContainerRunV3runyyYaKF->s:12ContainerXPC9XPCClientC4send5routeySS_tYaKF"
        in e1.symbol_links
    )
    assert "s:12ContainerXPC9XPCClientC10verifyPeeryyKF->c:@F@container_audit_token_pid" in e2.symbol_links

    manip_res = ManipulatorExtractionResult(
        nodes=[cmd_node, xpc_node, c_node],
        edges=[e1.model_copy(update={"symbol_links": []}), e2.model_copy(update={"symbol_links": []})],
        routes=[],
    )
    with compiler_ir_artifacts_scope(index_store=usr_json_path, sil=sil_path, llvm_ir=ll_path):
        assert COMPILER_IR_PLUGIN.manipulator_hook is not None
        COMPILER_IR_PLUGIN.manipulator_hook(repo, "Sources", manip_res)
        assert any("c:@F@container_audit_token_pid" in lk for lk in manip_res.edges[1].symbol_links)

        attach_zoom1_stratum_badges(repo, report, plugins=[COMPILER_IR_PLUGIN], strict_plugins=True)
        assert any(b.key == "ir_symbols" and b.count >= 1 for b in cmd_node.stratum_badges)

        compacted = build_node_stratum_drilldown(
            repo,
            report,
            cmd_node.id,
            zoom=2,
            unfiltered_ir=False,
            plugins=[COMPILER_IR_PLUGIN],
            strict_plugins=True,
        )
        unfiltered = build_node_stratum_drilldown(
            repo,
            report,
            cmd_node.id,
            zoom=2,
            unfiltered_ir=True,
            plugins=[COMPILER_IR_PLUGIN],
            strict_plugins=True,
        )

        assert compacted.collapsed_thunk_count >= 2
        assert compacted.compacted_node_count < compacted.raw_node_count
        assert any(e.id.startswith("s:bridged:") for e in compacted.edges)
        assert any(e.kind == "collapsed_thunks" for e in compacted.edges)
        comp_labels = {n.label for n in compacted.nodes}
        assert not any(lbl.startswith("protocol witness for ") for lbl in comp_labels)
        assert "swift_retain" not in comp_labels

        assert unfiltered.collapsed_thunk_count == 0
        assert unfiltered.compacted_node_count == unfiltered.raw_node_count
        unfiltered_labels = {n.label for n in unfiltered.nodes}
        assert any(lbl.startswith("protocol witness for ") for lbl in unfiltered_labels)
        assert "swift_retain" in unfiltered_labels

        c_drill = build_node_stratum_drilldown(
            repo,
            report,
            c_node.id,
            zoom=2,
            unfiltered_ir=False,
            plugins=[COMPILER_IR_PLUGIN],
            strict_plugins=True,
        )
        assert c_drill.collapsed_thunk_count >= 2  # vtable thunk + objc_release folded!
        c_targets = {n.label for n in c_drill.nodes}
        assert "-[NSXPCConnection auditToken]" in c_targets
        assert "rust_crate::verify_hash" in c_targets


def test_zoom1_content_digest_invariance_and_non_metal_silence(tmp_path: Path) -> None:
    repo = tmp_path / "clean_python_repo"
    (repo / "backend" / "app" / "services").mkdir(parents=True)
    (repo / "backend" / "schema.sql").write_text(
        "CREATE TABLE jobs (id INTEGER PRIMARY KEY, state TEXT NOT NULL);\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "services" / "worker.py").write_text(
        "def fetch_jobs(db):\n"
        '    return db.execute("SELECT id, state FROM jobs")\n',
        encoding="utf-8",
    )

    rep_without = _scan_python_metal_repo(repo, slug="inv-without", with_plugin=False)
    rep_with = _scan_python_metal_repo(repo, slug="inv-with", with_plugin=True)
    assert rep_with.content_digest == rep_without.content_digest
    assert rep_with.findings == rep_without.findings
    assert all(not n.stratum_badges for n in rep_with.nodes)
    assert METAL_AIR_EPISTEMIC_NOTE not in rep_with.scan_notes

    # Add a valid, seam-clean Metal shader + host dispatcher: Zoom-1 content_digest stays invariant!
    (repo / "shaders").mkdir()
    (repo / "shaders" / "scale.metal").write_text(
        "#include <metal_stdlib>\nusing namespace metal;\n"
        "[[kernel]] void vec_scale(device const float* x [[buffer(0)]], device float* y [[buffer(1)]],\n"
        "                          uint tid [[thread_position_in_grid]]) { y[tid] = x[tid] * 2.0f; }\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "services" / "gpu.swift").write_text(
        "import Metal\n"
        "func runScale(lib: MTLLibrary, enc: MTLComputeCommandEncoder, a: MTLBuffer, b: MTLBuffer) {\n"
        '    let fn = lib.makeFunction(name: "vec_scale")\n'
        "    enc.setBuffer(a, offset: 0, index: 0)\n"
        "    enc.setBuffer(b, offset: 0, index: 1)\n"
        "    enc.dispatchThreads(MTLSize(), threadsPerThreadgroup: MTLSize())\n"
        "}\n",
        encoding="utf-8",
    )
    rep_metal_without = _scan_python_metal_repo(repo, slug="metal-inv-0", with_plugin=False)
    rep_metal_with = _scan_python_metal_repo(repo, slug="metal-inv-1", with_plugin=True)
    assert rep_metal_with.content_digest == rep_metal_without.content_digest
    assert rep_metal_with.gate.verdict == "PASS"
    assert METAL_AIR_EPISTEMIC_NOTE in rep_metal_with.scan_notes



def test_mlx_metal_compute_seam_dynamic_jit_unverified_and_air_vs_agx_note(
    tmp_path: Path,
) -> None:
    """Verify `ml-explore/mlx@fc344c986c4169d99f76b5d95ae6b4a58a359a63` Metal seams & AIR vs AGX note."""
    repo = tmp_path / "mlx_repo"
    (repo / "mlx" / "backend" / "metal" / "kernels").mkdir(parents=True)
    (repo / "examples" / "metal_extension").mkdir(parents=True)
    (repo / "backend").mkdir(parents=True)
    (repo / "backend" / "schema.sql").write_text(
        "CREATE TABLE tensor_ops (id INTEGER PRIMARY KEY);\n", encoding="utf-8"
    )

    (repo / "mlx" / "backend" / "metal" / "device.cpp").write_text(
        "// Distilled from ml-explore/mlx@fc344c986c4169d99f76b5d95ae6b4a58a359a63\n"
        "#include <Metal/Metal.hpp>\n"
        "void dispatch_binary_dynamic(mlx::core::metal::Device& d, const std::string& op_name) {\n"
        '    auto* kernel = d.get_kernel("binary_" + op_name);\n'
        "    auto& enc = d.get_command_encoder(0);\n"
        "    enc.set_compute_pipeline_state(kernel);\n"
        "    for (int i = 0; i < 3; ++i) { enc.set_input_array(arr, i); }\n"
        "    enc.dispatch_threads(grid, tg);\n"
        "}\n",
        encoding="utf-8",
    )
    (repo / "mlx" / "backend" / "metal" / "custom_kernel.cpp").write_text(
        "#include <Metal/Metal.hpp>\n"
        "void launch_silu_and_mul(mlx::core::metal::Device& d) {\n"
        '    auto* kernel = d.get_kernel("bfloat16_silu_and_mul");\n'
        "    auto& compute_encoder = d.get_command_encoder(0);\n"
        "    compute_encoder.set_compute_pipeline_state(kernel);\n"
        "    compute_encoder.set_input_array(x, 0);\n"
        "    compute_encoder.set_input_array(w, 1);\n"
        "    compute_encoder.set_output_array(out, 2);\n"
        "    compute_encoder.dispatch_threadgroups(grid, tg);\n"
        "}\n",
        encoding="utf-8",
    )
    (repo / "mlx" / "backend" / "metal" / "kernels" / "binary.metal").write_text(
        "template <typename T, typename U, typename Op>\n"
        "[[kernel]] void binary_ss(\n"
        "    device const T* a [[buffer(0)]],\n"
        "    device const U* b [[buffer(1)]],\n"
        "    device U* out [[buffer(2)]],\n"
        "    uint index [[thread_position_in_grid]]) {\n"
        "    out[index] = Op()(a[0], b[0]);\n"
        "}\n"
        'instantiate_kernel("v_Add_float32", binary_ss, float, float, Add)\n',
        encoding="utf-8",
    )
    (repo / "examples" / "metal_extension" / "silu_and_mul.metal").write_text(
        "template <typename T>\n"
        "[[kernel]] void silu_and_mul(\n"
        "    device const T* x [[buffer(0)]],\n"
        "    device const T* w [[buffer(1)]],\n"
        "    device T* out [[buffer(2)]],\n"
        "    uint elem [[thread_position_in_grid]]) {\n"
        "    out[elem] = x[elem] * w[elem];\n"
        "}\n"
        'template [[host_name("bfloat16_silu_and_mul")]] [[kernel]] void silu_and_mul<bfloat16_t>(\n'
        "    device const bfloat16_t* x [[buffer(0)]],\n"
        "    device const bfloat16_t* w [[buffer(1)]],\n"
        "    device bfloat16_t* out [[buffer(2)]],\n"
        "    uint elem [[thread_position_in_grid]]);\n",
        encoding="utf-8",
    )

    objdump_path = tmp_path / "mlx_air_objdump.txt"
    objdump_path.write_text(
        "mlx.metallib:\tfile format MetalLib-AIR\n"
        "<bfloat16_silu_and_mul>:\n"
        "  define void @bfloat16_silu_and_mul(ptr addrspace(1) %0, ptr addrspace(1) %1, ptr addrspace(1) %2)\n"
        '  !0 = !{i32 0, !"air.buffer"}\n'
        '  !1 = !{i32 1, !"air.buffer"}\n'
        '  !2 = !{i32 2, !"air.buffer"}\n',
        encoding="utf-8",
    )
    mtlb_path = tmp_path / "mlx_raw.metallib"
    mtlb_path.write_bytes(
        _build_synthetic_mtlb(
            [
                ("bfloat16_silu_and_mul", 2, (0, 1, 2)),
                ("v_Add_float32", 2, (0, 1, 2)),
            ]
        )
    )
    parsed_mtlb = parse_metallib_artifact(mtlb_path)
    assert parsed_mtlb.format == "mtlb_binary"
    assert set(parsed_mtlb.exports) == {"bfloat16_silu_and_mul", "v_Add_float32"}
    assert parsed_mtlb.exports["bfloat16_silu_and_mul"].buffer_indices == (0, 1, 2)

    with pytest.raises(ValueError, match="MTLB"):
        parse_metallib_bytes(b"MTLB\x00\x01truncated")

    with compiler_ir_artifacts_scope(metallib=[objdump_path, mtlb_path]):
        report = _scan_python_metal_repo(repo, slug="mlx-metal-clean", with_plugin=True)
        assert [f for f in report.findings if f.rule_code.startswith("METAL-")] == []
        assert report.gate.verdict == "PASS"
        assert METAL_AIR_EPISTEMIC_NOTE in report.scan_notes
        assert "AIR" in METAL_AIR_EPISTEMIC_NOTE and "AGX" in METAL_AIR_EPISTEMIC_NOTE
        assert any("unverified (unresolved)" in nt for nt in report.scan_notes)

        dev_node = AtlasNode(
            id="m:mlx:device",
            tier="manipulate",
            subkind="service",
            label="MetalDevice",
            source_file="mlx/backend/metal/device.cpp",
            line=1,
            summary="MLX Metal device dispatcher",
        )
        cust_node = AtlasNode(
            id="m:mlx:custom_kernel",
            tier="manipulate",
            subkind="service",
            label="CustomKernel",
            source_file="mlx/backend/metal/custom_kernel.cpp",
            line=1,
            summary="MLX custom Metal kernel launcher",
        )
        report.nodes.extend([dev_node, cust_node])

        dyn_drill = build_node_stratum_drilldown(
            repo, report, dev_node.id, zoom=2, plugins=[COMPILER_IR_PLUGIN], strict_plugins=True
        )
        assert METAL_AIR_EPISTEMIC_NOTE in dyn_drill.notes
        assert any(
            n.kind == "metal_dynamic_kernel" and n.verification == "unverified"
            for n in dyn_drill.nodes
        )

        stat_drill = build_node_stratum_drilldown(
            repo, report, cust_node.id, zoom=2, plugins=[COMPILER_IR_PLUGIN], strict_plugins=True
        )
        assert any(
            n.kind == "metal_air_kernel"
            and n.label == "bfloat16_silu_and_mul"
            and n.verification == "verified"
            for n in stat_drill.nodes
        )


def test_metal_001_missing_static_kernel_across_swift_objcpp_cpp_python(tmp_path: Path) -> None:
    repo = tmp_path / "m001_repo"
    (repo / "backend" / "app" / "services").mkdir(parents=True)
    (repo / "shaders").mkdir()
    (repo / "backend" / "schema.sql").write_text(
        "CREATE TABLE frames (id INTEGER PRIMARY KEY);\n", encoding="utf-8"
    )
    (repo / "shaders" / "existing.metal").write_text(
        "[[kernel]] void present_kernel(device float* out [[buffer(0)]]) { out[0] = 1.0f; }\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "services" / "dispatch.swift").write_text(
        "import Metal\n"
        "func runMissing(lib: MTLLibrary) {\n"
        '    let fn = lib.makeFunction(name: "missing_swift_kernel")\n'
        "}\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "services" / "dispatch.mm").write_text(
        "#import <Metal/Metal.h>\n"
        "- (void)launch:(id<MTLLibrary>)lib {\n"
        '    id<MTLFunction> f = [lib newFunctionWithName:@"missing_objc_kernel"];\n'
        "}\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "services" / "dispatch_ext.py").write_text(
        "def launch_custom(mx):\n"
        '    return mx.fast.metal_kernel(name="missing_py_kernel")\n',
        encoding="utf-8",
    )

    report = _scan_python_metal_repo(repo, slug="metal-001-check", with_plugin=True)
    m001 = [f for f in report.findings if f.rule_code == "METAL-001"]
    assert len(m001) == 3
    assert all(f.severity == "blocking" and f.blocks_gate for f in m001)
    assert report.gate.verdict == "FAIL"
    titles = " ".join(f.title for f in m001)
    assert "missing_swift_kernel" in titles
    assert "missing_objc_kernel" in titles
    assert "missing_py_kernel" in titles


def test_metal_002_buffer_index_omission_and_duplicate_collision(tmp_path: Path) -> None:
    repo = tmp_path / "m002_repo"
    (repo / "backend" / "app" / "services").mkdir(parents=True)
    (repo / "shaders").mkdir()
    (repo / "backend" / "schema.sql").write_text(
        "CREATE TABLE dispatches (id INTEGER PRIMARY KEY);\n", encoding="utf-8"
    )
    (repo / "shaders" / "ops.metal").write_text(
        "[[kernel]] void fused_triad(\n"
        "    device const float* a [[buffer(0)]],\n"
        "    device const float* b [[buffer(1)]],\n"
        "    device float* out [[buffer(2)]],\n"
        "    uint tid [[thread_position_in_grid]]) { out[tid] = a[tid] + b[tid]; }\n"
        "[[kernel]] void copy_one(device float* dst [[buffer(0)]]) { dst[0] = 0.0f; }\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "services" / "bad_bindings.swift").write_text(
        "import Metal\n"
        "func encodeBroken(lib: MTLLibrary, enc: MTLComputeCommandEncoder, a: MTLBuffer, b: MTLBuffer) {\n"
        '    let fn = lib.makeFunction(name: "fused_triad")\n'
        "    enc.setBuffer(a, offset: 0, index: 0)\n"
        "    enc.setBuffer(b, offset: 0, index: 0)\n"  # collision on index 0 AND omits index 1 & 2!
        "    enc.dispatchThreads(MTLSize(), threadsPerThreadgroup: MTLSize())\n"
        "}\n"
        "func encodeTwoValidPasses(lib: MTLLibrary, enc: MTLComputeCommandEncoder, a: MTLBuffer, b: MTLBuffer) {\n"
        '    let f1 = lib.makeFunction(name: "copy_one")\n'
        "    enc.setBuffer(a, offset: 0, index: 0)\n"
        "    enc.dispatchThreads(MTLSize(), threadsPerThreadgroup: MTLSize())\n"
        "    enc.setBuffer(b, offset: 0, index: 0)\n"  # Reuses f1 pipeline across 2nd dispatch!
        "    enc.dispatchThreads(MTLSize(), threadsPerThreadgroup: MTLSize())\n"
        "}\n",
        encoding="utf-8",
    )

    report = _scan_python_metal_repo(repo, slug="metal-002-check", with_plugin=True)
    m002 = [f for f in report.findings if f.rule_code == "METAL-002"]
    assert len(m002) == 1
    assert "omits declared" in m002[0].title.lower()
    assert "[[buffer(1)]]" in m002[0].title and "[[buffer(2)]]" in m002[0].title
    assert all("encodeTwoValidPasses" not in f.detail for f in m002)
    assert report.gate.verdict == "FAIL"



def test_metal_003_struct_layout_mismatch_float3_16b_vs_12b_and_field_order(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "m003_repo"
    (repo / "backend" / "app" / "services").mkdir(parents=True)
    (repo / "shaders").mkdir()
    (repo / "backend" / "schema.sql").write_text(
        "CREATE TABLE particles (id INTEGER PRIMARY KEY);\n", encoding="utf-8"
    )

    # 1) Classic MSL float3 (16B, align 16) vs C++ float[3] (12B, align 4) + field-order drift
    #    + clean negative control using packed_float3 (12B, align 4)!
    (repo / "backend" / "app" / "services" / "sim_host.cpp").write_text(
        "#include <Metal/Metal.hpp>\n"
        "struct Vec3Only { float coords[3]; };\n"  # 12B, align 4
        "struct ParticleParams { float position[3]; float mass; };\n"  # 16B stride, mass@12
        "struct ReorderedUniforms { float scale; uint32_t count; };\n"
        "struct SafePackedParams { float position[3]; float mass; };\n"  # matches packed_float3!
        "void stepParticles(MTL::Library* lib, MTL::ComputeCommandEncoder* enc) {\n"
        '    auto* fn = lib->newFunction(MTL::String::string("step_particles", MTL::UTF8StringEncoding));\n'
        "    ParticleParams p{};\n"
        "    enc->setBytes(&p, sizeof(ParticleParams), 0);\n"
        "    enc->dispatchThreads(MTL::Size(), MTL::Size());\n"
        "}\n",
        encoding="utf-8",
    )
    (repo / "shaders" / "particles.metal").write_text(
        "#include <metal_stdlib>\nusing namespace metal;\n"
        "struct Vec3Only { float3 coords; };\n"  # 16B, align 16!
        "struct ParticleParams { float3 position; float mass; };\n"  # 32B stride, mass@16!
        "struct ReorderedUniforms { uint count; float scale; };\n"  # field order swapped!
        "struct SafePackedParams { packed_float3 position; float mass; };\n"  # 16B stride, mass@12!
        "[[kernel]] void step_particles(\n"
        "    constant ParticleParams& params [[buffer(0)]],\n"
        "    uint tid [[thread_position_in_grid]]) {}\n",
        encoding="utf-8",
    )

    report = _scan_python_metal_repo(repo, slug="metal-003-check", with_plugin=True)
    m003 = [f for f in report.findings if f.rule_code == "METAL-003"]
    assert len(m003) == 3
    assert all(f.severity == "blocking" and f.blocks_gate for f in m003)
    combined_details = "\n".join(f.detail for f in m003)
    assert "12B" in combined_details and "16B" in combined_details
    assert "32B" in combined_details
    assert "field order drift" in combined_details
    assert "SafePackedParams" not in combined_details
    assert report.gate.verdict == "FAIL"


def test_adversarial_symlink_rejection_depth_bound_redos_and_passive_no_subprocess(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # 1) Symlinked file & symlinked parent-directory rejection (including macOS /var vs /private/var)
    repo = tmp_path / "sym_repo"
    real_dir = repo / "real_artifacts"
    real_dir.mkdir(parents=True)
    (real_dir / "idx.json").write_text('{"symbols": []}', encoding="utf-8")
    (real_dir / "mod.sil").write_text("sil_stage canonical\n", encoding="utf-8")
    (real_dir / "mod.ll").write_text('source_filename = "a.c"\n', encoding="utf-8")
    (real_dir / "k.metal").write_text("[[kernel]] void k(device float* x [[buffer(0)]]) {}\n", encoding="utf-8")
    (real_dir / "k.air.txt").write_text("<k>:\n", encoding="utf-8")

    sym_dir = repo / "sym_artifacts"
    sym_dir.symlink_to(real_dir)
    sym_file = repo / "direct_link.sil"
    sym_file.symlink_to(real_dir / "mod.sil")

    ext_real = tmp_path / "ext_real"
    ext_real.mkdir()
    (ext_real / "ext.json").write_text('{"symbols": []}', encoding="utf-8")
    ext_sym = tmp_path / "ext_sym"
    ext_sym.symlink_to(ext_real)

    cand_repos = [repo]
    if str(repo).startswith("/private/var/"):
        var_alias = Path(str(repo).replace("/private/var/", "/var/", 1))
        if var_alias.exists():
            cand_repos.append(var_alias)

    for c_repo in cand_repos:
        for root_arg in (repo, repo.resolve()):
            with pytest.raises(ValueError, match="(?i)symlink"):
                parse_usr_index(c_repo / "sym_artifacts" / "idx.json", repo_root=root_arg)
            with pytest.raises(ValueError, match="(?i)symlink"):
                parse_sil_file(c_repo / "sym_artifacts" / "mod.sil", repo_root=root_arg)
            with pytest.raises(ValueError, match="(?i)symlink"):
                parse_llvm_ir_file(c_repo / "sym_artifacts" / "mod.ll", repo_root=root_arg)
            with pytest.raises(ValueError, match="(?i)symlink"):
                parse_metal_file(c_repo / "sym_artifacts" / "k.metal", repo_root=root_arg)
            with pytest.raises(ValueError, match="(?i)symlink"):
                parse_metallib_artifact(c_repo / "sym_artifacts" / "k.air.txt", repo_root=root_arg)

    with pytest.raises(ValueError, match="(?i)symlink"):
        parse_sil_file(sym_file, repo_root=repo)
    with pytest.raises(ValueError, match="(?i)symlink"):
        parse_usr_index(ext_sym / "ext.json")

    # 2) Depth <= 64 enforcement on JSON & YAML (no RecursionError)
    with pytest.raises(ValueError, match="depth|nested"):
        load_bounded_json_or_yaml('{"a":' * 150 + "1" + "}" * 150)
    deep_yaml = "\n".join(f"{'  ' * d}k{d}:" for d in range(80))
    with pytest.raises(ValueError, match="depth|nesting"):
        load_bounded_json_or_yaml(deep_yaml)

    # 3) ReDoS resilience on unterminated backslashes & 16 KB lines AND passive zero-subprocess check
    def _forbid_subprocess(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise AssertionError(f"Forbidden external subprocess call: {args}")

    monkeypatch.setattr(subprocess, "run", _forbid_subprocess)
    monkeypatch.setattr(subprocess, "Popen", _forbid_subprocess)

    slashes = "\\" * 80
    long_pad = "x" * 16000
    t0 = time.perf_counter()
    parse_sil_text(f'sil @"{slashes}unterminated : $@convention(thin) () -> () {{\n{long_pad}\n}}\n')
    parse_llvm_ir_text(f'define void @"{slashes}unterminated() {{\n  call void @foo({long_pad})\n}}\n')
    parse_metal_source(
        f'[[host_name("{slashes}unterminated]]\n'
        f"struct Huge {{ {'int ' * 2500}! }};\n"
        f"[[kernel]] void k({long_pad}) {{}}\n",
        source_file="adv.metal",
    )
    verify_metal_compute_seams(repo)
    elapsed = time.perf_counter() - t0
    assert elapsed < 0.25, f"Expected linear O(N) parsing (<0.25s), took {elapsed:.3f}s"
