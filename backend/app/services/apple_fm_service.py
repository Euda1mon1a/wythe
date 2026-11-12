"""Apple Intelligence (`FoundationModels`) on-device runner for macOS 26.0+."""

from __future__ import annotations

import hashlib
import json
import platform
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from app.core.config import load_settings
from app.schemas.atlas import OnDeviceEngineStatus

_apple_lock = threading.Lock()
_last_apple_finish_mono = 0.0
_apple_gap_sec = 0.25
_apple_reason_notes = {
    "appleIntelligenceNotEnabled": "Turn on Apple Intelligence in System Settings -> Apple Intelligence & Siri.",
    "modelNotReady": "macOS is still preparing its on-device Apple Intelligence model.",
    "deviceNotEligible": "Apple Intelligence is not available on this Mac.",
}


def _resolve_helper_dir() -> Path:
    db_url = load_settings().database_url
    if db_url.startswith("sqlite:///") and ":memory:" not in db_url:
        db_file = Path(db_url.removeprefix("sqlite:///")).resolve()
        bin_dir = db_file.parent / "bin"
    else:
        bin_dir = Path(tempfile.gettempdir()) / "wythe-apple-fm-bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    return bin_dir


def _ensure_apple_helper_binary() -> tuple[Path | None, str]:
    if sys.platform != "darwin" or platform.machine() != "arm64":
        return None, "Apple Intelligence requires an Apple silicon Mac."
    mac_ver = platform.mac_ver()[0] or "0"
    try:
        major = int(mac_ver.split(".")[0])
    except ValueError:
        major = 0
    if major < 26:
        return None, f"Apple Intelligence requires macOS 26+ (found macOS {mac_ver})."

    swift_src = Path(__file__).with_name("apple_fm_bridge.swift")
    if not swift_src.is_file():
        return None, "Missing apple_fm_bridge.swift helper source."

    digest = hashlib.sha256(swift_src.read_bytes()).hexdigest()
    bin_dir = _resolve_helper_dir()
    binary = bin_dir / "wythe-apple-fm"
    stamp = bin_dir / "wythe-apple-fm.sha256"

    if (
        binary.is_file()
        and stamp.is_file()
        and stamp.read_text(encoding="utf-8").strip() == digest
    ):
        return binary, ""

    staged = bin_dir / "wythe-apple-fm.tmp"
    cmd = [
        "xcrun",
        "--sdk",
        "macosx",
        "swiftc",
        "-target",
        "arm64-apple-macos26.0",
        "-O",
        "-suppress-warnings",
        "-parse-as-library",
        str(swift_src),
        "-o",
        str(staged),
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if proc.returncode != 0 or not staged.is_file():
            err_line = (proc.stderr or proc.stdout or "swiftc failed").strip().splitlines()[0]
            return None, f"Could not compile Apple helper ({err_line[:140]})."
        staged.chmod(0o755)
        subprocess.run(
            ["/usr/bin/codesign", "--force", "--sign", "-", str(staged)],
            capture_output=True,
            check=False,
        )
        staged.replace(binary)
        stamp.write_text(digest + "\n", encoding="utf-8")
        return binary, ""
    except OSError as exc:
        return None, f"Swift toolchain unavailable ({exc})."


def _invoke_apple_helper(binary: Path, message: dict[str, Any]) -> dict[str, Any]:
    raw_in = json.dumps(message).encode("utf-8")
    proc = subprocess.run([str(binary)], input=raw_in, capture_output=True, check=False)
    out = proc.stdout.decode("utf-8", errors="replace").strip()
    if not out:
        err = proc.stderr.decode("utf-8", errors="replace").strip()
        return {"ok": False, "error": err or f"Apple helper exited with {proc.returncode}."}
    try:
        parsed = json.loads(out)
        return parsed if isinstance(parsed, dict) else {"ok": False, "error": "Malformed helper JSON."}
    except ValueError:
        return {"ok": False, "error": "Unreadable JSON from Apple helper."}


def check_apple_engine_status() -> OnDeviceEngineStatus:
    """Probe macOS 26+/27 `FoundationModels` availability without network calls."""
    binary, build_note = _ensure_apple_helper_binary()
    if binary is None:
        return OnDeviceEngineStatus(
            engine="apple",
            label="Apple Intelligence",
            state="unavailable",
            note=build_note,
        )
    res = _invoke_apple_helper(binary, {"type": "hello"})
    if res.get("ok") and res.get("available"):
        return OnDeviceEngineStatus(
            engine="apple",
            label="Apple Intelligence",
            state="ready",
            model_id="apple-foundation-models-on-device",
            supports_vision=False,
            note="Apple Intelligence (`FoundationModels`) ready on this Mac.",
        )
    reason = str(res.get("reason") or "")
    note = _apple_reason_notes.get(reason) or str(res.get("error") or "Apple Intelligence unavailable.")
    return OnDeviceEngineStatus(
        engine="apple",
        label="Apple Intelligence",
        state="downloading" if reason == "modelNotReady" else "unavailable",
        note=note,
    )


def run_apple_engine_ask(instructions: str, prompt: str) -> tuple[str, list[str]]:
    """Serialize Apple FM calls with 250ms spacing & modelmanagerd rate-limit backoff."""
    global _last_apple_finish_mono
    binary, build_note = _ensure_apple_helper_binary()
    if binary is None:
        raise RuntimeError(build_note)

    with _apple_lock:
        for attempt in range(4):
            wait_gap = (_last_apple_finish_mono + _apple_gap_sec) - time.monotonic()
            if wait_gap > 0:
                time.sleep(wait_gap)
            res = _invoke_apple_helper(
                binary,
                {"type": "ask", "instructions": instructions, "prompt": prompt},
            )
            _last_apple_finish_mono = time.monotonic()
            if res.get("ok"):
                if isinstance(res.get("plainText"), str) and res["plainText"].strip():
                    return res["plainText"].strip(), []
                summary = str(res.get("summary") or "").strip()
                cause = str(res.get("rootCauseOrRole") or "").strip()
                step = str(res.get("safeNextStep") or "").strip()
                refs = [str(x) for x in (res.get("referencedNodes") or []) if str(x).strip()]
                md_parts = [p for p in [summary] if p]
                if cause:
                    md_parts.append(f"**Why / Architectural Role:** {cause}")
                if step:
                    md_parts.append(f"**Safe Next Step:** {step}")
                return "\n\n".join(md_parts), refs
            if res.get("code") == "rate-limited" and attempt < 3:
                cooldown_ms = int(res.get("retryAfterMs") or (2500 * (attempt + 1)))
                time.sleep(min(15.0, max(0.5, cooldown_ms / 1000.0)))
                continue
            raise RuntimeError(str(res.get("error") or "Apple Intelligence call failed."))
    raise RuntimeError("Apple Intelligence rate limit persisted after retries.")
