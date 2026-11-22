"""Static `tach.toml` horizontal module-boundary bridge for Wythe Tier-2 lineage.

Parses `tach` (`gauge-sh/tach`) configuration files via Python 3.12 `tomllib` without
invoking the `tach` CLI or importing target repository code. Maps extracted Python
manipulator nodes to their owning horizontal `tach` domain module and verifies both
AST imports under `source_roots` and intra-repo `calls_helper` edges against
`depends_on`, `layers`, `utility = true`, `visibility`, `strict`, and `[[interfaces]]`.
"""

from __future__ import annotations

import ast
import functools
import os
import stat
import tomllib
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from app.adapters.base import ManipulatorExtractionResult, RawCandidateFinding
from app.adapters.service_sources import source_files
from app.schemas.atlas import AtlasEdge, AtlasNode


@dataclass(frozen=True)
class TachModuleRule:
    """Normalized `[[modules]]` declaration from `tach.toml`."""

    path: str
    depends_on: tuple[str, ...] | None = None
    deprecated_deps: frozenset[str] = field(default_factory=frozenset)
    layer: str | None = None
    utility: bool = False
    strict: bool = False
    visibility: tuple[str, ...] | None = None


@dataclass(frozen=True)
class TachInterfaceRule:
    """Normalized `[[interfaces]]` public contract from `tach.toml`."""

    from_modules: tuple[str, ...]
    expose: tuple[str, ...]
    visibility: tuple[str, ...] | None = None
    exclusive: bool = False


@dataclass(frozen=True)
class TachConfig:
    """Parsed `tach.toml` boundary specification."""

    config_path: Path
    config_rel: str
    config_dir: Path
    source_roots: tuple[Path, ...]
    layers: tuple[str, ...]
    modules: dict[str, TachModuleRule]
    interfaces: tuple[TachInterfaceRule, ...]
    exclude_patterns: tuple[str, ...] = ()


_MAX_TACH_PATTERN_LEN = 256
_MAX_TACH_CANDIDATE_LEN = 2048
_MAX_NFA_STATES = 256
_MAX_REGEX_DEPTH = 16
_MAX_QUANTIFIER_REPEAT = 16
_MAX_TACH_FILE_BYTES = 512 * 1024


class _NfaBudgetError(Exception):
    pass


class _RegexSyntaxError(Exception):
    pass


def _read_bounded_regular_text(
    path: Path,
    *,
    max_bytes: int = _MAX_TACH_FILE_BYTES,
    encoding: str = "utf-8-sig",
) -> str:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError("Not a regular file")
        if st.st_size > max_bytes:
            raise ValueError(f"File exceeds {max_bytes}-byte limit")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(65536, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise ValueError(f"File exceeds {max_bytes}-byte limit")
    finally:
        os.close(fd)
    return b"".join(chunks).decode(encoding)


def _match_shorthand(code: str, ch: str) -> bool:
    if code == "d":
        return "0" <= ch <= "9"
    if code == "D":
        return not ("0" <= ch <= "9")
    if code == "w":
        return ch == "_" or ("a" <= ch <= "z") or ("A" <= ch <= "Z") or ("0" <= ch <= "9")
    if code == "W":
        return not (ch == "_" or ("a" <= ch <= "z") or ("A" <= ch <= "Z") or ("0" <= ch <= "9"))
    if code == "s":
        return ch in " \t\n\r\f\v"
    if code == "S":
        return ch not in " \t\n\r\f\v"
    return False


def _match_char_pred(pred: tuple[Any, ...], ch: str) -> bool:
    kind = pred[0]
    if kind == "lit":
        return ch == pred[1]
    if kind == "dot":
        return ch != "\n"
    if kind == "sh":
        return _match_shorthand(pred[1], ch)
    if kind == "cls":
        _, neg, chars, ranges, shorthands = pred
        hit = (
            ch in chars
            or any(lo <= ch <= hi for lo, hi in ranges)
            or any(_match_shorthand(sc, ch) for sc in shorthands)
        )
        return not hit if neg else hit
    return False


class _BoundedRegexParser:
    def __init__(self, pattern: str) -> None:
        self.p = pattern
        self.n = len(pattern)
        self.i = 0

    def parse(self) -> tuple[Any, ...]:
        node = self._parse_alt(0)
        if self.i != self.n:
            raise _RegexSyntaxError("unexpected trailing character")
        return node

    def _parse_alt(self, depth: int) -> tuple[Any, ...]:
        if depth > _MAX_REGEX_DEPTH:
            raise _NfaBudgetError("regex nesting depth exceeded")
        branches = [self._parse_concat(depth)]
        while self.i < self.n and self.p[self.i] == "|":
            self.i += 1
            branches.append(self._parse_concat(depth))
        if len(branches) == 1:
            return branches[0]
        return ("alt", tuple(branches))

    def _parse_concat(self, depth: int) -> tuple[Any, ...]:
        items: list[tuple[Any, ...]] = []
        while self.i < self.n and self.p[self.i] not in "|)":
            items.append(self._parse_quantified(depth))
        if not items:
            return ("empty",)
        if len(items) == 1:
            return items[0]
        return ("concat", tuple(items))

    def _parse_quantified(self, depth: int) -> tuple[Any, ...]:
        atom = self._parse_atom(depth)
        if atom[0] in ("anchor",):
            return atom
        while self.i < self.n and self.p[self.i] in "*+?{":
            ch = self.p[self.i]
            if ch == "*":
                self.i += 1
                if self.i < self.n and self.p[self.i] == "?":
                    self.i += 1
                atom = ("rep", atom, 0, None)
            elif ch == "+":
                self.i += 1
                if self.i < self.n and self.p[self.i] == "?":
                    self.i += 1
                atom = ("rep", atom, 1, None)
            elif ch == "?":
                self.i += 1
                if self.i < self.n and self.p[self.i] == "?":
                    self.i += 1
                atom = ("rep", atom, 0, 1)
            else:
                close = self.p.find("}", self.i + 1)
                if close == -1:
                    raise _RegexSyntaxError("unclosed {")
                body = self.p[self.i + 1 : close]
                if "," in body:
                    lo_s, hi_s = body.split(",", 1)
                    if not (lo_s.isascii() and lo_s.isdigit()) or (
                        hi_s and not (hi_s.isascii() and hi_s.isdigit())
                    ):
                        raise _RegexSyntaxError("invalid quantifier")
                    if len(lo_s) > 5 or (hi_s and len(hi_s) > 5):
                        raise _NfaBudgetError("quantifier bound exceeded")
                    lo = int(lo_s)
                    hi = int(hi_s) if hi_s else None
                    if hi is not None and hi < lo:
                        raise _RegexSyntaxError("invalid range")
                elif body.isascii() and body.isdigit():
                    if len(body) > 5:
                        raise _NfaBudgetError("quantifier bound exceeded")
                    lo = int(body)
                    hi = lo
                else:
                    raise _RegexSyntaxError("invalid quantifier")
                if lo > _MAX_QUANTIFIER_REPEAT or (hi is not None and hi > _MAX_QUANTIFIER_REPEAT):
                    raise _NfaBudgetError("quantifier bound exceeded")
                self.i = close + 1
                if self.i < self.n and self.p[self.i] == "?":
                    self.i += 1
                atom = ("rep", atom, lo, hi)
        return atom

    def _parse_atom(self, depth: int) -> tuple[Any, ...]:
        ch = self.p[self.i]
        if ch in "*+?":
            raise _RegexSyntaxError("nothing to repeat")
        if ch == "(":
            self.i += 1
            if self.i < self.n and self.p[self.i] == "?":
                if self.p[self.i : self.i + 2] == "?:":
                    self.i += 2
                else:
                    raise _NfaBudgetError("unsupported group extension")
            inner = self._parse_alt(depth + 1)
            if self.i >= self.n or self.p[self.i] != ")":
                raise _RegexSyntaxError("unclosed group")
            self.i += 1
            return inner
        if ch == "[":
            return self._parse_class()
        if ch == ".":
            self.i += 1
            return ("dot",)
        if ch == "^":
            self.i += 1
            return ("anchor", "^")
        if ch == "$":
            self.i += 1
            return ("anchor", "$")
        if ch == "\\":
            self.i += 1
            if self.i >= self.n:
                raise _RegexSyntaxError("trailing backslash")
            esc = self.p[self.i]
            self.i += 1
            if esc in "dDwWsS":
                return ("sh", esc)
            if "1" <= esc <= "9":
                raise _NfaBudgetError("backreference unsupported")
            return ("lit", esc)
        self.i += 1
        return ("lit", ch)

    def _parse_class(self) -> tuple[Any, ...]:
        self.i += 1  # skip '['
        neg = False
        if self.i < self.n and self.p[self.i] == "^":
            neg = True
            self.i += 1
        chars: set[str] = set()
        ranges: list[tuple[str, str]] = []
        shorthands: list[str] = []
        items: list[tuple[str, str]] = []  # ("char", c) or ("sh", code)
        first = True
        while self.i < self.n:
            c = self.p[self.i]
            if c == "]" and not first:
                self.i += 1
                break
            first = False
            if c == "\\":
                self.i += 1
                if self.i >= self.n:
                    raise _RegexSyntaxError("trailing backslash in class")
                esc = self.p[self.i]
                self.i += 1
                if esc in "dDwWsS":
                    items.append(("sh", esc))
                else:
                    items.append(("char", esc))
            else:
                self.i += 1
                items.append(("char", c))
        else:
            raise _RegexSyntaxError("unclosed character class")

        idx = 0
        while idx < len(items):
            kind, val = items[idx]
            if (
                kind == "char"
                and idx + 2 < len(items)
                and items[idx + 1] == ("char", "-")
                and items[idx + 2][0] == "char"
            ):
                hi = items[idx + 2][1]
                if ord(val) > ord(hi):
                    raise _RegexSyntaxError("bad character range")
                ranges.append((val, hi))
                idx += 3
            elif kind == "sh":
                shorthands.append(val)
                idx += 1
            else:
                chars.add(val)
                idx += 1
        return ("cls", neg, frozenset(chars), tuple(ranges), tuple(shorthands))


@dataclass
class _NfaState:
    eps: list[int] = field(default_factory=list)
    anchor: str | None = None
    edge: tuple[tuple[Any, ...], int] | None = None


def _compile_nfa(ast_node: tuple[Any, ...]) -> tuple[list[_NfaState], int, int]:
    states: list[_NfaState] = []

    def _new() -> int:
        if len(states) >= _MAX_NFA_STATES:
            raise _NfaBudgetError("NFA state limit exceeded")
        states.append(_NfaState())
        return len(states) - 1

    def _build(node: tuple[Any, ...]) -> tuple[int, int]:
        kind = node[0]
        if kind == "empty":
            s = _new()
            return s, s
        if kind == "anchor":
            s = _new()
            e = _new()
            states[s].anchor = node[1]
            states[s].eps.append(e)
            return s, e
        if kind in ("lit", "dot", "sh", "cls"):
            s = _new()
            e = _new()
            states[s].edge = (node, e)
            return s, e
        if kind == "concat":
            items = node[1]
            start, end = _build(items[0])
            for nxt in items[1:]:
                ns, ne = _build(nxt)
                states[end].eps.append(ns)
                end = ne
            return start, end
        if kind == "alt":
            s = _new()
            e = _new()
            for br in node[1]:
                bs, be = _build(br)
                states[s].eps.append(bs)
                states[be].eps.append(e)
            return s, e
        if kind == "rep":
            _, sub, lo, hi = node
            if lo == 0 and hi == 1:
                s = _new()
                e = _new()
                bs, be = _build(sub)
                states[s].eps.extend([bs, e])
                states[be].eps.append(e)
                return s, e
            if lo == 0 and hi is None:
                s = _new()
                e = _new()
                bs, be = _build(sub)
                states[s].eps.extend([bs, e])
                states[be].eps.extend([bs, e])
                return s, e
            if lo == 1 and hi is None:
                s = _new()
                e = _new()
                bs, be = _build(sub)
                states[s].eps.append(bs)
                states[be].eps.extend([bs, e])
                return s, e
            cur_s = _new()
            cur_e = cur_s
            for _ in range(lo):
                bs, be = _build(sub)
                states[cur_e].eps.append(bs)
                cur_e = be
            if hi is None:
                star_s, star_e = _build(("rep", sub, 0, None))
                states[cur_e].eps.append(star_s)
                cur_e = star_e
            else:
                for _ in range(hi - lo):
                    opt_s, opt_e = _build(("rep", sub, 0, 1))
                    states[cur_e].eps.append(opt_s)
                    cur_e = opt_e
            return cur_s, cur_e
        raise _NfaBudgetError("unknown AST node")

    start_id, end_id = _build(ast_node)
    return states, start_id, end_id


@dataclass(frozen=True)
class _FrozenNfaState:
    eps: tuple[int, ...] = ()
    anchor: str | None = None
    edge: tuple[tuple[Any, ...], int] | None = None


@functools.lru_cache(maxsize=2048)
def _compile_cached_nfa(pattern: str) -> tuple[tuple[_FrozenNfaState, ...], int, int]:
    ast_node = _BoundedRegexParser(pattern).parse()
    states, start_id, end_id = _compile_nfa(ast_node)
    frozen = tuple(_FrozenNfaState(tuple(s.eps), s.anchor, s.edge) for s in states)
    return frozen, start_id, end_id


def _thompson_nfa_fullmatch(pattern: str, candidate: str) -> bool:
    states, start_id, end_id = _compile_cached_nfa(pattern)
    n = len(candidate)

    def _eps_closure(seed: set[int], pos: int) -> set[int]:
        seen = set(seed)
        q = deque(seed)
        while q:
            sid = q.popleft()
            st = states[sid]
            if st.anchor == "^" and pos != 0:
                continue
            if st.anchor == "$" and pos != n:
                continue
            for nxt in st.eps:
                if nxt not in seen:
                    seen.add(nxt)
                    q.append(nxt)
        return seen

    active = _eps_closure({start_id}, 0)
    for idx, ch in enumerate(candidate):
        nxt_seed: set[int] = set()
        for sid in active:
            edge = states[sid].edge
            if edge is not None and _match_char_pred(edge[0], ch):
                nxt_seed.add(edge[1])
        if not nxt_seed:
            return False
        active = _eps_closure(nxt_seed, idx + 1)
    return end_id in active


@functools.lru_cache(maxsize=2048)
def _compile_glob_tokens(pattern: str) -> tuple[tuple[Any, ...], ...]:
    tokens: list[tuple[Any, ...]] = []
    i = 0
    pn = len(pattern)
    while i < pn:
        ch = pattern[i]
        if ch == "*":
            if not tokens or tokens[-1][0] != "star":
                tokens.append(("star",))
            i += 1
        elif ch == "?":
            tokens.append(("any",))
            i += 1
        elif ch == "[":
            end = pattern.find("]", i + 1)
            if end == -1:
                tokens.append(("lit", "["))
                i += 1
            else:
                body = pattern[i + 1 : end]
                neg = body.startswith(("!", "^"))
                if neg:
                    body = body[1:]
                if not body:
                    tokens.append(("lit", "["))
                    i += 1
                else:
                    chars: set[str] = set()
                    ranges: list[tuple[str, str]] = []
                    j = 0
                    while j < len(body):
                        if j + 2 < len(body) and body[j + 1] == "-":
                            lo, hi = body[j], body[j + 2]
                            if ord(lo) <= ord(hi):
                                ranges.append((lo, hi))
                            j += 3
                        else:
                            chars.add(body[j])
                            j += 1
                    tokens.append(("cls", neg, frozenset(chars), tuple(ranges), ()))
                    i = end + 1
        else:
            tokens.append(("lit", ch))
            i += 1
    return tuple(tokens)


def _dp_glob_match(pattern: str, candidate: str) -> bool:
    # Linear-time glob matcher supporting '*', '?', and '[...]' without backtracking regex.
    tokens = _compile_glob_tokens(pattern)
    ti = 0
    si = 0
    tn = len(tokens)
    sn = len(candidate)
    star_ti = -1
    star_si = 0
    while si < sn:
        if ti < tn and tokens[ti][0] == "star":
            star_ti = ti
            star_si = si
            ti += 1
        elif ti < tn and (
            tokens[ti][0] == "any" or _match_char_pred(tokens[ti], candidate[si])
        ):
            ti += 1
            si += 1
        elif star_ti != -1:
            ti = star_ti + 1
            star_si += 1
            si = star_si
        else:
            return False
    while ti < tn and tokens[ti][0] == "star":
        ti += 1
    return ti == tn


def _pattern_matches(pattern: str, candidate: str) -> bool:
    if pattern in ("*", ".*"):
        return True
    if pattern == candidate:
        return True
    if len(pattern) > _MAX_TACH_PATTERN_LEN or len(candidate) > _MAX_TACH_CANDIDATE_LEN:
        return False
    try:
        if _thompson_nfa_fullmatch(pattern, candidate):
            return True
    except _NfaBudgetError:
        return False
    except _RegexSyntaxError:
        pass
    return _dp_glob_match(pattern, candidate)


def _has_safe_path_segments(path_or_str: Path | str, *, max_segment_bytes: int = 255) -> bool:
    if isinstance(path_or_str, str):
        if not path_or_str or "\x00" in path_or_str:
            return False
        path_obj = Path(path_or_str)
    else:
        raw_s = str(path_or_str)
        if not raw_s or "\x00" in raw_s:
            return False
        path_obj = path_or_str
    anchor = path_obj.anchor
    for part in path_obj.parts:
        if part == anchor or part in ("", "."):
            continue
        if "\x00" in part or len(part.encode("utf-8", errors="surrogateescape")) > max_segment_bytes:
            return False
    return True


def _find_tach_toml(
    repo_root: Path,
    backend_subdir: str,
    *,
    skipped_notes: list[str] | None = None,
) -> Path | None:
    if "\x00" in str(repo_root):
        return None
    try:
        resolved_root = repo_root.resolve()
    except (OSError, ValueError):
        return None
    candidates = [repo_root / "tach.toml"]
    clean_sub = backend_subdir.strip().strip("/")
    if clean_sub and clean_sub != "." and _has_safe_path_segments(clean_sub):
        candidates.append(repo_root / clean_sub / "tach.toml")
    for cand in candidates:
        if not _has_safe_path_segments(cand):
            continue
        try:
            is_sym = cand.is_symlink()
            exists = cand.exists()
            is_file = cand.is_file()
        except (OSError, ValueError):
            continue
        if is_sym or (exists and not is_file):
            if skipped_notes is not None:
                skipped_notes.append(
                    f"Tach boundary parse skipped ({cand.name}): symlink or non-regular file."
                )
            continue
        if not exists:
            continue
        try:
            resolved = cand.resolve()
            in_root = resolved.is_relative_to(resolved_root)
        except (OSError, ValueError):
            continue
        if in_root:
            return resolved
        if skipped_notes is not None:
            skipped_notes.append(
                f"Tach boundary parse skipped ({cand.name}): escapes repository root."
            )
    return None


def _parse_depends_on(raw_deps: object) -> tuple[tuple[str, ...] | None, frozenset[str]]:
    if raw_deps is None:
        return None, frozenset()
    if not isinstance(raw_deps, list):
        return (), frozenset()
    allowed: list[str] = []
    deprecated: set[str] = set()
    for item in raw_deps:
        if isinstance(item, str) and item.strip():
            allowed.append(item.strip())
        elif isinstance(item, dict):
            dep_path = item.get("path")
            if isinstance(dep_path, str) and dep_path.strip():
                clean = dep_path.strip()
                allowed.append(clean)
                if bool(item.get("deprecated", False)):
                    deprecated.add(clean)
    return tuple(dict.fromkeys(allowed)), frozenset(deprecated)


def _as_str_tuple(raw: object) -> tuple[str, ...] | None:
    if raw is None:
        return None
    if isinstance(raw, str):
        return (raw.strip(),) if raw.strip() else ()
    if isinstance(raw, list):
        return tuple(x.strip() for x in raw if isinstance(x, str) and x.strip())
    return ()


def parse_tach_toml(config_path: Path, repo_root: Path) -> TachConfig:
    """Parse a validated `tach.toml` file into `TachConfig`."""
    resolved_root = repo_root.resolve()
    try:
        data = tomllib.loads(
            _read_bounded_regular_text(
                config_path, max_bytes=_MAX_TACH_FILE_BYTES, encoding="utf-8-sig"
            )
        )
    except RecursionError as exc:
        raise ValueError(f"Tach configuration exceeds maximum nesting depth: {exc}") from exc
    config_dir = config_path.parent.resolve()
    config_rel = config_path.resolve().relative_to(resolved_root).as_posix()

    raw_roots = data.get("source_roots")
    if raw_roots is None:
        single_root = data.get("source_root", ".")
        raw_roots = [single_root] if isinstance(single_root, str) else ["."]
    roots: list[Path] = []
    if isinstance(raw_roots, list):
        for entry in raw_roots:
            if not isinstance(entry, str) or not entry.strip():
                continue
            entry_s = entry.strip()
            if not _has_safe_path_segments(entry_s):
                continue
            try:
                cand = (config_dir / entry_s).resolve()
                if cand.is_relative_to(resolved_root) and cand.is_dir() and not cand.is_symlink():
                    roots.append(cand)
            except (OSError, ValueError):
                continue
    if not roots:
        roots.append(config_dir)
    # Longest path first so nested source roots bind to their most specific root.
    roots.sort(key=lambda p: len(p.parts), reverse=True)

    layers = _as_str_tuple(data.get("layers")) or ()
    excludes = _as_str_tuple(data.get("exclude")) or ()

    modules: dict[str, TachModuleRule] = {}
    raw_modules = data.get("modules", [])
    if not isinstance(raw_modules, list):
        raise TypeError("`modules` in tach.toml must be an array of tables")
    for entry in raw_modules:
            if not isinstance(entry, dict):
                continue
            mod_paths: list[str] = []
            if isinstance(entry.get("path"), str) and entry["path"].strip():
                mod_paths.append(entry["path"].strip())
            elif isinstance(entry.get("paths"), list):
                mod_paths.extend(
                    p.strip() for p in entry["paths"] if isinstance(p, str) and p.strip()
                )
            deps, dep_depr = _parse_depends_on(entry.get("depends_on"))
            layer_val = entry.get("layer")
            layer_str = layer_val.strip() if isinstance(layer_val, str) and layer_val.strip() else None
            vis = _as_str_tuple(entry.get("visibility"))
            for mpath in mod_paths:
                modules[mpath] = TachModuleRule(
                    path=mpath,
                    depends_on=deps,
                    deprecated_deps=dep_depr,
                    layer=layer_str,
                    utility=bool(entry.get("utility", False)),
                    strict=bool(entry.get("strict", False)),
                    visibility=vis,
                )

    interfaces: list[TachInterfaceRule] = []
    raw_ifaces = data.get("interfaces", [])
    if not isinstance(raw_ifaces, list):
        raise TypeError("`interfaces` in tach.toml must be an array of tables")
    for entry in raw_ifaces:
        if not isinstance(entry, dict):
            continue
        from_mods = _as_str_tuple(entry.get("from")) or ()
        expose_list = _as_str_tuple(entry.get("expose")) or ()
        if not from_mods:
            continue
        interfaces.append(
            TachInterfaceRule(
                from_modules=from_mods,
                expose=expose_list,
                visibility=_as_str_tuple(entry.get("visibility")),
                exclusive=bool(entry.get("exclusive", False)),
            )
        )

    return TachConfig(
        config_path=config_path,
        config_rel=config_rel,
        config_dir=config_dir,
        source_roots=tuple(dict.fromkeys(roots)),
        layers=layers,
        modules=modules,
        interfaces=tuple(interfaces),
        exclude_patterns=excludes,
    )


def _sr_prefix_for_root(sr: Path, config_dir: Path) -> str:
    if sr == config_dir or not sr.is_relative_to(config_dir):
        return ""
    return ".".join(sr.relative_to(config_dir).parts)


def _dotted_for_file(abs_file: Path, config: TachConfig) -> tuple[str, str, bool] | None:
    resolved = abs_file.resolve()
    for sr in config.source_roots:
        if not resolved.is_relative_to(sr):
            continue
        rel = resolved.relative_to(sr)
        if rel.suffix != ".py":
            return None
        parts = list(rel.with_suffix("").parts)
        is_pkg_init = bool(parts and parts[-1] == "__init__")
        if is_pkg_init:
            parts = parts[:-1]
        dotted = ".".join(parts) if parts else "<root>"
        return dotted, _sr_prefix_for_root(sr, config.config_dir), is_pkg_init
    return None


def resolve_owning_tach_module(
    mod_dotted: str,
    config: TachConfig,
    sr_prefix: str = "",
) -> str | None:
    """Return the most specific declared `tach` module owning `mod_dotted`."""
    if mod_dotted == "<root>":
        return "<root>" if "<root>" in config.modules else None
    candidates = [mod_dotted]
    if sr_prefix and not mod_dotted.startswith(f"{sr_prefix}."):
        candidates.append(f"{sr_prefix}.{mod_dotted}")
    best: str | None = None
    for cand in candidates:
        for declared in config.modules:
            if declared == "<root>":
                continue
            if (cand == declared or cand.startswith(f"{declared}.")) and (
                best is None or len(declared) > len(best)
            ):
                best = declared
        if best is not None:
            return best
    return "<root>" if "<root>" in config.modules else None


def _extract_dunder_all(tree: ast.Module) -> frozenset[str] | None:
    for stmt in tree.body:
        targets: list[ast.expr] = []
        val: ast.expr | None = None
        if isinstance(stmt, ast.Assign):
            targets = list(stmt.targets)
            val = stmt.value
        elif isinstance(stmt, ast.AnnAssign):
            targets = [stmt.target]
            val = stmt.value
        if any(isinstance(t, ast.Name) and t.id == "__all__" for t in targets) and isinstance(
            val, (ast.List, ast.Tuple, ast.Set)
        ):
            items = [
                elt.value
                for elt in val.elts
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
            ]
            return frozenset(items)
    return None


def _evaluate_import_boundary(
    *,
    caller_owner: str,
    callee_owner: str,
    target_mod: str,
    rel_member: str | None,
    config: TachConfig,
    pkg_dunder_all: dict[str, frozenset[str] | None],
) -> tuple[str, str, str] | None:
    if caller_owner == callee_owner:
        return None
    caller_rule = config.modules.get(caller_owner)
    callee_rule = config.modules.get(callee_owner)
    if caller_rule is None or callee_rule is None:
        return None

    if callee_rule.visibility is not None and not any(
        _pattern_matches(v, caller_owner) for v in callee_rule.visibility
    ):
        allowed_vis = ", ".join(f"`{v}`" for v in callee_rule.visibility) or "none"
        return (
            f"Forbidden tach import `{caller_owner}` -> `{callee_owner}` (visibility restricted)",
            (
                f"`{caller_owner}` imports `{target_mod}`, but `{callee_owner}` restricts "
                f"visibility in `{config.config_rel}` to: {allowed_vis}."
            ),
            (
                f"Route calls through a module authorized by `{callee_owner}` visibility or "
                f"update `{config.config_rel}` if the architectural boundary changed intentionally."
            ),
        )

    if not callee_rule.utility:
        if caller_rule.depends_on is not None and callee_owner not in caller_rule.depends_on:
            allowed_deps = ", ".join(f"`{d}`" for d in caller_rule.depends_on) or "none"
            return (
                f"Forbidden cross-domain import `{caller_owner}` -> `{callee_owner}`",
                (
                    f"`{caller_owner}` imports `{target_mod}` owned by `{callee_owner}`, which is "
                    f"not in `{caller_owner}` `depends_on` ({allowed_deps}) in "
                    f"`{config.config_rel}`."
                ),
                (
                    f"Remove the cross-domain import from `{caller_owner}` to `{callee_owner}` or "
                    f"expose a shared domain/service contract permitted by `{config.config_rel}`."
                ),
            )
        if (
            config.layers
            and caller_rule.layer in config.layers
            and callee_rule.layer in config.layers
            and config.layers.index(caller_rule.layer) > config.layers.index(callee_rule.layer)
            and callee_owner not in (caller_rule.depends_on or ())
        ):
            return (
                (
                    f"Forbidden upward layer import `{caller_owner}` ({caller_rule.layer}) -> "
                    f"`{callee_owner}` ({callee_rule.layer})"
                ),
                (
                    f"`{caller_owner}` in lower layer `{caller_rule.layer}` imports "
                    f"`{target_mod}` in higher layer `{callee_rule.layer}` (`{config.config_rel}`)."
                ),
                "Invert the dependency so lower layers never import higher presentation/API layers.",
            )

    matching_ifaces = [
        iface
        for iface in config.interfaces
        if any(_pattern_matches(fm, callee_owner) for fm in iface.from_modules)
    ]
    if matching_ifaces:
        visible_ifaces = [
            iface
            for iface in matching_ifaces
            if iface.visibility is None
            or any(_pattern_matches(v, caller_owner) for v in iface.visibility)
        ]
        if not visible_ifaces:
            return (
                f"Unexposed tach interface `{caller_owner}` -> `{callee_owner}`",
                (
                    f"`{callee_owner}` defines `[[interfaces]]` in `{config.config_rel}`, and "
                    f"none are visible to `{caller_owner}`."
                ),
                f"Import only public interfaces visible to `{caller_owner}`.",
            )
        if rel_member is not None:
            exposed_ok = (
                any(exp in ("*", ".*") for iface in visible_ifaces for exp in iface.expose)
                if rel_member == "*"
                else any(
                    _pattern_matches(exp, rel_member)
                    for iface in visible_ifaces
                    for exp in iface.expose
                )
            )
            if not exposed_ok:
                shown = ", ".join(
                    f"`{exp}`" for iface in visible_ifaces for exp in iface.expose
                ) or "none"
                return (
                    f"Import bypasses `{callee_owner}` public `[[interfaces]]` (`{rel_member}`)",
                    (
                        f"`{caller_owner}` imports unexposed member `{callee_owner}.{rel_member}`; "
                        f"`{config.config_rel}` `[[interfaces]]` exposes only: {shown}."
                    ),
                    f"Import via `{callee_owner}`'s exposed public interface symbols ({shown}).",
                )
    elif callee_rule.strict and callee_owner != "<root>":
        deep_sub = target_mod != callee_owner and target_mod.startswith(f"{callee_owner}.")
        init_all = pkg_dunder_all.get(callee_owner)
        unlisted_sym = (
            rel_member is not None
            and "." not in rel_member
            and init_all is not None
            and rel_member not in init_all
        )
        if deep_sub or unlisted_sym:
            member_desc = f"{callee_owner}.{rel_member}" if rel_member else target_mod
            return (
                f"Strict tach module boundary bypassed (`{member_desc}`)",
                (
                    f"`{caller_owner}` imports `{member_desc}` directly, but `{callee_owner}` "
                    f"sets `strict = true` in `{config.config_rel}`."
                ),
                f"Import public symbols exported at `{callee_owner}` package root (`__all__`).",
            )
    return None


def _is_excluded(rel_posix: str, exclude_patterns: tuple[str, ...]) -> bool:
    for pat in exclude_patterns:
        clean = pat.strip().strip("/")
        if not clean:
            continue
        if rel_posix == clean or rel_posix.startswith(f"{clean}/") or _pattern_matches(
            clean, rel_posix
        ):
            return True
    return False


def _sub_prefix_under_owner(base_mod: str, callee_owner: str, sr_prefix: str) -> str:
    if callee_owner == "<root>":
        return "" if base_mod == "<root>" else base_mod
    norm_base = base_mod
    if sr_prefix and callee_owner.startswith(f"{sr_prefix}.") and not base_mod.startswith(
        f"{sr_prefix}."
    ):
        norm_base = f"{sr_prefix}.{base_mod}"
    if norm_base == callee_owner:
        return ""
    if norm_base.startswith(f"{callee_owner}."):
        return norm_base[len(callee_owner) + 1 :]
    return ""


def _type_checking_excluded_ids(tree: ast.Module) -> set[int]:
    """Return AST node IDs inside `if TYPE_CHECKING:` / `if typing.TYPE_CHECKING:` blocks."""
    excluded: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        test = node.test
        is_tc = (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (
            isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"
        )
        if is_tc:
            for sub in node.body:
                excluded.update(id(c) for c in ast.walk(sub))
    return excluded


def _iter_ast_import_refs(
    tree: ast.Module,
    mod_dotted: str,
    sr_prefix: str,
    is_pkg_init: bool,
    config: TachConfig,
    known_modules: set[str],
) -> list[tuple[int, str, str, str | None, str | None]]:
    """Return `(lineno, callee_owner, target_mod, rel_member, imported_sym)` for imports."""
    refs: list[tuple[int, str, str, str | None, str | None]] = []
    mod_parts = [] if mod_dotted == "<root>" else mod_dotted.split(".")
    pkg_parts = mod_parts if is_pkg_init else mod_parts[:-1]
    imported_mod_aliases: dict[str, str] = {}
    excluded = _type_checking_excluded_ids(tree)

    for node in ast.walk(tree):
        if id(node) in excluded:
            continue
        if isinstance(node, ast.Import):
            for alias in node.names:
                raw_name = alias.name.strip()
                if not raw_name:
                    continue
                owner = resolve_owning_tach_module(raw_name, config, sr_prefix)
                if owner is None:
                    continue
                sub = _sub_prefix_under_owner(raw_name, owner, sr_prefix)
                refs.append((node.lineno, owner, raw_name, sub or None, None))
                bind_name = alias.asname or raw_name
                imported_mod_aliases[bind_name] = raw_name
        elif isinstance(node, ast.ImportFrom):
            if node.level > 0:
                if node.level - 1 > len(pkg_parts):
                    continue
                anchor = pkg_parts[: len(pkg_parts) - (node.level - 1)]
                tail = node.module.split(".") if node.module else []
                base_mod = ".".join([*anchor, *tail]) or "<root>"
            else:
                if not node.module:
                    continue
                base_mod = node.module.strip()

            for alias in node.names:
                sym = alias.name.strip()
                if not sym:
                    continue
                cand_submod = sym if base_mod == "<root>" else f"{base_mod}.{sym}"
                submod_exists = sym != "*" and (
                    cand_submod in known_modules
                    or cand_submod in config.modules
                    or (bool(sr_prefix) and f"{sr_prefix}.{cand_submod}" in config.modules)
                )
                if submod_exists:
                    owner = resolve_owning_tach_module(cand_submod, config, sr_prefix)
                    if owner is not None:
                        sub = _sub_prefix_under_owner(cand_submod, owner, sr_prefix)
                        refs.append((node.lineno, owner, cand_submod, sub or None, None))
                        imported_mod_aliases[alias.asname or sym] = cand_submod
                    continue

                owner = resolve_owning_tach_module(base_mod, config, sr_prefix)
                if owner is None:
                    continue
                sub = _sub_prefix_under_owner(base_mod, owner, sr_prefix)
                rel_member = f"{sub}.{sym}" if sub else sym
                concrete_sym = None if sym == "*" else sym
                refs.append((node.lineno, owner, base_mod, rel_member, concrete_sym))

    if imported_mod_aliases and config.interfaces:
        for node in ast.walk(tree):
            if id(node) in excluded or not isinstance(node, ast.Attribute):
                continue
            chain = _dotted_expr(node.value)
            if chain is None:
                continue
            aliased_mod = imported_mod_aliases.get(chain)
            if not aliased_mod:
                continue
            owner = resolve_owning_tach_module(aliased_mod, config, sr_prefix)
            if owner is None:
                continue
            sub = _sub_prefix_under_owner(aliased_mod, owner, sr_prefix)
            rel_member = f"{sub}.{node.attr}" if sub else node.attr
            refs.append((node.lineno, owner, aliased_mod, rel_member, None))

    return refs


def _extract_pkg_reexports(tree: ast.Module, pkg_dotted: str) -> dict[str, tuple[str, str]]:
    """Map exported symbol name -> `(target_module_dotted, original_symbol)` in `__init__.py`."""
    pkg_parts = [] if pkg_dotted == "<root>" else pkg_dotted.split(".")
    reexports: dict[str, tuple[str, str]] = {}
    for node in tree.body:
        if not isinstance(node, ast.ImportFrom):
            continue
        if node.level > 0:
            if node.level - 1 > len(pkg_parts):
                continue
            anchor = pkg_parts[: len(pkg_parts) - (node.level - 1)]
            tail = node.module.split(".") if node.module else []
            base_mod = ".".join([*anchor, *tail]) or "<root>"
        else:
            if not node.module:
                continue
            base_mod = node.module.strip()
        for alias in node.names:
            orig_sym = alias.name.strip()
            if not orig_sym or orig_sym == "*":
                continue
            bound = (alias.asname or orig_sym).strip()
            reexports[bound] = (base_mod, orig_sym)
    return reexports


def _resolve_import_target_file(
    target_mod: str,
    imported_sym: str | None,
    sr_prefix: str,
    mod_to_rel: dict[str, str],
    pkg_reexports: dict[str, dict[str, tuple[str, str]]],
    py_nodes_by_file: dict[str, list[AtlasNode]],
) -> tuple[str | None, str | None]:
    cands = [target_mod]
    if sr_prefix and not target_mod.startswith(f"{sr_prefix}."):
        cands.append(f"{sr_prefix}.{target_mod}")
    dst_rel = next((mod_to_rel[m] for m in cands if m in mod_to_rel), None)
    if dst_rel is None:
        return None, imported_sym
    if imported_sym is not None and dst_rel in pkg_reexports:
        re_entry = pkg_reexports[dst_rel].get(imported_sym)
        if re_entry is not None:
            re_mod, orig_sym = re_entry
            re_cands = [re_mod]
            if sr_prefix and not re_mod.startswith(f"{sr_prefix}."):
                re_cands.append(f"{sr_prefix}.{re_mod}")
            re_rel = next((mod_to_rel[m] for m in re_cands if m in mod_to_rel), None)
            if re_rel is not None and (
                dst_rel not in py_nodes_by_file or re_rel in py_nodes_by_file
            ):
                return re_rel, orig_sym
    return dst_rel, imported_sym


def _dotted_expr(expr: ast.AST) -> str | None:
    parts: list[str] = []
    cur = expr
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return None


_TACH_ROUTER_MOUNT_ATTRS = frozenset(
    {"include_router", "register_blueprint", "add_api_route", "add_url_rule", "mount"}
)


def _extract_top_level_callables(stmts: list[ast.stmt]) -> frozenset[str]:
    names: set[str] = set()
    try_types = (ast.Try, *((ast.TryStar,) if hasattr(ast, "TryStar") else ()))
    stack: list[ast.stmt] = list(reversed(stmts))
    while stack:
        stmt = stack.pop()
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(stmt.name)
        elif isinstance(stmt, ast.If):
            stack.extend(reversed(stmt.orelse))
            stack.extend(reversed(stmt.body))
        elif isinstance(stmt, try_types):
            stack.extend(reversed(stmt.finalbody))
            stack.extend(reversed(stmt.orelse))
            for handler in reversed(stmt.handlers):
                stack.extend(reversed(handler.body))
            stack.extend(reversed(stmt.body))
    return frozenset(names)


def _has_router_mount_call(tree: ast.Module) -> bool:
    return any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in _TACH_ROUTER_MOUNT_ATTRS
        for node in ast.walk(tree)
    )


def augment_tach_boundaries(
    repo_root: Path,
    backend_subdir: str,
    result: ManipulatorExtractionResult,
) -> None:
    """Annotate Tier-2 nodes with `tach.toml` domains and flag forbidden boundary imports."""
    skipped_tach: list[str] = []
    tach_path = _find_tach_toml(repo_root, backend_subdir, skipped_notes=skipped_tach)
    if skipped_tach:
        object.__setattr__(result, "coverage_complete", False)
        for sn in skipped_tach:
            if sn not in result.notes:
                result.notes.append(sn)
    if tach_path is None:
        return

    try:
        resolved_root = repo_root.resolve()
    except (OSError, ValueError) as exc:
        object.__setattr__(result, "coverage_complete", False)
        result.notes.append(f"Tach boundary parse skipped: {exc}")
        return
    try:
        config = parse_tach_toml(tach_path, resolved_root)
    except (
        OSError,
        UnicodeError,
        tomllib.TOMLDecodeError,
        TypeError,
        ValueError,
        RecursionError,
    ) as exc:
        rel_err = tach_path.relative_to(resolved_root).as_posix()
        object.__setattr__(result, "coverage_complete", False)
        result.notes.append(f"Tach boundary parse skipped ({rel_err}): {exc}")
        return

    py_files: list[Path] = []
    seen_files: set[Path] = set()
    for sr in config.source_roots:
        skipped_sr: list[str] = []
        try:
            found, _ = source_files(sr, {".py"}, skipped_out=skipped_sr)
        except OSError as exc:
            object.__setattr__(result, "coverage_complete", False)
            try:
                sr_label = sr.relative_to(resolved_root).as_posix() or "."
            except ValueError:
                sr_label = sr.name or "."
            note = f"Tach boundary source discovery incomplete ({sr_label}): {exc}"
            if note not in result.notes:
                result.notes.append(note)
            continue
        if skipped_sr:
            object.__setattr__(result, "coverage_complete", False)
            try:
                sr_label = sr.relative_to(resolved_root).as_posix() or "."
            except ValueError:
                sr_label = sr.name or "."
            note = (
                f"Tach boundary source discovery skipped {len(skipped_sr)} "
                f"unsafe or unreadable path(s) ({sr_label})."
            )
            if note not in result.notes:
                result.notes.append(note)
        for fp in found:
            try:
                resolved_fp = fp.resolve()
            except (OSError, ValueError):
                object.__setattr__(result, "coverage_complete", False)
                continue
            if resolved_fp in seen_files or not resolved_fp.is_relative_to(resolved_root):
                continue
            rel_posix = resolved_fp.relative_to(resolved_root).as_posix()
            if _is_excluded(rel_posix, config.exclude_patterns):
                continue
            seen_files.add(resolved_fp)
            py_files.append(resolved_fp)

    file_meta: dict[str, tuple[str, str, bool, str | None]] = {}
    known_modules: set[str] = set()
    mod_to_rel: dict[str, str] = {}
    pkg_dunder_all: dict[str, frozenset[str] | None] = {}
    pkg_reexports: dict[str, dict[str, tuple[str, str]]] = {}
    parsed_trees: dict[str, ast.Module] = {}
    callable_defs_by_rel: dict[str, frozenset[str]] = {}

    for fp in py_files:
        rel_posix = fp.relative_to(resolved_root).as_posix()
        info = _dotted_for_file(fp, config)
        if info is None:
            continue
        dotted, sr_prefix, is_pkg_init = info
        known_modules.add(dotted)
        mod_to_rel[dotted] = rel_posix
        if sr_prefix and dotted != "<root>":
            known_modules.add(f"{sr_prefix}.{dotted}")
            mod_to_rel[f"{sr_prefix}.{dotted}"] = rel_posix
        elif sr_prefix and dotted == "<root>":
            mod_to_rel[sr_prefix] = rel_posix
        owner = resolve_owning_tach_module(dotted, config, sr_prefix)
        file_meta[rel_posix] = (dotted, sr_prefix, is_pkg_init, owner)
        try:
            tree = ast.parse(
                _read_bounded_regular_text(
                    fp, max_bytes=_MAX_TACH_FILE_BYTES, encoding="utf-8-sig"
                )
            )
        except (OSError, UnicodeError, SyntaxError, ValueError, RecursionError) as exc:
            object.__setattr__(result, "coverage_complete", False)
            result.notes.append(f"Tach skipped unparseable Python file `{rel_posix}`: {exc}")
            continue
        parsed_trees[rel_posix] = tree
        callable_defs_by_rel[rel_posix] = (
            frozenset() if _has_router_mount_call(tree) else _extract_top_level_callables(tree.body)
        )
        if is_pkg_init:
            pkg_reexports[rel_posix] = _extract_pkg_reexports(tree, dotted)
        if is_pkg_init and owner is not None and (
            dotted == owner or f"{sr_prefix}.{dotted}" == owner
        ):
            pkg_dunder_all[owner] = _extract_dunder_all(tree)

    nodes_by_file: dict[str, list[AtlasNode]] = {}
    py_manip_nodes_by_file: dict[str, list[AtlasNode]] = {}
    node_by_id: dict[str, AtlasNode] = {}
    owner_first_node_id: dict[str, str] = {}
    mapped_node_count = 0

    for idx, node in enumerate(result.nodes):
        node_by_id[node.id] = node
        nodes_by_file.setdefault(node.source_file, []).append(node)
        if node.tier != "manipulate" or not node.source_file.endswith(".py"):
            continue
        meta = file_meta.get(node.source_file)
        owner = meta[3] if meta else None
        if owner is None and _has_safe_path_segments(node.source_file):
            try:
                abs_cand = (resolved_root / PurePosixPath(node.source_file)).resolve()
                info = _dotted_for_file(abs_cand, config) if abs_cand.is_relative_to(resolved_root) else None
            except (OSError, ValueError):
                info = None
            if info is not None:
                owner = resolve_owning_tach_module(info[0], config, info[1])
        if owner is None:
            continue
        mapped_node_count += 1
        owner_first_node_id.setdefault(owner, node.id)
        rule = config.modules.get(owner)
        qualifiers: list[str] = []
        if rule and rule.layer:
            qualifiers.append(f"layer={rule.layer}")
        if rule and rule.utility:
            qualifiers.append("utility")
        qual_str = f" ({', '.join(qualifiers)})" if qualifiers else ""
        tag = f"[tach:{owner}{qual_str}]"
        new_summary = node.summary if tag in node.summary else f"{node.summary} {tag}"
        note_piece = f"tach module `{owner}`"
        prev_note = node.verification_note
        new_note = (
            prev_note
            if prev_note and note_piece in prev_note
            else f"{prev_note}; {note_piece}"
            if prev_note
            else note_piece
        )
        updated = node.model_copy(update={"summary": new_summary, "verification_note": new_note})
        result.nodes[idx] = updated
        node_by_id[updated.id] = updated
        py_manip_nodes_by_file.setdefault(updated.source_file, []).append(updated)

    checked_cross_imports = 0
    violation_count = 0
    emitted_keys: set[tuple[str, str, str | None]] = set()
    ast_checked_pairs: set[tuple[str, str]] = set()
    pair_symbols: dict[tuple[str, str], set[str]] = {}
    pair_wildcards: set[tuple[str, str]] = set()
    owner_pair_symbols: dict[tuple[str, str], set[str]] = {}
    owner_pair_wildcards: set[tuple[str, str]] = set()
    cross_file_targets: dict[tuple[str, str], tuple[str, str, str]] = {}

    for rel_posix, tree in sorted(parsed_trees.items()):
        dotted, sr_prefix, is_pkg_init, caller_owner = file_meta[rel_posix]
        if caller_owner is None:
            continue
        refs = _iter_ast_import_refs(
            tree, dotted, sr_prefix, is_pkg_init, config, known_modules
        )
        for lineno, callee_owner, target_mod, rel_member, imported_sym in refs:
            dst_rel, resolved_sym = _resolve_import_target_file(
                target_mod,
                imported_sym,
                sr_prefix,
                mod_to_rel,
                pkg_reexports,
                py_manip_nodes_by_file,
            )
            is_callable_sym = (
                dst_rel is not None
                and resolved_sym is not None
                and resolved_sym in callable_defs_by_rel.get(dst_rel, frozenset())
            )
            if dst_rel is not None and dst_rel != rel_posix:
                if is_callable_sym and resolved_sym is not None:
                    pair_symbols.setdefault((rel_posix, dst_rel), set()).add(resolved_sym)
                else:
                    pair_wildcards.add((rel_posix, dst_rel))
                if caller_owner != callee_owner:
                    cross_file_targets.setdefault(
                        (rel_posix, dst_rel), (caller_owner, callee_owner, target_mod)
                    )
            if caller_owner == callee_owner:
                continue
            if is_callable_sym and resolved_sym is not None:
                owner_pair_symbols.setdefault((rel_posix, callee_owner), set()).add(resolved_sym)
            else:
                owner_pair_wildcards.add((rel_posix, callee_owner))
            checked_cross_imports += 1
            ast_checked_pairs.add((rel_posix, callee_owner))
            verdict = _evaluate_import_boundary(
                caller_owner=caller_owner,
                callee_owner=callee_owner,
                target_mod=target_mod,
                rel_member=rel_member,
                config=config,
                pkg_dunder_all=pkg_dunder_all,
            )
            if verdict is None:
                continue
            dedup_key = (rel_posix, callee_owner, rel_member)
            if dedup_key in emitted_keys:
                continue
            emitted_keys.add(dedup_key)
            violation_count += 1
            title, detail, remediation = verdict
            file_nodes = nodes_by_file.get(rel_posix, ())
            src_nid = file_nodes[0].id if file_nodes else None
            dst_nid = owner_first_node_id.get(callee_owner)
            result.findings.append(
                RawCandidateFinding(
                    rule_code="MANIP-006",
                    node_id=src_nid,
                    target_node_id=dst_nid,
                    source_file=rel_posix,
                    line=lineno,
                    title=title,
                    detail=detail,
                    remediation=remediation,
                    confidence="confirmed",
                    evidence_strength="structural_match",
                )
            )

    out_total_by_src: dict[str, int] = {}
    out_scoped_by_src: set[str] = set()
    for existing_edge in result.edges:
        if existing_edge.source_id.startswith(("m:dockerfile:", "m:compose:", "m:k8s:")):
            continue
        out_total_by_src[existing_edge.source_id] = (
            out_total_by_src.get(existing_edge.source_id, 0) + 1
        )
        if existing_edge.symbol_links:
            out_scoped_by_src.add(existing_edge.source_id)
    unscoped_only_nodes = {
        nid for nid, cnt in out_total_by_src.items() if cnt > 0 and nid not in out_scoped_by_src
    }

    existing_helper_pairs: set[tuple[str, str]] = set()
    for edge in result.edges:
        if edge.kind != "calls_helper":
            continue
        existing_helper_pairs.add((edge.source_id, edge.target_id))
        src_node = node_by_id.get(edge.source_id)
        dst_node = node_by_id.get(edge.target_id)
        if src_node is None or dst_node is None:
            continue
        if not src_node.source_file.endswith(".py") or not dst_node.source_file.endswith(".py"):
            continue
        src_owner = _resolve_node_owner(src_node.source_file, resolved_root, config, file_meta)
        dst_owner = _resolve_node_owner(dst_node.source_file, resolved_root, config, file_meta)
        if not edge.symbol_links and dst_node.id not in unscoped_only_nodes:
            fpair = (src_node.source_file, dst_node.source_file)
            if fpair in pair_symbols and fpair not in pair_wildcards:
                edge.symbol_links = [f"*->{s}" for s in sorted(pair_symbols[fpair])]
            elif (
                dst_owner is not None
                and fpair not in pair_wildcards
                and (src_node.source_file, dst_owner) in owner_pair_symbols
                and (src_node.source_file, dst_owner) not in owner_pair_wildcards
            ):
                dst_callables = callable_defs_by_rel.get(dst_node.source_file, frozenset())
                valid_syms = sorted(
                    s
                    for s in owner_pair_symbols[(src_node.source_file, dst_owner)]
                    if s in dst_callables
                )
                if valid_syms:
                    edge.symbol_links = [f"*->{s}" for s in valid_syms]
        if src_owner is None or dst_owner is None or src_owner == dst_owner:
            continue
        if (src_node.source_file, dst_owner) in ast_checked_pairs:
            continue
        checked_cross_imports += 1
        verdict = _evaluate_import_boundary(
            caller_owner=src_owner,
            callee_owner=dst_owner,
            target_mod=dst_owner,
            rel_member=None,
            config=config,
            pkg_dunder_all=pkg_dunder_all,
        )
        if verdict is None:
            continue
        dedup_key = (src_node.source_file, dst_owner, None)
        if dedup_key in emitted_keys:
            continue
        emitted_keys.add(dedup_key)
        violation_count += 1
        title, detail, remediation = verdict
        result.findings.append(
            RawCandidateFinding(
                rule_code="MANIP-006",
                node_id=src_node.id,
                target_node_id=dst_node.id,
                source_file=src_node.source_file,
                line=src_node.line,
                title=title,
                detail=detail,
                remediation=remediation,
                confidence="confirmed",
                evidence_strength="structural_match",
            )
        )

    for (src_rel, dst_rel), (c_owner, d_owner, t_mod) in sorted(cross_file_targets.items()):
        src_nodes = py_manip_nodes_by_file.get(src_rel, ())
        dst_nodes = py_manip_nodes_by_file.get(dst_rel, ())
        if not src_nodes or not dst_nodes:
            continue
        fpair = (src_rel, dst_rel)
        slinks = (
            []
            if fpair in pair_wildcards
            else [f"*->{s}" for s in sorted(pair_symbols.get(fpair, ()))]
        )
        for src_node in src_nodes:
            for dst_node in dst_nodes:
                if src_node.id == dst_node.id or (src_node.id, dst_node.id) in existing_helper_pairs:
                    continue
                existing_helper_pairs.add((src_node.id, dst_node.id))
                eff_slinks = [] if dst_node.id in unscoped_only_nodes else list(slinks)
                result.edges.append(
                    AtlasEdge(
                        id=f"e:tach:{src_node.id}->{dst_node.id}",
                        source_id=src_node.id,
                        target_id=dst_node.id,
                        kind="calls_helper",
                        verification="declared",
                        evidence_path=src_rel,
                        evidence_note=(
                            f"Tach module `{c_owner}` imports `{t_mod}` from `{d_owner}`."
                        ),
                        symbol_links=eff_slinks,
                    )
                )

    result.notes.append(
        f"Tach horizontal boundary check ({config.config_rel}): "
        f"{len(config.modules)} declared module(s), {mapped_node_count} node(s) mapped, "
        f"{checked_cross_imports} cross-module dependency reference(s) checked, "
        f"{violation_count} boundary violation(s)."
    )


def _resolve_node_owner(
    rel_file: str,
    resolved_root: Path,
    config: TachConfig,
    file_meta: dict[str, tuple[str, str, bool, str | None]],
) -> str | None:
    meta = file_meta.get(rel_file)
    if meta is not None:
        return meta[3]
    if not _has_safe_path_segments(rel_file):
        return None
    try:
        abs_cand = (resolved_root / PurePosixPath(rel_file)).resolve()
        if not abs_cand.is_relative_to(resolved_root):
            return None
    except (OSError, ValueError):
        return None
    info = _dotted_for_file(abs_cand, config)
    if info is None:
        return None
    return resolve_owning_tach_module(info[0], config, info[1])
