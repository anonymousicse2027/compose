#!/usr/bin/env python3
import os, re, sys, json, time, math, random, uuid, hashlib, pickle, shutil
import subprocess
from subprocess import run
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple, Union
from collections import Counter
from dataclasses import dataclass, asdict
from compose_common import (SAMPLE_REGEX, _MANUAL_DUAL_SRC_PROGRAMS, _MANUAL_SLASH_WRAP_PROGRAMS,
    _escape_regex_delim_slash, escape_single_quotes, make_abs)
from compose_regex import generate_random_text
from _shared import (load_mox, manuals_dir as _shared_manuals_dir,
                     build_profile as _shared_build_profile, parse_help_profile as _shared_parse_help)
mox = load_mox()
_HAS_MOX = mox is not None

__all__ = [
    '_USAGE_PROFILE_CACHE',
    '_derive_src_base_dir_from_pgm_dir',
    '_build_all_files_pool',
    '_pick_random_items',
    '_load_recorded_src_files',
    '_load_recorded_options',
    '_exec_dir_path',
    '_locate_program_binary',
    '_resolve_program_invocation',
    '_RE_LONG',
    '_RE_SHORT',
    '_RE_SHORT_LONG',
    '_DISALLOWED_FLAGS',
    '_RE_SHORT_TAKES_VALUE',
    '_RE_LONG_TAKES_VALUE',
    '_short_takes_value',
    '_long_takes_value',
    '_filter_disallowed_flags',
    '_extract_all_flags_from_help',
    '_get_help_text',
    '_parse_program_usage_profile',
    '_MANUAL_EXTS',
    '_MANUAL_CLI_OVERRIDE',
    '_resolve_manual_path',
    '_build_usage_profile_from_manual',
    '_get_usage_profile',
    '_save_usage_profile',
    '_get_help_flag_candidates',
    '_build_program_command',
    '_run_binary_get_branches',
    '_select_src_combined',
    '_select_options_combined',
    '_build_regex_profile',
    '_write_profile',
]




_USAGE_PROFILE_CACHE: Dict[str, dict] = {}

def _derive_src_base_dir_from_pgm_dir(pgm_dir: str, pgm: str = "") -> Path:
    _bench_root = os.environ.get("COMPOSE_BENCH_ROOT", "benchmarks")
    _fm_bench_root = os.environ.get("COMPOSE_FEATMAKER_BENCH_ROOT",
                                    os.path.join("FeatMaker", "benchmarks"))
    _SRC_BASE_DIRS = {
        "gawk": os.path.join(_bench_root, "gawk-5.1.0"),
        "nano": os.path.join(_bench_root, "nano-4.9"),
        "find": os.path.join(_bench_root, "findutils-4.7.0"),
        "grep": os.path.join(_bench_root, "grep-3.6"),
        "diff": os.path.join(_bench_root, "diffutils-3.7"),
        "sed":  os.path.join(_bench_root, "sed-4.8"),
        "ptx":  os.path.join(_bench_root, "coreutils-8.32"),
        "csplit": os.path.join(_bench_root, "coreutils-8.32"),
        "nl":   os.path.join(_bench_root, "coreutils-8.32"),
        "tac":  os.path.join(_bench_root, "coreutils-8.32"),
        "expr": os.path.join(_bench_root, "coreutils-8.32"),
        "m4":   os.path.join(_fm_bench_root, "m4-1.4.19"),
    }
    if pgm and pgm in _SRC_BASE_DIRS:
        p = Path(_SRC_BASE_DIRS[pgm])
        if p.exists():
            return p
    p = Path(pgm_dir).resolve()
    parts = list(p.parts)
    if "obj-llvm" in parts:
        idx = parts.index("obj-llvm")
        return Path(*parts[:idx])
    return p.parent

def _build_all_files_pool(base_dir: Path) -> List[str]:
    pool: List[str] = []
    if not base_dir.exists():
        return pool
    try:
        for p in base_dir.rglob("*"):
            try:
                if p.is_file():
                    path_str = str(p)
                    if '/obj-gcov' in path_str or '\\obj-gcov' in path_str:
                        continue
                    pool.append(str(p.resolve()))
            except Exception:
                continue
    except Exception:
        return pool
    return pool

def _pick_random_items(pool: List[str], k: int) -> List[str]:
    if not pool or k <= 0:
        return []
    if len(pool) >= k:
        return random.sample(pool, k)
    return random.choices(pool, k=k)

def _load_recorded_src_files(regex_dir: Path, iter_no: int) -> Optional[List[str]]:
    p = regex_dir / f"iteration-{iter_no}.json"
    if not p.exists():
        return None
    try:
        obj = json.loads(p.read_text())
        v = obj.get("chosen_src_files")
        if isinstance(v, list) and all(isinstance(x, str) for x in v):
            vv = [x for x in v if x.strip()]
            return vv if vv else None
    except Exception:
        pass
    return None

def _load_recorded_options(regex_dir: Path, iter_no: int, n_scores: int) -> Optional[List[str]]:
    p = regex_dir / f"iteration-{iter_no}.json"
    if not p.exists():
        return None
    try:
        obj = json.loads(p.read_text())
        v_list = obj.get("chosen_options")
        if isinstance(v_list, list) and all(isinstance(x, str) for x in v_list):
            opts = [x.strip() for x in v_list if x is not None]
            opts = [x for x in opts if x]
            opts = _filter_disallowed_flags(opts)
            if not opts:
                return None
            if len(opts) < n_scores:
                opts += [opts[0]] * (n_scores - len(opts))
            return opts[:n_scores]
        v = obj.get("chosen_option")
        if isinstance(v, str) and v.strip():
            picked = v.strip()
            if picked in _DISALLOWED_FLAGS:
                return None
            return [picked] * n_scores
    except Exception:
        pass
    return None

def _exec_dir_path(pconfig: dict) -> Optional[Path]:
    gcov = pconfig.get("gcov_path") or ""
    exec_dir = pconfig.get("exec_dir", "").strip("/")
    if not gcov:
        return None
    if exec_dir:
        return Path(gcov) / exec_dir
    return Path(gcov)

def _locate_program_binary(pconfig: dict, pgm: str) -> Optional[str]:
    candidates = []
    gcov = pconfig.get("gcov_path") or ""
    exec_dir = pconfig.get("exec_dir", "").strip("/")
    if gcov:
        if exec_dir:
            candidates.append(os.path.join(gcov, exec_dir, pgm))
        candidates.append(os.path.join(gcov, "src", pgm))
        candidates.append(os.path.join(gcov, pgm))
    try:
        which = shutil.which(pgm)
        if which:
            candidates.append(which)
    except Exception:
        pass
    for c in candidates:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None

def _resolve_program_invocation(pconfig: dict, pgm: str, exec_dir: Optional[Path]) -> str:
    bin_path = _locate_program_binary(pconfig, pgm)
    if bin_path:
        try:
            bin_p = Path(bin_path).resolve()
            if exec_dir and exec_dir.resolve() == bin_p.parent:
                return f"./{bin_p.name}"
        except Exception:
            pass
        return bin_path
    return pgm

_RE_LONG = re.compile(r"--[A-Za-z0-9][A-Za-z0-9\-]*")

_RE_SHORT = re.compile(r"(?<!-)-[A-Za-z]\b")

_RE_SHORT_LONG = re.compile(r"(?<![A-Za-z0-9\-])-[A-Za-z][A-Za-z0-9]*")  # For options like -regex, -iregex (excludes matches inside --long-options)

_DISALLOWED_FLAGS = {"--debug"}

_RE_SHORT_TAKES_VALUE = re.compile(r'^\s*(-[A-Za-z])(?:\[|\s+[a-z]|\s+<|\s+\')')

_RE_LONG_TAKES_VALUE = re.compile(r'(--[A-Za-z0-9][A-Za-z0-9\-]*)(?:\[?=)')

def _short_takes_value(ln: str) -> Set[str]:
    """Return set of short flags on this line that take a value argument."""
    return {m.group(1) for m in _RE_SHORT_TAKES_VALUE.finditer(ln)}

def _long_takes_value(ln: str) -> Set[str]:
    """Return set of long flags on this line that take a value argument."""
    return {m.group(1) for m in _RE_LONG_TAKES_VALUE.finditer(ln)}

def _filter_disallowed_flags(flags: List[str]) -> List[str]:
    return [flag for flag in flags if flag not in _DISALLOWED_FLAGS]

def _extract_all_flags_from_help(help_text: str) -> List[str]:
    flags: Set[str] = set()
    for ln in help_text.splitlines():
        if "-" not in ln:
            continue
        stripped = ln.lstrip()
        if not stripped.startswith('-'):
            continue
        val_flags = _short_takes_value(ln)
        val_longs = _long_takes_value(ln)
        shorts = []
        longs = []
        for m in _RE_SHORT.finditer(ln):
            f = m.group(0).rstrip(",.;:)=]")
            if f not in val_flags:
                shorts.append(f)
        for m in _RE_LONG.finditer(ln):
            f = m.group(0).rstrip(",.;:)=]")
            if f not in val_longs:
                longs.append(f)
        single_dash_longs = []
        for m in _RE_SHORT_LONG.finditer(ln):
            f = m.group(0).rstrip(",.;:)=]")
            if len(f) > 2 and f not in shorts and f not in longs:
                single_dash_longs.append(f)
        if shorts and longs:
            for f in shorts + single_dash_longs: flags.add(f)
        else:
            for f in shorts + longs + single_dash_longs: flags.add(f)
    return _filter_disallowed_flags(
        sorted(flags, key=lambda x: (0 if x.startswith("--") else 1, x))
    )

def _get_help_text(pconfig: dict, pgm: str) -> str:
    """Get --help text for a program."""
    bin_path = _locate_program_binary(pconfig, pgm)
    if not bin_path:
        return ""
    try:
        res = run([bin_path, "--help"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False, timeout=10)
        return res.stdout or ""
    except Exception:
        return ""

def _parse_program_usage_profile(help_text: str, pgm: str) -> dict:
    """Parse a program's --help text into a usage profile (delegates to the shared
    manual_profile builder)."""
    p = _shared_parse_help(help_text, pgm)
    if p is None:
        p = {"arg_order": "regex_first", "regex_prefix": "", "regex_options": [], "all_options": [],
             "special_syntax": None, "uses_slash_wrap": pgm in _MANUAL_SLASH_WRAP_PROGRAMS,
             "needs_dual_src": pgm in _MANUAL_DUAL_SRC_PROGRAMS, "accepts_options": True}
    return p

_MANUAL_EXTS = (".pdf", ".1", ".txt", ".html", ".htm", "")

_MANUAL_CLI_OVERRIDE: Dict[str, str] = {}



def _resolve_manual_path(pconfig: dict, pgm: str) -> Optional[str]:
    """Return a readable manual path for pgm, or None if none is configured."""
    cand: List[str] = []
    cfg = (pconfig or {}).get("manual") or (pconfig or {}).get("manual_path")
    if cfg:
        cand.append(make_abs(cfg))
    if pgm in _MANUAL_CLI_OVERRIDE:
        cand.append(make_abs(_MANUAL_CLI_OVERRIDE[pgm]))
    manual_dir = os.environ.get("COMPOSE_MANUAL_DIR")
    if not manual_dir:
        _sd = _shared_manuals_dir()
        manual_dir = str(_sd) if _sd else "manuals"
    for ext in _MANUAL_EXTS:
        cand.append(make_abs(os.path.join(manual_dir, f"{pgm}{ext}")))
    for c in cand:
        if c and os.path.isfile(c):
            return c
    return None

def _build_usage_profile_from_manual(manual_path: str, binary: Optional[str], pgm: str) -> Optional[dict]:
    return _shared_build_profile(manual_path, binary, pgm)


def _get_usage_profile(pconfig: dict, pgm: str) -> dict:
    if pgm not in _USAGE_PROFILE_CACHE:
        p = None
        manual_path = _resolve_manual_path(pconfig, pgm)
        if manual_path:
            binary = _locate_program_binary(pconfig, pgm)
            p = _build_usage_profile_from_manual(manual_path, binary, pgm)
            if p is not None:
                print(f"[profile] {pgm}: source=manual ({os.path.basename(manual_path)})")
        if p is None:
            if manual_path is None:
                print(f"[profile] {pgm}: no manual found, falling back to --help")
            help_text = _get_help_text(pconfig, pgm)
            p = _parse_program_usage_profile(help_text, pgm)
            p["source"] = "help"
        _FALLBACK_PROF = {
            "tac":  {"regex_options": ["-s"], "separator_flags": ["-b", "-r", "-s"], "separator_value_flag": "-s", "arg_order": "regex_first", "accepts_options": True},
            "ptx":  {"regex_options": ["-S", "-W"], "arg_order": "regex_first", "accepts_options": True},
            "find": {"regex_options": ["-regex"], "arg_order": "file_first", "accepts_options": False},
            "diff": {"regex_options": ["-F", "-I"], "arg_order": "regex_first", "accepts_options": True},
            "nano": {"regex_options": ["-Q"], "arg_order": "regex_first", "accepts_options": True},
        }
        if not p.get("regex_options") and pgm in _FALLBACK_PROF:
            print(f"[profile] {pgm}: empty option pool, applying built-in fallback defaults")
            for k, v in _FALLBACK_PROF[pgm].items():
                if not p.get(k): p[k] = v
        _USAGE_PROFILE_CACHE[pgm] = p
    return _USAGE_PROFILE_CACHE[pgm]

def _save_usage_profile(regex_dir: Path, pgm: str, profile: dict) -> None:
    """Save usage profile to JSON for debugging/verification."""
    profile_path = regex_dir / f"usage_profile_{pgm}.json"
    try:
        with open(profile_path, "w") as f:
            json.dump(profile, f, indent=2, ensure_ascii=False)
    except Exception:
        pass

def _get_help_flag_candidates(pconfig: dict, pgm: str) -> List[str]:
    """Get all flag candidates from --help."""
    bin_path = _locate_program_binary(pconfig, pgm)
    if not bin_path:
        return []
    try:
        res = run([bin_path, "--help"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False, timeout=10)
        txt = res.stdout or ""
        return _extract_all_flags_from_help(txt)
    except Exception:
        return []

def _build_program_command(
    pgm: str,
    program_invocation: str,
    regex: str,
    src_file: str,
    regex_mode: str,
    extra_flag: str = "",
    usage_profile: Optional[dict] = None
) -> str:
    q = escape_single_quotes(regex.strip())

    q_for_slash = _escape_regex_delim_slash(q)
    wrapped = f"/{q_for_slash}/"
    
    # Get profile info
    if usage_profile is None:
        usage_profile = {}
    uses_slash_wrap = usage_profile.get("uses_slash_wrap", False) or pgm in _MANUAL_SLASH_WRAP_PROGRAMS
    regex_prefix = usage_profile.get("regex_prefix", "")
    arg_order = usage_profile.get("arg_order", "regex_first")
    special_syntax = usage_profile.get("special_syntax")
    separator_flags = usage_profile.get("separator_flags", [])
    separator_value_flag = usage_profile.get("separator_value_flag", "")
    
    q_with_prefix = f"{regex_prefix}{q}" if regex_prefix else q
    regex_token = f"'{wrapped}'" if uses_slash_wrap else f"'{q_with_prefix}'"

    flag_parts = []
    separator_value_flag = usage_profile.get("separator_value_flag", "")
    for sf in separator_flags:
        sf_clean = sf.strip()
        if sf_clean and sf_clean != separator_value_flag and sf_clean not in flag_parts:
            flag_parts.append(sf_clean)
    flag_prefix = " ".join(flag_parts)
    flag_prefix = f"{flag_prefix} " if flag_prefix else ""

    ef = str(extra_flag).strip() if extra_flag else ""
    if ef:
        if ef.startswith("--") and not uses_slash_wrap and special_syntax is None:
            regex_part = f"{ef}={regex_token}"
        else:
            regex_part = f"{ef} {regex_token}"
    else:
        regex_part = regex_token

    if special_syntax == "string_colon_regex":
        input_text = generate_random_text()
        esc_text = input_text.replace('\"', '\\\"')
        return f"{program_invocation} {flag_prefix}\"{esc_text}\" : '{q_with_prefix}'".strip()

    elif arg_order == "file_first":
        return f"{program_invocation} {src_file} {flag_prefix}{regex_part}".strip()
    
    elif arg_order == "no_file":
        return f"{program_invocation} {flag_prefix}{regex_part}".strip()
    
    else:
        return f"{program_invocation} {flag_prefix}{regex_part} {src_file}".strip()

def _run_binary_get_branches(gcov_obj: str, exec_dir: Path, cmds: List[str], src_files: List[str], gcov_depth: int = 1, timeout: int = 10) -> Dict[str, Set[str]]:
    result: Dict[str, Set[str]] = {}
    target = Path(gcov_obj).resolve()
    if not target.exists():
        return {sf: set() for sf in src_files}
    base = target.parent
    for _ in range(gcov_depth): base = base.parent
    base = base.resolve()
    gcda_pat = str(Path(*(['..'] * gcov_depth)) / '**/*.gcda')
    gcov_pat = str(Path(*(['..'] * gcov_depth)) / '**/*.gcov')

    orig = os.getcwd()
    for sf, cmd in zip(src_files, cmds):
        branches: Set[str] = set()
        try:
            subprocess.run(f'find {base} -name "*.gcda" -delete 2>/dev/null', shell=True, check=False, timeout=10)
            subprocess.run(f'find {base} -name "*.gcov" -delete 2>/dev/null', shell=True, check=False, timeout=10)
            subprocess.run(cmd, shell=True, cwd=str(exec_dir),
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, timeout=timeout)
            os.chdir(str(target.parent))
            gcda_files = list(Path().glob(gcda_pat))
            gcda_files = [g for g in gcda_files if 'signal.gcda' not in str(g)]
            if gcda_files:
                subprocess.run(f'gcov -b {" ".join(str(g) for g in gcda_files)}',
                               shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                subprocess.run(f'find {base} -name "signal.c.gcov" -delete 2>/dev/null', shell=True, check=False)
                for gf in Path().glob(gcov_pat):
                    try:
                        content = gf.read_text(errors='ignore')
                        parts = content.split('        -:    0:Source')[1:]
                        for part in parts:
                            lines = part.split('\n')
                            if not lines: continue
                            src_name = lines[0].split('/')[-1]
                            if src_name == 'signal.c': continue  
                            line_number = 0
                            code_line_start = 1
                            while code_line_start < len(lines) and "0:" in lines[code_line_start]:
                                code_line_start += 1
                            for l in lines[code_line_start:]:
                                if ':' in l:
                                    line_number += 1
                                    continue
                                if 'taken' in l:
                                    tmp = l.split()
                                    if len(tmp) >= 4 and tmp[3] != '0%':
                                        branches.add(f'{src_name}_{line_number}_{tmp[1]}')
                    except: pass
            os.chdir(orig)
        except Exception:
            try: os.chdir(orig)
            except: pass
        result[sf] = branches
    try:
        subprocess.run(f'find {base} -name "*.gcda" -delete 2>/dev/null', shell=True, check=False, timeout=10)
        subprocess.run(f'find {base} -name "*.gcov" -delete 2>/dev/null', shell=True, check=False, timeout=10)
    except: pass
    return result

def _select_src_combined(
    pgm: str,
    regex_mode: str,
    pconfig: dict,
    src_pool: List[str],
    n_select: int,
    sample_count: int,
    freq_cum: Counter,
    tested_set: Set[str],
    usage_profile: Optional[dict] = None,
    gcov_depth: int = 1
) -> Tuple[List[str], str]:
    fallback_src = pconfig.get("src_file", "")
    if not src_pool:
        return [fallback_src] * n_select, fallback_src

    gcov_obj = _locate_program_binary(pconfig, pgm)
    exec_dir = _exec_dir_path(pconfig)
    if not gcov_obj or not exec_dir or not exec_dir.exists():
        return [fallback_src] * n_select, fallback_src

    untested = [f for f in src_pool if f not in tested_set]
    if not untested:
        tested_set.clear()
        untested = list(src_pool)
    candidates = random.sample(untested, min(sample_count, len(untested)))
    program_invocation = _resolve_program_invocation(pconfig, pgm, exec_dir)
    commands = [
        _build_program_command(pgm, program_invocation, SAMPLE_REGEX, src_file, regex_mode, usage_profile=usage_profile)
        for src_file in candidates
    ]
    branch_map = _run_binary_get_branches(gcov_obj, exec_dir, commands, candidates, gcov_depth)
    scored: List[Tuple[float, str]] = []
    for sf in candidates:
        bs = branch_map.get(sf, set())
        sc = sum(1.0 / math.sqrt(int(freq_cum.get(b, 0)) + 1.0) for b in bs) if bs else 0.0
        scored.append((sc, sf))
    scored.sort(key=lambda x: x[0], reverse=True)
    top = [sf for _, sf in scored[:n_select]]
    if not top: top = [fallback_src] * n_select
    elif len(top) < n_select: top += [top[0]] * (n_select - len(top))
    tested_set.update(candidates)
    best = top[0] if top else fallback_src
    best_sc = f'{scored[0][0]:.2f}' if scored else 'N/A'
    print(f'[src-combined] top {n_select} from {len(candidates)} candidates '
          f'(untested_remaining={len(untested)-len(candidates)}, best_score={best_sc})')
    return top, best

def _select_options_combined(
    pgm: str,
    regex_mode: str,
    pconfig: dict,
    best_src: str,
    pool: List[str],
    n_select: int,
    freq_cum: Counter,
    usage_profile: Optional[dict] = None,
    gcov_depth: int = 1
) -> Tuple[List[str], str]:
    if not pool:
        return [""] * n_select, ""
    gcov_obj = _locate_program_binary(pconfig, pgm)
    exec_dir = _exec_dir_path(pconfig)
    if not gcov_obj or not exec_dir or not exec_dir.exists():
        return [random.choice(pool) for _ in range(n_select)], random.choice(pool)
    program_invocation = _resolve_program_invocation(pconfig, pgm, exec_dir)
    cmds = [
        _build_program_command(pgm, program_invocation, SAMPLE_REGEX, best_src, regex_mode,
                               extra_flag=f, usage_profile=usage_profile)
        for f in pool
    ]
    branch_map = _run_binary_get_branches(gcov_obj, exec_dir, cmds, pool, gcov_depth)
    scored: List[Tuple[float, str]] = []
    for f in pool:
        bs = branch_map.get(f, set())
        sc = sum(1.0 / math.sqrt(int(freq_cum.get(b, 0)) + 1.0) for b in bs) if bs else 0.0
        scored.append((sc, f))
    weights = [max(sc, 0.0) + 1.0 for sc, _ in scored]
    chosen = random.choices([f for _, f in scored], weights=weights, k=n_select)
    best_sc = max(scored, key=lambda x: x[0])
    best = best_sc[1]
    return chosen, best

def _build_regex_profile(pgm: str, regex_mode: str) -> dict:
    profile = {
        "mode": regex_mode,
        "slots": {"char": 30, "class": 20, "alt": 8, "anchor": 12, "boundary": 0, "lookaround": 0, "backref": 0},
        "char_dist": [5, 5, 40, 40, 10],
        "class_dist": [50, 40, 10],
        "rep_dist": [10, 20, 20, 50],
        "knobs": {"max_group_depth": 3, "posix_class_max": 8, "word_boundary_limit": 0, "alt_max": 6, "no_cap_dotstar": True},
        "allow": {"literal_meta": True, "fixed_count": True, "open_count": True, "bare_alt": True, "composite_class": True, "pcre_backref": False},
        "prefer_tokens": [], "avoid_tokens": []
    }
    return profile

def _write_profile(profile: dict, path: Path) -> None:
    path.write_text(json.dumps(profile, ensure_ascii=False, indent=2))
