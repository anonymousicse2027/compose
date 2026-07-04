#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CompoSE +Naive baseline: random regex generation with random option seeding.

Runs iterations until --total_budget is exhausted. Branch-coverage flow matches
the adaptive runner: for iteration > 0, data/features/weights are generated from
the PREVIOUS iteration's results; the final iteration's coverage is collected once
after the loop.

Per iteration (no mutation, no parent selection, no reward accounting):
- Generate n_scores regexes randomly via regexgen (mode = --regex_mode).
- Pick ONE random source file per regex from the program's benchmark tree
  (derived from pgm_dir), recorded under "chosen_src_files" for prev-iteration reuse.
- Pick ONE random option per regex from the option-seed pool.
- Build one sym_options command per regex.

Option-seed pool: regex-related options extracted from the program's manual
(--manual PDF/HTML/text), cross-verified against the built binary's --help;
falls back to parsing --help directly when the manual/extractor is unavailable.

m4 runs with KLEE --optimize OFF (it fails to produce testcases under --optimize).

Housekeeping: per-iteration purge of the previous iteration's *.ktest_gcov after
snapshots; final *.ktest_gcov cleanup scoped to {top_dir}/result.
"""

from __future__ import annotations

# ============================== stdlib imports ============================== #
from subprocess import run, PIPE, STDOUT
import json
import time
import os
import optparse
import pickle
import random
from pathlib import Path
from typing import List, Dict, Set, Optional
import re
import shutil
import traceback

# ===== manual (documentation) based option extractor =====
# Naive mode seeds each random regex with ONE random program option. The option
# pool is extracted from the program's manual (regex-related options), then
# cross-verified against the built binary's --help. Falls back to parsing the
# binary's --help directly when the manual or the extractor is unavailable.

# ===== featmaker subscripts =====
from featmaker_subscript import klee_executor_naive as klee_executor_regex
try:
    from featmaker_subscript import klee_executor_naive_without_optimize as klee_executor_regex_no_opt
except Exception:
    klee_executor_regex_no_opt = None  # m4 needs KLEE --optimize OFF (seed-aware no-opt executor)
from featmaker_subscript import data_generator
from featmaker_subscript import feature_generator
from featmaker_subscript import weight_generator
from _shared import get_regex_mode, compose_root


# ============================== constants & globals ======================== #
ROOT = os.path.abspath(os.getcwd())  # script start cwd (assumed repo root)

# Programs that require two src_files (e.g., diff src1 src2)
_DUAL_SRC_PROGRAMS = {"diff"}


# ============================== utility helpers ============================ #
def load_pgm_config(config_file: str) -> Dict:
    """Load program configuration JSON."""
    with open(config_file, "r") as f:
        return json.load(f)


def ensure_dirs(paths: List[str]) -> None:
    """Ensure that each path in `paths` exists."""
    for p in paths:
        os.makedirs(p, exist_ok=True)


def escape_single_quotes(s: str) -> str:
    """Escape single quotes for safe inclusion inside single-quoted shell string."""
    return s.replace("'", "'\"'\"'")


def generate_regexes(n: int, mode: str, outfile: Path) -> None:
    """
    Generate `n` regexes using `regexgen` in given `mode` (pcre/bre/ere), writing to `outfile`.
    """
    cmd = ["regexgen", "-c", str(n), "--mode", mode, "-f", str(outfile)]
    run(cmd, check=True)


def make_abs(path_str: str) -> str:
    """
    Convert relative path (to ROOT) into absolute; leave absolute as-is.
    """
    if not path_str:
        return path_str
    return path_str if os.path.isabs(path_str) else os.path.abspath(os.path.join(ROOT, path_str))


def _resolve_cfg_path(path_str, root):
    """Resolve a pgm_config path relative to the SHARED CompoSE root (compose_root()).
    Absolute paths (incl. space-separated absolute src_file lists) are left unchanged."""
    if not path_str:
        return path_str
    first = path_str.split()[0] if path_str.split() else path_str
    if os.path.isabs(first):
        return path_str
    return os.path.abspath(os.path.join(root, path_str))


# ============================== src_file random picker ================= #
def _derive_src_base_dir_from_pgm_dir(pgm_dir: str) -> Path:
    """
    Derive the base dir (the parent of obj-llvm) from pgm_dir.
    Example:
      pgm_dir = ".../benchmarks/diffutils-3.7/obj-llvm/"
      -> base = ".../benchmarks/diffutils-3.7"

    If 'obj-llvm' is not found in the path parts, we fallback to pgm_dir's parent.
    """
    p = Path(pgm_dir).resolve()
    parts = list(p.parts)
    if "obj-llvm" in parts:
        idx = parts.index("obj-llvm")
        base = Path(*parts[:idx])  # path before obj-llvm
        return base
    return p.parent


def _build_all_files_pool(base_dir: Path) -> List[str]:
    """
    Recursively collect all regular files under base_dir.
    Returns a list of absolute file paths (strings).
    """
    pool: List[str] = []
    if not base_dir.exists():
        return pool
    try:
        for p in base_dir.rglob("*"):
            try:
                if p.is_file():
                    pool.append(str(p.resolve()))
            except Exception:
                continue
    except Exception:
        return pool
    return pool


def _pick_random_src_files(pool: List[str], k: int) -> List[str]:
    """
    Pick k random files from pool WITH replacement (each regex independently).
    If pool is empty, returns [""] * k.
    """
    if not pool or k <= 0:
        return [""] * k
    return [random.choice(pool) for _ in range(k)]


def _load_recorded_src_files(regex_dir: Path, iter_no: int) -> Optional[List[str]]:
    """
    Load chosen src files for iteration iter_no from regex/iteration-<iter_no>.json.
    Returns list[str] or None.
    """
    p = regex_dir / f"iteration-{iter_no}.json"
    if not p.exists():
        return None
    try:
        obj = json.loads(p.read_text())
        v = obj.get("chosen_src_files")
        if isinstance(v, list) and all(isinstance(x, str) for x in v):
            vv = [x for x in v if x.strip()]
            return vv if vv else None
        return None
    except Exception:
        return None


# ============================== program/flags discovery ===================== #
def _locate_program_binary(pconfig: Dict, pgm: str) -> Optional[str]:
    """
    Try to locate the compiled binary for `pgm` relative to gcov_path/exec_dir, with fallbacks:
    1) {gcov_path}/{exec_dir}/{pgm}
    2) {gcov_path}/src/{pgm}
    3) {gcov_path}/{pgm}
    4) PATH search (shutil.which)
    """
    candidates = []
    gcov = pconfig.get("gcov_path") or ""
    exec_dir = pconfig.get("exec_dir", "").strip("/")
    if gcov:
        if exec_dir:
            candidates.append(os.path.join(gcov, exec_dir, pgm))
        candidates.append(os.path.join(gcov, "src", pgm))
        candidates.append(os.path.join(gcov, pgm))
    # last resort: PATH
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


# Regexes for extracting option-like tokens from `--help` text.
_RE_LONG = re.compile(r"--[A-Za-z0-9][A-Za-z0-9\-]*")
_RE_SHORT = re.compile(r"(?<!-)-[A-Za-z]\b")


_DISALLOWED_FLAGS = {"--debug", "--help", "--version", "-h", "-V"}

def _extract_all_flags_from_help(help_text: str) -> List[str]:
    """
    Extract a de-duplicated list of option-like strings from `help_text`.
    We keep both long and short forms, then sort with long options first for readability.
    Excludes --debug, --help, --version and similar dangerous/useless flags.
    """
    flags: Set[str] = set()
    for ln in help_text.splitlines():
        if "-" not in ln:
            continue
        for m in _RE_LONG.finditer(ln):
            flags.add(m.group(0).rstrip(",.;:)=]"))
        for m in _RE_SHORT.finditer(ln):
            flags.add(m.group(0).rstrip(",.;:)=]"))
    flags -= _DISALLOWED_FLAGS
    return sorted(flags, key=lambda x: (0 if x.startswith("--") else 1, x))


def _get_help_flag_candidates(pconfig: Dict, pgm: str) -> List[str]:
    """
    Run `<pgm> --help` and parse possible flags as candidates.
    If the binary is missing or help parsing fails, return [].
    """
    bin_path = _locate_program_binary(pconfig, pgm)
    if not bin_path:
        return []
    try:
        res = run([bin_path, "--help"], stdout=PIPE, stderr=STDOUT, text=True, check=False, timeout=10)
        txt = res.stdout or ""
        return _extract_all_flags_from_help(txt)
    except Exception:
        return []


def _pick_random_flags_for_each(k: int, candidates: List[str]) -> List[str]:
    """
    Select one random flag per regex. If no candidates, return all empty strings.
    """
    if not candidates:
        return [""] * k
    return [random.choice(candidates) for _ in range(k)]


def _get_option_candidates(pconfig: Dict, pgm: str, manual_path: Optional[str]) -> List[str]:
    """Build the NAIVE option-seed candidate pool.

    NAIVE is regex-AGNOSTIC about options on purpose: it seeds each random regex
    with ONE random flag drawn from ALL of the binary's options (parsed from its
    --help), NOT just regex-related ones. This is the intended naive baseline.
    (`manual_path` is kept for signature compatibility but is unused here.)
    """
    return _get_help_flag_candidates(pconfig, pgm)


# ============================== KLEE command builder ======================== #
def build_sym_options_list(
    regexes: List[str],
    src_files: List[str],
    sym_args: str,
    pgm: str,
    extra_flags: Optional[List[str]] = None,
    src_files_2: Optional[List[str]] = None
) -> List[str]:
    """
    Build sym_options_list for KLEE.

    Parameters
    ----------
    src_files   : primary src_file per regex
    src_files_2 : (diff only) second src_file per regex.  When pgm is in
                  _DUAL_SRC_PROGRAMS and this list is provided, both files
                  are appended: ``flag 'regex' src1 src2 sym_args``
    """
    def pref(flag: str) -> str:
        return (flag + " ") if flag else ""

    n = len(regexes)
    if len(src_files) != n:
        raise ValueError(f"src_files length mismatch: got {len(src_files)} expected {n}")

    if extra_flags is None or len(extra_flags) != n:
        extra_flags = [""] * n

    needs_dual = pgm in _DUAL_SRC_PROGRAMS and src_files_2 is not None
    if needs_dual and len(src_files_2) != n:
        raise ValueError(f"src_files_2 length mismatch: got {len(src_files_2)} expected {n}")

    sym_list: List[str] = []
    for idx, rgx in enumerate(regexes):
        flag = extra_flags[idx]
        src1 = src_files[idx] or ""
        src1_q = f"'{escape_single_quotes(src1)}'" if src1 else src1

        q = escape_single_quotes(rgx.strip())

        if needs_dual:
            # diff-like: flag 'regex' src1 src2
            src2 = src_files_2[idx] or ""
            src2_q = f"'{escape_single_quotes(src2)}'" if src2 else src2
            sym_list.append(
                f"{pref(flag)} '{q}' {src1_q} {src2_q} {sym_args}".strip()
            )
        elif pgm in ('gawk', 'sed', 'csplit'):
            # use /regex/ form
            sym_list.append(
                f"{pref(flag)} '/{q}/' {src1_q} {sym_args}".strip()
            )
        else:
            sym_list.append(
                f"{pref(flag)} '{q}' {src1_q} {sym_args}".strip()
            )

    return sym_list


# ============================== coverage helpers (snapshot only) =========== #
def _parse_branch_keys_from_ktest_gcov(gcov_path: Path) -> Set[str]:
    """
    Parse a single *.ktest_gcov and collect unique taken-branch identifiers.
    Very lightweight, used only for diagnostic snapshots.
    """
    covered_branch: Set[str] = set()
    try:
        with open(gcov_path, 'r', errors='ignore') as f:
            content = f.read()
        parts = content.split('        -:    0:Source')[1:]
        for part in parts:
            s = part.split('\n')
            if not s:
                continue
            src_name = s[0].split('/')[-1]
            line_number = 0
            code_line_start = 1
            while code_line_start < len(s) and "0:" in s[code_line_start]:
                code_line_start += 1
            for l in s[code_line_start:]:
                if ":" in l:
                    line_number += 1
                    continue
                if 'taken' in l:
                    tmp = l.split()
                    if len(tmp) >= 4 and tmp[3] != '0%':
                        covered_branch.add(f"{src_name}_{line_number}_{tmp[1]}")
    except Exception:
        pass
    return covered_branch


def _unique_taken_branches_in_idx_dir(idx_dir: Path) -> int:
    """
    Aggregate unique taken branches across all *.ktest_gcov files under `idx_dir`.
    """
    uniq: Set[str] = set()
    if not idx_dir.exists():
        return 0
    for p in idx_dir.glob("*.ktest_gcov"):
        uniq |= _parse_branch_keys_from_ktest_gcov(p)
    return len(uniq)


def _save_iteration_branch_snapshot(regex_dir: Path, iteration: int, branches_now: List[int]) -> None:
    """
    Save a simple JSON snapshot of branch counts per widx for the given iteration.
    """
    snap = regex_dir / f"iteration-{iteration}.branch_counts.json"
    payload = {str(i): int(branches_now[i]) for i in range(len(branches_now))}
    snap.write_text(json.dumps(payload, ensure_ascii=False, indent=2))


# ========================= Naive SeedCache =========================
class NaiveSeedCache:
    """Store individual ktest file paths, return a temp dir with one random ktest."""
    def __init__(self, root: Path):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.ktest_files: List[str] = []  # list of individual ktest file paths

    def store(self, iteration: int, idx: int, outdir: str) -> None:
        """Collect all .ktest file paths from outdir."""
        src = Path(outdir)
        if not src.exists():
            return
        for kt in src.glob("*.ktest"):
            self.ktest_files.append(str(kt))

    def get_single_seed_dir(self, tag: str) -> Optional[str]:
        """Pick one random ktest, copy it into a temp dir, return that dir path."""
        if not self.ktest_files:
            return None
        chosen = random.choice(self.ktest_files)
        if not Path(chosen).exists():
            return None
        seed_dir = self.root / f"single_{tag}"
        seed_dir.mkdir(parents=True, exist_ok=True)
        # Clean previous contents
        for old in seed_dir.glob("*.ktest"):
            try: old.unlink()
            except Exception: pass
        try:
            shutil.copy2(chosen, str(seed_dir / Path(chosen).name))
        except Exception:
            return None
        return str(seed_dir)


def _purge_iteration_ktest_gcov(top_dir: str, iter_no: int) -> int:
    """
    Remove all *.ktest_gcov under result/iteration-<iter_no>.
    Returns the number of files removed.
    """
    it_dir = Path(top_dir) / f"result/iteration-{iter_no}"
    removed = 0
    if it_dir.exists():
        for p in it_dir.rglob("*.ktest_gcov"):
            try:
                p.unlink()
                removed += 1
            except Exception:
                pass
    print(f"[cleanup] removed {removed} '*.ktest_gcov' in iteration-{iter_no}")
    return removed


# ============================== main ======================================= #
def main() -> int:
    parser = optparse.OptionParser()
    parser.add_option(
        "--pgm", dest="pgm",
        help=("Benchmarks : csplit, diff, expr, find, gawk, grep"
              "ptx, sed, nano, tac, csplit, nl"),
        choices=["csplit", "diff", "expr", "find", "gawk",
                 "grep", "m4", "ptx", 
                 "sed", "nano", "tac", "nl", ]
    )
    parser.add_option("--output_dir", dest="output_dir", help="Result directory")
    parser.add_option("--config", dest="config", type="int", default=1,
                      help="Configuration number to use (Default: 1)")
    parser.add_option("--resume", dest="resume", action="store_true", default=False,
                      help="Append new iterations to an existing output_dir")
    parser.add_option("--total_budget", dest="total_time", type="int", default=86400,
                      help="Total time budget (sec) (Default: 86400 = 24h)")
    parser.add_option("--small_budget", dest="small_time", type="int", default=120,
                      help="Per-weight small time budget (sec) (Default: 120)")
    parser.add_option("--n_scores", dest="n_scores", type="int", default=20,
                      help="Number of score functions (weights) per iteration (Default: 20)")
    parser.add_option("--main_option", dest="main_option", default="featmaker",
                      help="featmaker or naive (Default: featmaker)", choices=["featmaker", "naive"])
    parser.add_option("--regex_mode", dest="regex_mode", choices=["pcre", "bre", "ere"], default="ere",
                      help="Regex mode: pcre, bre, or ere (default: ere)")
    parser.add_option("--manual", dest="manual", default=None,
                      help="Path to the program manual (.pdf/.txt/.html) for option extraction. "
                           "Extracted regex-related options are cross-verified against the binary "
                           "and used as the random option-seed pool (falls back to --help).")
    (options, args) = parser.parse_args()

    if not options.pgm:
        print("Required option is empty: pgm")
        return 1
    if not options.output_dir:
        print("Required option is empty: output_dir")
        return 1

    pgm = options.pgm
    output_dir = options.output_dir
    config_number = options.config
    # regex_mode is taken from the stored per-program table (regex_mode_table.py);
    # --regex_mode only acts as a fallback for programs not listed there.
    regex_mode = get_regex_mode(pgm, default=options.regex_mode)
    print(f"[regex_mode] {pgm} -> {regex_mode}")
    # pgm_config is a SHARED resource at the CompoSE root, not per-tool.
    _croot = compose_root()
    _cfg_root = str(_croot) if _croot else os.getcwd()
    config_file = os.path.join(_cfg_root, "pgm_config", f"{pgm}{config_number}.json")

    exp_dir = f"{options.main_option}_experiments"
    top_dir = os.path.abspath(f"{exp_dir}/{output_dir}/{pgm}")
    root_dir = os.getcwd()

    if not os.path.exists(top_dir):
        ensure_dirs([
            top_dir,
            f"{top_dir}/result",
            f"{top_dir}/weight",
            f"{top_dir}/errors",
            f"{top_dir}/features",
            f"{top_dir}/data"
        ])
        start_iter = 0
    else:
        if not options.resume:
            print("Output directory is already existing")
            return 1
        iters = []
        for d in os.listdir(f"{top_dir}/result"):
            if d.startswith("iteration-"):
                try:
                    iters.append(int(d.split("-")[-1]))
                except Exception:
                    pass
        start_iter = (max(iters) + 1) if iters else 0
        print(f"[resume] start from iteration {start_iter}")

    pconfig_base = load_pgm_config(config_file)

    # Resolve config-relative paths against the SHARED CompoSE root (compose_root()),
    # not the tool CWD -- so pgm_config can live at CompoSE/pgm_config/ and be shared.
    for key in ["pgm_dir", "gcov_path", "src_file"]:
        if key in pconfig_base:
            pconfig_base[key] = _resolve_cfg_path(pconfig_base[key], _cfg_root)
    pconfig_base["exec_dir"] = pconfig_base.get("exec_dir", "").lstrip("/")

    llvm_dir = pconfig_base["pgm_dir"]
    obj_copy_target = f"{top_dir}/obj-llvm"
    if obj_copy_target.endswith('}'):
        obj_copy_target = obj_copy_target[:-1]
    if not os.path.exists(obj_copy_target):
        run(["cp", "-r", llvm_dir, obj_copy_target], check=True)

    # -------- build src pool --------
    pgm_dir_abs = pconfig_base.get("pgm_dir", "")
    src_base_dir = _derive_src_base_dir_from_pgm_dir(pgm_dir_abs) if pgm_dir_abs else None
    src_pool: List[str] = []
    if src_base_dir and src_base_dir.exists():
        print(f"[src_file] base dir (before obj-llvm): {src_base_dir}")
        src_pool = _build_all_files_pool(src_base_dir)
        print(f"[src_file] pooled files: {len(src_pool)}")
    else:
        print("[src_file] WARNING: cannot derive base dir from pgm_dir; (cannot derive base dir).")

    if not src_pool:
        fallback = ""
        if fallback:
            print("[src_file] WARNING: src_pool empty -> fallback to config src_file")
        else:
            print("[src_file] ERROR: src_pool empty and config src_file empty -> cannot proceed.")
            return 1

    # ---- Option-seed candidate pool (computed once; static across iterations) ----
    # NAIVE option pool: ALL of the binary's options (from --help), regex-agnostic.
    option_candidates = _get_option_candidates(pconfig_base, pgm, options.manual)
    if option_candidates:
        print(f"[option-seed] {len(option_candidates)} candidate flags (all options from --help): "
              f"{', '.join(option_candidates[:min(8, len(option_candidates))])}")
    else:
        print("[option-seed] no candidate flags found; regexes will use no extra option.")

    start_time = time.time()
    remaining_time = options.total_time
    iteration = start_iter

    regex_dir = Path(top_dir) / "regex"
    regex_dir.mkdir(exist_ok=True)

    # ── Naive seed cache ──
    seed_cache = NaiveSeedCache(Path(top_dir) / "seed_cache")

    data: Dict[str, List[int]] = {}

    while remaining_time > 0:
        print(f"\n===== Iteration {iteration} (remaining {int(remaining_time)}s) =====")

        ensure_dirs([
            f"{top_dir}/result/iteration-{iteration}",
            f"{top_dir}/weight/iteration-{iteration}"
        ])

        # ---------- Handle PREVIOUS iteration ----------
        if iteration != 0:
            prev_iter = iteration - 1
            print(f"Generate data from iteration {prev_iter}")

            prev_src_files = _load_recorded_src_files(regex_dir, prev_iter)
            prev_src_first = None
            if prev_src_files and len(prev_src_files) > 0:
                prev_src_first = prev_src_files[0]
            else:
                prev_src_first = ""

            pconfig_prev = dict(pconfig_base)
            if prev_src_first:
                pconfig_prev["src_file"] = prev_src_first

            dg_prev = data_generator.data_generator(pconfig_prev, top_dir, options)
            dg_prev.generate_data(prev_iter)

            print(f"Generate features from iteration {prev_iter}")
            fg_prev = feature_generator.feature_generator(data, top_dir, options)
            fg_prev.collect(iteration)
            fg_prev.extract_feature()

            print(f"Generate weights for iteration {iteration}")
            if options.main_option == "featmaker":
                wg_prev = weight_generator.learning_weight_generator(data, top_dir, options.n_scores)
            else:
                wg_prev = weight_generator.random_weight_generator(data, top_dir, options.n_scores)
            wg_prev.generate_weight(iteration)

            # Snapshot branches for prev iteration
            try:
                this_txt = regex_dir / f"iteration-{prev_iter}.txt"
                regex_list_prev = [l.strip() for l in this_txt.read_text().splitlines() if l.strip()] if this_txt.exists() else []
                branches_prev: List[int] = []
                prev_dir = Path(top_dir) / f"result/iteration-{prev_iter}"
                for idx in range(len(regex_list_prev) or options.n_scores):
                    kdir = prev_dir / f"{idx}"
                    branches_prev.append(_unique_taken_branches_in_idx_dir(kdir))
                _save_iteration_branch_snapshot(regex_dir, prev_iter, branches_prev)
            except Exception as e:
                print(f"[warn] snapshot for prev iteration failed: {e}")
                traceback.print_exc()

            # Archive prev <widx>_result.pkl
            try:
                for widx in range(options.n_scores):
                    src = Path(top_dir) / f"{widx}_result.pkl"
                    if src.exists():
                        dst_dir = Path(top_dir) / f"data/iteration-{prev_iter}"
                        dst_dir.mkdir(parents=True, exist_ok=True)
                        dst = dst_dir / f"{widx}_result.pkl"
                        try:
                            shutil.move(str(src), str(dst))
                        except Exception:
                            try:
                                shutil.copy2(str(src), str(dst))
                                os.remove(str(src))
                            except Exception:
                                pass
            except Exception:
                pass

        # ---------- Purge old ktest_gcov: when iteration N starts, delete iteration N-2 ----------
        purge_target = iteration - 2
        if purge_target >= 0:
            _purge_iteration_ktest_gcov(top_dir, purge_target)

        # ---------- Generate regexes ----------
        out_txt = regex_dir / f"iteration-{iteration}.txt"
        generate_regexes(options.n_scores, regex_mode, out_txt)

        with open(out_txt, "r") as rf:
            regexes = [ln.strip() for ln in rf if ln.strip()]

        # Ensure regex count is exactly n_scores if regexgen gives fewer lines
        if len(regexes) < options.n_scores:
            # pad to n_scores
            while len(regexes) < options.n_scores:
                regexes.append("a")  # harmless minimal regex
        elif len(regexes) > options.n_scores:
            regexes = regexes[:options.n_scores]

        # ---------- Random src_file per regex (fresh each iteration) ----------
        if src_pool:
            chosen_src_files = _pick_random_src_files(src_pool, len(regexes))
        else:
            chosen_src_files = [""] * len(regexes)

        chosen_src_first = chosen_src_files[0] if chosen_src_files else ""
        if not chosen_src_first:
            print(f"[iter {iteration}] ERROR: chosen src_file empty")
            return 1
        _sample_src = ", ".join(os.path.basename(s) for s in chosen_src_files[:min(5, len(chosen_src_files))])
        print(f"[iter {iteration}] random src_file per-regex (sample): {_sample_src}")

        # For dual-src programs (diff): second random src_file per regex
        chosen_src_files_2: Optional[List[str]] = None
        if pgm in _DUAL_SRC_PROGRAMS:
            if src_pool:
                chosen_src_files_2 = _pick_random_src_files(src_pool, len(regexes))
            else:
                chosen_src_files_2 = [""] * len(regexes)
            _sample_src2 = ", ".join(os.path.basename(s) for s in chosen_src_files_2[:min(5, len(chosen_src_files_2))])
            print(f"[iter {iteration}] random src_file_2 per-regex (sample): {_sample_src2}")

        pconfig_iter = dict(pconfig_base)
        pconfig_iter["src_file"] = chosen_src_first  # compatibility only

        # ---------- Build per-regex random option flags (from the seed pool) ----------
        candidates = option_candidates
        extra_flags = _pick_random_flags_for_each(len(regexes), candidates)

        if candidates:
            sample = ", ".join(extra_flags[:min(5, len(extra_flags))])
            print(f"[iter {iteration}] random flags per-regex (sample): {sample}")
        else:
            print(f"[iter {iteration}] no flags found; using no extra flags per-regex.")

        # ---------- Build sym_options_list (uses per-regex src_files) ----------
        pconfig_iter["sym_options_list"] = build_sym_options_list(
            regexes=regexes,
            src_files=chosen_src_files,
            sym_args=pconfig_iter.get("sym_args", ""),
            pgm=pgm,
            extra_flags=extra_flags,
            src_files_2=chosen_src_files_2
        )

        # Save iteration config snapshot
        iter_cfg_path = regex_dir / f"iteration-{iteration}.json"
        iter_snapshot = {
            **pconfig_iter,
            "generated_regexes": regexes,
            "random_flags": extra_flags,
            "mutation": False,
            "chosen_src_files": chosen_src_files,
            "src_base_dir": str(src_base_dir) if src_base_dir else ""
        }
        if chosen_src_files_2:
            iter_snapshot["chosen_src_files_2"] = chosen_src_files_2
        with open(iter_cfg_path, "w") as jf:
            json.dump(iter_snapshot, jf, ensure_ascii=False, indent=2)

        # ---------- Seed dirs: iteration-0 has no seeds, iteration-1+ get one random ktest per regex ----------
        if iteration > 0 and seed_cache.ktest_files:
            pconfig_iter["seed_dirs_map"] = []
            for widx in range(len(regexes)):
                sd = seed_cache.get_single_seed_dir(f"i{iteration}_w{widx}")
                pconfig_iter["seed_dirs_map"].append([sd] if sd else [])
            print(f"[iter {iteration}] seed: 1 random ktest per-regex from {len(seed_cache.ktest_files)} ktests")
        else:
            pconfig_iter["seed_dirs_map"] = [[] for _ in regexes]

        # ---------- Run KLEE ----------
        remaining_time = options.total_time - (time.time() - start_time)
        # m4: MUST run with KLEE --optimize OFF (m4 fails to produce testcases under --optimize)
        if pgm == 'm4':
            if klee_executor_regex_no_opt is None:
                print("[m4][ERROR] no-optimize executor not found "
                      "(featmaker_subscript/klee_executor_naive_without_optimize.py). "
                      "m4 must run WITHOUT --optimize. Aborting.")
                return 1
            ke = klee_executor_regex_no_opt.klee_executor(pconfig_iter, top_dir, options)
        else:
            ke = klee_executor_regex.klee_executor(pconfig_iter, top_dir, options)
        ke.execute_klee(iteration, int(remaining_time))

        # ---------- Store seeds (ktest only) from this iteration ----------
        it_result = Path(top_dir) / f"result/iteration-{iteration}"
        for idx in range(len(regexes)):
            kdir = it_result / f"{idx}"
            if kdir.exists():
                seed_cache.store(iteration, idx, str(kdir))
        print(f"[iter {iteration}] seed cache: {len(seed_cache.ktest_files)} ktests stored")

        # Optional small cleanup
        try:
            os.chdir(f"{top_dir}/result")
            os.system('find . -type f -name "assembly.ll" -exec rm -f {} +')
        finally:
            os.chdir(root_dir)

        remaining_time = options.total_time - (time.time() - start_time)
        print(f"[DONE] iteration-{iteration}")
        iteration += 1

    # ================== AFTER LOOP: FINAL COLLECTION ================== #
    print("\nTesting Done. Please wait for collecting data")
    final_prev = iteration - 1
    if final_prev >= 0:
        last_src_files = _load_recorded_src_files(regex_dir, final_prev)
        last_src_first = last_src_files[0] if last_src_files else ""

        pconfig_last = dict(pconfig_base)
        if last_src_first:
            pconfig_last["src_file"] = last_src_first

        dg_last = data_generator.data_generator(pconfig_last, top_dir, options)
        dg_last.generate_data(final_prev)
        fg_last = feature_generator.feature_generator(data, top_dir, options)
        fg_last.collect(iteration)
    print("Collecting Done")

    # Final snapshot for last iteration (diagnostics only)
    try:
        this_txt = regex_dir / f"iteration-{final_prev}.txt"
        regex_list_prev = [l.strip() for l in this_txt.read_text().splitlines() if l.strip()] if this_txt.exists() else []
        branches_prev: List[int] = []
        prev_dir = Path(top_dir) / f"result/iteration-{final_prev}"
        for idx in range(len(regex_list_prev) or options.n_scores):
            kdir = prev_dir / f"{idx}"
            branches_prev.append(_unique_taken_branches_in_idx_dir(kdir))
        _save_iteration_branch_snapshot(regex_dir, final_prev, branches_prev)
    except Exception as e:
        print(f"[warn] final snapshot failed: {e}")
        traceback.print_exc()

    # Archive <widx>_result.pkl for the FINAL iteration as well
    try:
        for widx in range(options.n_scores):
            src = Path(top_dir) / f"{widx}_result.pkl"
            if src.exists():
                dst_dir = Path(top_dir) / f"data/iteration-{final_prev}"
                dst_dir.mkdir(parents=True, exist_ok=True)
                dst = dst_dir / f"{widx}_result.pkl"
                try:
                    shutil.move(str(src), str(dst))
                except Exception:
                    try:
                        shutil.copy2(str(src), str(dst))
                        os.remove(str(src))
                    except Exception:
                        pass
    except Exception:
        pass

    # Gather error inputs like original end-of-run
    try:
        os.chdir(top_dir)
        error_inputs = []
        for i in range(iteration):
            err_file = f"{top_dir}/errors/{i}_potential_errors.pkl"
            if os.path.exists(err_file):
                try:
                    with open(err_file, 'rb') as f:
                        error_inputs += pickle.load(f)
                except Exception:
                    pass
        with open(f"{top_dir}/error_inputs.txt", 'w') as f:
            f.write("\n".join(error_inputs))
    finally:
        os.chdir(root_dir)

    # Final cleanup mirroring original script (safe-scoped)
    try:
        os.chdir(top_dir)
        os.system("rm -rf obj-llvm")
        os.system("rm *_result.pkl")
        os.system("rm -r errors")
        os.system("find data -type f -name '*.pkl' -delete")
        os.system("find data -type d -empty -delete")
    finally:
        os.chdir(root_dir)

    # Scoped cleanup: remove any stray *.ktest_gcov under result only
    os.system(f"find '{top_dir}/result' -type f -name '*.ktest_gcov' -delete")

    print("\nAll done. Total budget exhausted or reached.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        raise