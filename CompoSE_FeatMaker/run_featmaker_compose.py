#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CompoSE runner with combined coverage + bug-focused mutation.

Uses --w_coverage (default 0.5) and --w_bug (default 0.5) to blend:
  - Coverage reward: freq-scarcity-based (1/sqrt(freq+1)) delta scoring
  - Bug reward: wall-clock time (worst-case) with a crash bonus
  - Crash bonus: lambda = 50 added to score_bug when a crash is observed

Bug features:
  - Timeout check for all supported programs
  - KLEE .err classification (ASSERTION/INVALID_MEM/ABORT)
  - bug_corpus.jsonl accumulation
  - Bug bonus in parent selection

All existing coverage features preserved:
  - Fragment mutation (UCB1 + epsilon-greedy)
  - SeedCache (freq-based best ktest per regex)
  - Usage profile system (arg_order, regex_options, format, dual-src, etc.)
  - src_file/option scoring and selection

Preparation (option / regex-format / dual-src) is derived from each program's
documentation (a manual PDF/HTML/text), following the paper's "Option Selection"
and "Regex Formatting" description, and is cross-checked against the built
binary's --help so that only options the binary actually exposes are kept.
"""

from subprocess import run
import subprocess
import json
import time
import os
import optparse
import pickle
import random
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple, Union
from collections import Counter
import hashlib
import re
import sys
import shutil
from dataclasses import dataclass, asdict
import math
import uuid

# ===== (optional) sniffles path =====
# Location of the bundled Sniffles source tree. Defaults to a "sniffles/src"
# directory next to this script; override with the SNIFFLES_SRC env var.
_SNIFFLES_SRC = os.environ.get(
    "SNIFFLES_SRC",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "sniffles", "src"),
)
sys.path.insert(0, os.path.abspath(_SNIFFLES_SRC))
from sniffles.regex_generator import verify_bre_escapes  # PCRE features unused

# ===== featmaker subscripts =====
from featmaker_subscript import klee_executor_compose as klee_executor_regex
from featmaker_subscript import klee_executor_compose_without_optimize as klee_executor_regex_no_opt
from featmaker_subscript import data_generator
from featmaker_subscript import feature_generator
from featmaker_subscript import weight_generator

# ===== manual (documentation) based option extractor =====
# Preparation reads each program's manual (PDF/HTML/text) to identify
# regex-related options, the regex format template (e.g. /pattern/), and
# whether the program consumes two source files (e.g. diff). If the module or
# its pdftotext dependency is unavailable, preparation falls back to parsing the
# binary's --help output.
from _shared import load_mox
mox = load_mox()
_HAS_MOX = mox is not None

# ---- CompoSE split modules (see compose_common/regex/profile/coverage.py) ----
from compose_common import *
from compose_regex import *
from compose_profile import *
from compose_coverage import *
from _shared import get_regex_mode, compose_root

def _resolve_cfg_path(path_str, root):
    """Resolve a pgm_config path relative to the SHARED CompoSE root (compose_root()).
    Absolute paths (incl. space-separated absolute src_file lists) are left unchanged."""
    if not path_str:
        return path_str
    first = path_str.split()[0] if path_str.split() else path_str
    if os.path.isabs(first):
        return path_str
    return os.path.abspath(os.path.join(root, path_str))

# ----------------------------- globals ----------------------------- #
REWARD_CLAMP_MAX: Optional[float] = None
SRC_SAMPLE_COUNT = 100

# ── Bug-focused reward ──
BUG_BONUS_CRASH = 50.0

def _measure_replay_perf(idx_dir, binary_path, klee_replay_bin="klee-replay", timeout=10):
    """Replay ktest files and measure actual wall-clock time + peak RSS.
    Returns (max_elapsed_sec, max_rss_kb) across all ktests in idx_dir.
    Peak RSS is recorded for logging only; the bug score uses wall-clock time
    plus a crash bonus (see _compute_score_bug).
    """
    idx_dir = Path(idx_dir)
    ktests = list(idx_dir.glob("*.ktest"))
    if not ktests or not binary_path:
        return 0.0, 0.0
    max_time = 0.0
    max_rss_kb = 0.0
    for kt in ktests:
        try:
            cmd = f"/usr/bin/time -v {klee_replay_bin} {binary_path} {kt}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            for line in result.stderr.splitlines():
                line = line.strip()
                if "Elapsed (wall clock) time" in line:
                    ts = line.split(": ")[-1].strip()
                    parts = ts.split(":")
                    if len(parts) == 3:
                        t = float(parts[0]) * 3600 + float(parts[1]) * 60 + float(parts[2])
                    elif len(parts) == 2:
                        t = float(parts[0]) * 60 + float(parts[1])
                    else:
                        t = float(parts[0])
                    max_time = max(max_time, t)
                elif "Maximum resident set size" in line:
                    rss = float(line.split(": ")[-1].strip())
                    max_rss_kb = max(max_rss_kb, rss)
        except subprocess.TimeoutExpired:
            max_time = max(max_time, float(timeout))
        except Exception:
            pass
    # Save to perf.json for caching
    try:
        perf = {"elapsed_sec": max_time, "max_rss_kb": max_rss_kb, "source": "replay"}
        (idx_dir / "perf.json").write_text(json.dumps(perf, indent=2), encoding="utf-8")
    except Exception:
        pass
    return max_time, max_rss_kb

def _compute_score_bug(elapsed_sec: float, rss_kb: float, has_crash: bool) -> float:
    """Compute bug score: elapsed_sec + crash_bonus (raw, no log).

    The paper formulation is score_bug(r) = tau_max + lambda * delta(r), i.e.
    worst-case wall-clock time plus a crash bonus. Peak RSS is no longer part of
    the score; the rss_kb argument is kept only for caller compatibility and is
    ignored here. The log compression is applied later at the combination step
    (score(r)) so the scale matches score_cov, which is also raw at definition.
    """
    del rss_kb  # intentionally unused (kept for caller compatibility)
    return elapsed_sec + (BUG_BONUS_CRASH if has_crash else 0.0)


def load_pgm_config(config_file: str):
    with open(config_file, "r") as f:
        return json.load(f)

def ensure_dirs(paths):
    for p in paths:
        os.makedirs(p, exist_ok=True)


# ===================== BUG CLASSIFICATION =====================
def classify_klee_error(idx_dir: Path) -> Tuple[Optional[str], Optional[str]]:
    err_files = list(idx_dir.glob("*.err"))
    if not err_files:
        return None, None
    p = err_files[0]
    try: txt = p.read_text(errors="ignore")
    except: txt = ""
    name = p.name.lower()
    if "assert" in name or "assert" in txt: return "CRASH", "ASSERTION"
    if "invalid read" in txt or "invalid write" in txt or "ptr" in name: return "CRASH", "INVALID_MEM"
    if "abort" in name or "abort" in txt: return "CRASH", "ABORT"
    return "CRASH", "UNKNOWN"


# ===================== Bug corpus =====================
_BUG_CORPUS_PATH: Optional[Path] = None

def _init_bug_corpus(regex_dir: Path) -> None:
    global _BUG_CORPUS_PATH
    _BUG_CORPUS_PATH = regex_dir / "bug_corpus.jsonl"

def _append_bug_entry(entry: dict) -> None:
    if _BUG_CORPUS_PATH is None: return
    try:
        with open(_BUG_CORPUS_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass

def _load_bug_corpus_fragments(regex_dir: Path) -> List[str]:
    """Load regexes from bug corpus for fragment extraction."""
    path = regex_dir / "bug_corpus.jsonl"
    if not path.exists(): return []
    frags = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip(): continue
            entry = json.loads(line)
            rx = entry.get("regex")
            if rx: frags.append(rx)
    except Exception:
        pass
    return frags


# ----------------------------- main ----------------------------- #
if __name__ == "__main__":
    parser = optparse.OptionParser()
    parser.add_option("--pgm", dest="pgm",
                      help=("Benchmarks : csplit, diff,expr, find, gawk, grep, m4, "
                            "ptx, sed, nano, tac, nl"),
                      choices=["csplit", "diff", "expr", "find", "gawk",
                               "grep", "m4", "ptx", 
                               "sed", "nano", "tac", "nl"])
    parser.add_option("--output_dir", dest="output_dir", help="Result directory")
    parser.add_option("--config", dest="config", type="int", default=1, help="Configuration number to use (Default: 1)")
    parser.add_option("--resume", dest="resume", action="store_true", default=False, help="Append new iterations to an existing output_dir")
    parser.add_option("--total_budget", dest="total_time", type="int", default=86400, help="Total time budget (sec)")
    parser.add_option("--small_budget", dest="small_time", type="int", default=120, help="Per-weight small time budget (sec)")
    parser.add_option("--n_scores", dest="n_scores", type="int", default=20, help="Number of score functions (weights) per iteration")
    parser.add_option("--main_option", dest="main_option", default="featmaker", choices=["featmaker", "naive"])
    parser.add_option("--regex_mode", dest="regex_mode", choices=["bre","ere"], default="ere")
    parser.add_option("--op_stats_init", dest="op_stats_init", default=None)
    parser.add_option("--max_fragment_trials", dest="max_fragment_trials", type="int", default=50, help="Trials per candidate to get a compilable mutated pattern")
    parser.add_option("--w_coverage", dest="w_coverage", type="float", default=0.5, help="Weight for coverage-based reward/mutation (0-1)")
    parser.add_option("--w_bug", dest="w_bug", type="float", default=0.5, help="Weight for bug-based reward/mutation (0-1)")
    parser.add_option("--no_regex_seed_filter", dest="no_regex_seed_filter", action="store_true", default=False,
                      help="Disable regex-reached filtering when selecting seeds (for ablation study)")
    parser.add_option("--no_regex_state_pruning", dest="no_regex_state_pruning", action="store_true", default=False,
                      help="Disable KLEE --guide-by-regex state pruning (for ablation study)")
    parser.add_option("--regex_src_files", dest="regex_src_files",
                      default="regex_internal.c,regex_internal.h,regcomp.c,regexec.c,dfa.c,dfasearch.c",
                      help="Comma-separated regex source-file basenames used to build the "
                           "regex function set for KLEE state initialization")
    parser.add_option("--manual", dest="manual", default=None,
                      help="Path to the program manual (PDF/HTML/text) used for preparation "
                           "(option pool, regex format, dual-src). Overrides pgm_config['manual'] "
                           "and the COMPOSE_MANUAL_DIR lookup.")

    (options, args) = parser.parse_args()

    if not options.pgm:
        print("Required option is empty: pgm"); exit(1)
    if not options.output_dir:
        print("Required option is empty: output_dir"); exit(1)

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

    # Prepare / resume
    if not os.path.exists(top_dir):
        ensure_dirs([top_dir, f"{top_dir}/result", f"{top_dir}/weight", f"{top_dir}/errors",
                     f"{top_dir}/features", f"{top_dir}/data"])
        start_iter = 0
    else:
        if not options.resume:
            print("Output directory is already existing"); exit(1)
        iters = []
        for d in os.listdir(f"{top_dir}/result"):
            if d.startswith("iteration-"):
                try: iters.append(int(d.split("-")[-1]))
                except Exception: pass
        start_iter = (max(iters) + 1) if iters else 0
        print(f"[resume] start from iteration {start_iter}")

    # Load config
    pconfig_base = load_pgm_config(config_file)
    # Resolve config-relative paths against the SHARED CompoSE root (compose_root()),
    # not the tool CWD -- so pgm_config can live at CompoSE/pgm_config/ and be shared.
    for key in ["pgm_dir", "gcov_path", "src_file"]:
        if key in pconfig_base:
            pconfig_base[key] = _resolve_cfg_path(pconfig_base[key], _cfg_root)
    pconfig_base["exec_dir"] = pconfig_base.get("exec_dir", "").lstrip("/")

    # --manual CLI override feeds the manual-based preparation for this program.
    if options.manual:
        _MANUAL_CLI_OVERRIDE[pgm] = options.manual

    # Regex dir
    regex_dir = Path(top_dir) / "regex"
    regex_dir.mkdir(exist_ok=True)

    seed_cache = SeedCache(Path(top_dir) / "seed_cache")

    # ── Log regex-based state guiding configuration ──
    print(f"[regex-guiding] KLEE guide-by-regex={'OFF' if options.no_regex_state_pruning else 'ON'}, "
          f"seed-filter={'OFF' if options.no_regex_seed_filter else 'ON'}")

    # Bug corpus init
    _init_bug_corpus(Path(top_dir) / "regex")

    # op_stats
    OPSTAT_PATH = regex_dir / "op_stats.json"
    if options.op_stats_init and not OPSTAT_PATH.exists():
        try:
            with open(options.op_stats_init, "r") as f:
                seed = json.load(f)
            normalized = {
                OP_FRAGMENT: {
                    "tries": int(seed.get(OP_FRAGMENT, {}).get("tries", 0)),
                    "reward": float(seed.get(OP_FRAGMENT, {}).get("reward", 0.0)),
                    "success": int(seed.get(OP_FRAGMENT, {}).get("success", 0)),
                },
                OP_RANDOM: {
                    "tries": int(seed.get(OP_RANDOM, {}).get("tries", 0)),
                    "reward": float(seed.get(OP_RANDOM, {}).get("reward", 0.0)),
                    "success": int(seed.get(OP_RANDOM, {}).get("success", 0)),
                },
            }
            OPSTAT_PATH.write_text(json.dumps(normalized, ensure_ascii=False, indent=2))
            print(f"[init] Seeded op_stats from {options.op_stats_init}")
        except Exception as e:
            print(f"[warn] Failed to seed op_stats: {e}")

    def load_op_stats():
        try:
            d = json.loads(OPSTAT_PATH.read_text())
        except Exception:
            d = {}
        for key in (OP_FRAGMENT, OP_RANDOM):
            slot = d.setdefault(key, {"tries": 0, "reward": 0.0, "success": 0})
            slot.setdefault("tries", 0); slot.setdefault("reward", 0.0); slot.setdefault("success", 0)
        return d

    def save_op_stats(d: dict):
        OPSTAT_PATH.write_text(json.dumps(d, ensure_ascii=False, indent=2))

    # Fragment DB
    FRAG_PKL = regex_dir / "fragments.pkl"
    fdb = FragmentDB(FRAG_PKL)
    # Note: kind migration happens on load, so saving right away normalizes the format.
    # Includes purging of fail_compile items.
    fdb.save()
    fdb.export_preview(regex_dir / "fragments_preview.tsv")

    # Inject fragments from bug corpus into FragmentDB (if w_bug > 0)
    if options.w_bug > 0:
        bug_rxs = _load_bug_corpus_fragments(regex_dir)
        if bug_rxs:
            injected = 0
            for rx in bug_rxs[-200:]:  # last 200 bug regexes
                try:
                    nodes = parse_regex_nodes(rx)
                    for nd in nodes:
                        if nd.kind != "LITERAL" and nd.text:
                            key = (nd.kind, nd.text)
                            if key not in fdb.items:
                                fdb.items[key] = FragItem(nd.kind, nd.text, FragStat(
                                    reward_sum=0.5, success=1, n=1
                                ))
                                injected += 1
                except Exception:
                    pass
            if injected > 0:
                fdb.save()
                print(f"[bug-corpus] Injected {injected} fragments from {len(bug_rxs)} bug regexes")

    # Copy obj-llvm
    llvm_dir = pconfig_base["pgm_dir"]
    obj_copy_target = f"{top_dir}/obj-llvm"
    if not os.path.exists(obj_copy_target):
        run(["cp", "-r", llvm_dir, obj_copy_target], check=True)

    # -------- build src pool --------
    pgm_dir_abs = pconfig_base.get("pgm_dir", "")
    src_base_dir = _derive_src_base_dir_from_pgm_dir(pgm_dir_abs, pgm=pgm) if pgm_dir_abs else None
    src_pool: List[str] = []
    if src_base_dir and src_base_dir.exists():
        print(f"[src_file] base dir (before obj-llvm): {src_base_dir}")
        src_pool = _build_all_files_pool(src_base_dir)
        print(f"[src_file] pooled files: {len(src_pool)}")
    else:
        print("[src_file] WARNING: cannot derive base dir from pgm_dir.")

    if not src_pool:
        print("[src_file] ERROR: src_pool empty (cannot derive from pgm_dir) -> cannot proceed.")
        exit(1)

    start_time = time.time()
    remaining_time = options.total_time
    iteration = start_iter
    data: Dict[str, List[int]] = {}
    prev_scores_cached: Optional[List[float]] = None
    prev_rewards_cached: Optional[List[float]] = None
    tested_srcs: Set[str] = set()  # Track tested src files for untested-first sampling

    profile_path = regex_dir / "profile.json"
    if not profile_path.exists():
        try:
            profile = _build_regex_profile(pgm, regex_mode)
            _write_profile(profile, profile_path)
        except Exception as e:
            print(f"[warn] profile init failed: {e}")

    def _fragment_effectiveness(op_stats: dict) -> float:
        """
        frag_ratio = mut_avg / (mut_avg + rand_avg)

        Compares the *average reward* earned by fragment-mutation regexes
        against that earned by fresh/random regexes (paper formulation).

        We use the average reward instead of a binary success rate because
        nearly every regex covers at least one new branch in a 120 s budget,
        which collapses both Laplace-smoothed success rates to ~1.0 and
        pins frag_ratio at 0.5 regardless of which strategy is actually
        more productive. Returns 0.5 (neutral) when no data has been
        accumulated for a side yet.
        """
        f = op_stats.get(OP_FRAGMENT, {"tries": 0, "reward": 0.0})
        r = op_stats.get(OP_RANDOM,   {"tries": 0, "reward": 0.0})
        f_tries = int(f.get("tries", 0))
        r_tries = int(r.get("tries", 0))

        if f_tries == 0 and r_tries == 0:
            return 0.5

        f_eff = float(f.get("reward", 0.0)) / max(1, f_tries)
        r_eff = float(r.get("reward", 0.0)) / max(1, r_tries)
        total = f_eff + r_eff
        if total <= 0.0:
            return 0.5
        return f_eff / total

    def _weighted_sample_without_replacement(idxs: List[int], weights: List[float], k: int) -> List[int]:
        """
        Weighted sampling without replacement (no hyper params).
        """
        k = min(k, len(idxs))
        if k <= 0:
            return []
        chosen = []
        items = list(zip(idxs, weights))
        for _ in range(k):
            total = sum(w for _, w in items)
            if total <= 0:
                i = random.randrange(len(items))
                chosen.append(items.pop(i)[0])
                continue
            r = random.random() * total
            acc = 0.0
            pick_i = 0
            for j, (idx, w) in enumerate(items):
                acc += w
                if acc >= r:
                    pick_i = j
                    break
            chosen.append(items.pop(pick_i)[0])
        return chosen

    while remaining_time > 0:
        print(f"\n===== Iteration {iteration} (remaining {int(remaining_time)}s) =====")
        ensure_dirs([f"{top_dir}/result/iteration-{iteration}", f"{top_dir}/weight/iteration-{iteration}"])

        # ---------- PREVIOUS iteration ----------
        if iteration != 0:
            prev_iter = iteration - 1
            print(f"Generate data from iteration {prev_iter}")
            prev_src_files = _load_recorded_src_files(regex_dir, prev_iter)
            prev_src_first = prev_src_files[0] if prev_src_files else ""
            pconfig_prev = dict(pconfig_base)
            if prev_src_first:
                pconfig_prev["src_file"] = prev_src_first

            dg_prev = data_generator.data_generator(pconfig_prev, top_dir, options); dg_prev.generate_data(prev_iter)

            print(f"Generate features from iteration {prev_iter}")
            fg_prev = feature_generator.feature_generator(data, top_dir, options)
            fg_prev.collect(iteration); fg_prev.extract_feature()

            print(f"Generate weights for iteration {iteration}")
            wg_prev = (weight_generator.learning_weight_generator if options.main_option == "featmaker"
                       else weight_generator.random_weight_generator)(data, top_dir, options.n_scores)
            if "features" not in data:
                raise KeyError("feature_generator.extract_feature() didn't populate data['features']")
            wg_prev.generate_weight(iteration)

            try:
                this_txt = regex_dir / f"iteration-{prev_iter}.txt"
                regex_list_prev = [l.strip() for l in this_txt.read_text().splitlines() if l.strip()] if this_txt.exists() else []

                covered_sets_prev = _covered_sets_for_iteration(top_dir, prev_iter, options.n_scores)
                freq_cum_before = _load_freq_cum(regex_dir)
                scores_prev: List[float] = _score_from_freq_map(covered_sets_prev, freq_cum_before)
                _save_iteration_score_snapshot(regex_dir, prev_iter, scores_prev)

                try:
                    chosen_src_files_prev = _load_recorded_src_files(regex_dir, prev_iter) or []
                    chosen_opts_prev = _load_recorded_options(regex_dir, prev_iter, options.n_scores) or []
                    src_scores_map = _load_score_map(_src_score_path(regex_dir))
                    opt_scores_map = _load_score_map(_option_score_path(regex_dir))

                    for i, sc in enumerate(scores_prev):
                        if chosen_src_files_prev and i < len(chosen_src_files_prev):
                            src = chosen_src_files_prev[i]
                            if src:
                                src_scores_map[src] = float(src_scores_map.get(src, 0.0)) + float(sc)
                        if chosen_opts_prev and i < len(chosen_opts_prev):
                            opt = chosen_opts_prev[i]
                            if opt:
                                opt_scores_map[opt] = float(opt_scores_map.get(opt, 0.0)) + float(sc)

                    _save_score_map(_src_score_path(regex_dir), src_scores_map)
                    _save_score_map(_option_score_path(regex_dir), opt_scores_map)
                except Exception as e:
                    print(f"[warn] score map update failed: {e}")

                freq_cum_after = Counter(freq_cum_before)
                for s in covered_sets_prev:
                    for b in s:
                        freq_cum_after[b] += 1

                op_stats = load_op_stats()
                prev_prev_scores = _load_iteration_score_snapshot(regex_dir, prev_iter - 1, options.n_scores) if prev_iter - 1 >= 0 else []

                meta_path = regex_dir / f"iteration-{prev_iter}.meta.json"
                meta = json.loads(meta_path.read_text()).get("mutants", []) if meta_path.exists() else []

                raw_deltas = []
                for i in range(options.n_scores):
                    now = float(scores_prev[i]) if i < len(scores_prev) else 0.0
                    old = float(prev_prev_scores[i]) if i < len(prev_prev_scores) else 0.0
                    raw_deltas.append(max(0.0, now - old))
                # NOTE: 'scale' kept only for legacy logging; cov_reward now uses
                # the absolute paper formula score_cov(r) = Σ 1/√(freq(b)+1).
                scale = max(1.0, max(raw_deltas) if raw_deltas else 1.0)

                # ── Bug reward: replay-based actual perf measurement ──
                replay_binary = _locate_program_binary(pconfig_base, pgm)
                prev_dir = Path(top_dir) / f"result/iteration-{prev_iter}"

                # ── Combined reward per idx ──
                combined_reward_per_idx: List[float] = [0.0] * options.n_scores

                for idx, entry in enumerate(meta):
                    if idx >= options.n_scores: break
                    # Coverage reward — paper formula (absolute, no normalization)
                    # with log1p applied to align scale with score_bug (which is
                    # already log-scale). score_cov(r) = Σ 1/√(freq(b)+1) is
                    # preserved as-is for parent ranking, snapshot logging, etc.;
                    # the log compression is applied ONLY to the reward signal.
                    abs_now = float(scores_prev[idx]) if idx < len(scores_prev) else 0.0
                    abs_old = float(prev_prev_scores[idx]) if idx < len(prev_prev_scores) else 0.0
                    raw_delta = abs_now - abs_old
                    if REWARD_CLAMP_MAX is not None:
                        raw_delta = min(raw_delta, REWARD_CLAMP_MAX)
                    cov_reward = math.log1p(max(0.0, abs_now))

                    # Bug score: replay ktest with actual binary → time + crash (raw).
                    idx_dir = prev_dir / f"{idx}"
                    replay_time, replay_rss = _measure_replay_perf(idx_dir, replay_binary)
                    crash_kind, crash_detail = classify_klee_error(idx_dir)
                    has_crash = (crash_kind == "CRASH")
                    score_bug = _compute_score_bug(replay_time, replay_rss, has_crash)

                    # Combined reward
                    # Paper formula: score(r) = log(1 + score_cov(r)) + log(1 + score_bug(r)).
                    # Both raw scores are log-compressed at this step for symmetric scaling.
                    reward_delta = cov_reward + math.log1p(max(0.0, score_bug))
                    combined_reward_per_idx[idx] = reward_delta

                    # Bug corpus logging — only timeout-near or crash regexes
                    if score_bug > 5.0 or has_crash:
                        regex_prev = regex_list_prev[idx] if idx < len(regex_list_prev) else None
                        _append_bug_entry({
                            "iteration": prev_iter, "widx": idx, "tool": pgm,
                            "regex": regex_prev,
                            "replay_time": replay_time, "replay_rss_kb": replay_rss,
                            "has_crash": has_crash, "crash_detail": crash_detail,
                            "score_bug": score_bug,
                            "cov_reward": cov_reward,
                            "combined_reward": reward_delta,
                        })

                    ops_used = entry.get("ops", [])
                    has_fragment = any(isinstance(op, dict) and op.get("op") == OP_FRAGMENT for op in ops_used)
                    if has_fragment:
                        st = op_stats.setdefault(OP_FRAGMENT, {"tries": 0, "reward": 0.0, "success": 0})
                        st["tries"] += 1
                        st["reward"] += reward_delta
                        if reward_delta > 0.0:
                            st["success"] = st.get("success", 0) + 1
                    else:
                        # Random / fresh regex bookkeeping for adaptive frag_ratio.
                        st = op_stats.setdefault(OP_RANDOM, {"tries": 0, "reward": 0.0, "success": 0})
                        st["tries"] += 1
                        st["reward"] += reward_delta
                        if reward_delta > 0.0:
                            st["success"] = st.get("success", 0) + 1

                    frag_ops = [op for op in ops_used if isinstance(op, dict) and op.get("op") == OP_FRAGMENT and op.get("to_text")]
                    m = max(1, len(frag_ops))
                    share = reward_delta / m
                    for op in frag_ops:
                        knd = op.get("to_kind"); txt = op.get("to_text")
                        if knd and txt:
                            nk = _map_old_kind_to_new(knd, txt) or knd
                            if nk in ALL_KINDS:
                                fdb.record_reward(nk, txt, share)

                save_op_stats(op_stats)
                _save_freq_cum(regex_dir, freq_cum_after)

                try:
                    _store_best_seed_ktests(top_dir, prev_iter, regex_list_prev, freq_cum_after, seed_cache,
                                            filter_regex=not options.no_regex_seed_filter)
                except Exception as e:
                    print(f"[warn] failed to refresh seed cache: {e}")

                # Parent selection
                parent_scores_for_selection = [
                    combined_reward_per_idx[i]
                    for i in range(min(options.n_scores, len(combined_reward_per_idx)))
                ]

                top_k_seed = max(1, len(parent_scores_for_selection) // 4)
                best_idxs_seed = sorted(range(len(parent_scores_for_selection)),
                                        key=lambda i: parent_scores_for_selection[i], reverse=True)[:top_k_seed]
                top_regexes = [regex_list_prev[i] for i in best_idxs_seed if i < len(regex_list_prev)]

                rand_regexes = []
                if regex_list_prev:
                    pool = regex_list_prev[:]
                    random.shuffle(pool)
                    rand_regexes = pool[:min(max(10, len(pool)//10), len(pool))]

                diverse_regexes = []
                if regex_list_prev:
                    candidates = regex_list_prev[:]
                    random.shuffle(candidates)
                    chosen_tokens = [_tokenize_regex_for_diversity(r) for r in (top_regexes[:10] + rand_regexes[:10])]
                    for rx in candidates:
                        if len(diverse_regexes) >= max(8, len(regex_list_prev)//20):
                            break
                        toks = _tokenize_regex_for_diversity(rx)
                        if not chosen_tokens:
                            diverse_regexes.append(rx)
                            chosen_tokens.append(toks)
                            continue
                        sims = [_jaccard_tokens(toks, ct) for ct in chosen_tokens]
                        if sims and max(sims) < 0.35:
                            diverse_regexes.append(rx)
                            chosen_tokens.append(toks)

                fdb.add_from_patterns(top_regexes + rand_regexes + diverse_regexes)

                # -------- PRUNING APPLY (NEW) --------
                try:
                    removed = fdb.prune(cur_iter=prev_iter)
                    if removed > 0:
                        print(f"[prune] removed={removed} fragments at iter={prev_iter} (after feedback)")
                except Exception as e:
                    print(f"[warn] pruning failed: {e}")

                fdb.save()
                fdb.export_preview(regex_dir / "fragments_preview.tsv")

                prev_scores_cached = scores_prev[:]
                prev_rewards_cached = combined_reward_per_idx[:]

                try:
                    profile = _build_regex_profile(pgm, regex_mode)
                    _write_profile(profile, profile_path)
                except Exception as e:
                    print(f"[warn] profile build failed: {e}")

            except Exception as e:
                print(f"[warn] feedback update failed: {e}")

            try:
                for widx in range(options.n_scores):
                    src = Path(top_dir) / f"{widx}_result.pkl"
                    if src.exists():
                        dst_dir = Path(top_dir) / f"data/iteration-{prev_iter}"
                        dst_dir.mkdir(parents=True, exist_ok=True)
                        dst = dst_dir / f"{widx}_result.pkl"
                        try: shutil.move(str(src), str(dst))
                        except Exception:
                            try: shutil.copy2(str(src), str(dst)); os.remove(str(src))
                            except Exception: pass
            except Exception:
                pass

            _purge_iteration_ktest_gcov(top_dir, prev_iter)

        # ---------- Generate CURRENT iteration ----------
        op_stats_now = load_op_stats()

        # frag_ratio = mutation_eff / (mutation_eff + random_eff)
        if len(fdb.items) > 0:
            if iteration == 1:
                frag_ratio = 0.5
            else:
                frag_ratio = max(0.3, _fragment_effectiveness(op_stats_now))
        else:
            frag_ratio = 0.0

        n_frag = int(round(options.n_scores * frag_ratio))
        n_frag = max(0, min(options.n_scores, n_frag))

        # Unified mutation: no cov/bug split. Position priority (bug-style) and
        # fragment selection (UCB-weighted probabilistic sampling) drive a
        # single mutation path; combined reward drives parent selection.
        print(f"[policy] frag_ratio={frag_ratio:.3f} -> n_frag={n_frag}/{options.n_scores}")

        if iteration == 0:
            out_file = regex_dir / f"iteration-{iteration}.txt"
            generate_regexes(options.n_scores, regex_mode, out_file, profile_path=profile_path)
            (regex_dir / f"iteration-{iteration}.meta.json").write_text(
                json.dumps({"mutants": [{"parent": None, "ops": []} for _ in range(options.n_scores)]},
                           ensure_ascii=False, indent=2)
            )
        else:
            prev_scores = prev_scores_cached or _load_iteration_score_snapshot(regex_dir, iteration-1, options.n_scores)
            if not prev_scores:
                covered_sets_prev = _covered_sets_for_iteration(top_dir, iteration-1, options.n_scores)
                freq_live = _load_freq_cum(regex_dir)
                prev_scores = _score_from_freq_map(covered_sets_prev, freq_live)

            prev_txt = regex_dir / f"iteration-{iteration-1}.txt"
            prev_regexes = [l.strip() for l in prev_txt.read_text().splitlines() if l.strip()] if prev_txt.exists() else []

            new_regexes: List[str] = []
            meta_entries: List[Dict] = []

            # Parent selection now uses combined reward (cov + bug, both log-scale).
            # Falls back to score_cov on the first mutation iteration where the
            # previous reward array has not been populated yet.
            prev_rewards = prev_rewards_cached if prev_rewards_cached else prev_scores
            parent_indices = list(range(min(len(prev_regexes), len(prev_rewards))))

            # ── UNIFIED MUTATION ──
            if parent_indices and n_frag > 0 and len(fdb.items) > 0:
                weights = [max(0.0, float(prev_rewards[i])) + 1e-9 for i in parent_indices]
                chosen_parents = _weighted_sample_without_replacement(parent_indices, weights, n_frag)

                iter_used_counter = Counter()
                kind_used_counter = Counter()

                n_mut_created = 0
                for bi in chosen_parents:
                    if n_mut_created >= n_frag: break
                    base = prev_regexes[bi] if bi < len(prev_regexes) else ""
                    if not base:
                        continue

                    muts, ops_used_list = mutate_candidates_for_parent(
                        base,
                        fdb,
                        regex_mode=regex_mode,
                        frag_ratio=frag_ratio,
                        current_iteration=iteration,
                        max_trials=options.max_fragment_trials,
                        iter_used_counter=iter_used_counter,
                        kind_used_counter=kind_used_counter
                    )
                    if not muts:
                        continue

                    scored_pool: List[Tuple[float, str, List[dict]]] = []
                    for j in range(len(muts)):
                        ops_j = ops_used_list[j] if j < len(ops_used_list) else []
                        pred = _predict_mutant_quality(ops_j, fdb)
                        scored_pool.append((pred, muts[j], ops_j))
                    scored_pool.sort(key=lambda x: x[0], reverse=True)

                    pred, rx, ops_j = scored_pool[0]
                    new_regexes.append(rx)
                    meta_entries.append({"parent": bi, "ops": ops_j, "pred_score": float(pred), "mode": "mutation"})
                    n_mut_created += 1

                print(f"[mutate] parents={len(chosen_parents)} produced={n_mut_created}/{n_frag}")

            need_more = options.n_scores - len(new_regexes)
            if need_more > 0:
                tmp_file = regex_dir / f".tmp-fill-{iteration}.txt"
                generate_regexes(need_more, regex_mode, tmp_file, profile_path=profile_path)
                fills = [l.strip() for l in tmp_file.read_text().splitlines() if l.strip()]
                new_regexes += fills
                meta_entries += [{"parent": None, "ops": [], "mode": "fresh"} for _ in range(len(fills))]

            new_regexes = new_regexes[:options.n_scores]
            meta_entries = meta_entries[:options.n_scores]
            out_txt = regex_dir / f"iteration-{iteration}.txt"
            out_txt.write_text("\n".join(new_regexes))
            (regex_dir / f"iteration-{iteration}.meta.json").write_text(
                json.dumps({"mutants": meta_entries}, ensure_ascii=False, indent=2)
            )

        # --------- Build per-weight sym options & record ---------
        regex_txt = regex_dir / f"iteration-{iteration}.txt"
        with open(regex_txt, "r") as rf:
            regexes = [ln.strip() for ln in rf if ln.strip()]

        seed_dirs_map = [seed_cache.find(rx) for rx in regexes]

        # --- Get usage profile for this program ---
        usage_profile = _get_usage_profile(pconfig_base, pgm)
        if iteration == start_iter:
            # Save profile on first iteration for debugging
            _save_usage_profile(regex_dir, pgm, usage_profile)
            print(f"[profile] {pgm}: source={usage_profile.get('source')}, "
                  f"arg_order={usage_profile.get('arg_order')}, "
                  f"regex_options={usage_profile.get('regex_options', [])}, "
                  f"separator_flags={usage_profile.get('separator_flags', [])}, "
                  f"uses_slash_wrap={usage_profile.get('uses_slash_wrap')}, "
                  f"needs_dual_src={usage_profile.get('needs_dual_src')}")

        # --- Determine if we need dual src files (diff) ---
        needs_dual_src = usage_profile.get("needs_dual_src", False)
        src_count_needed = options.n_scores * 2 if needs_dual_src else options.n_scores

        # --- src_file selection (combined binary+freq) ---
        recorded_src = _load_recorded_src_files(regex_dir, iteration)
        if recorded_src:
            chosen_src_files = recorded_src
            best_src = recorded_src[0]
            best_src_score = None

        elif src_pool:
            freq_cum = _load_freq_cum(regex_dir)
            chosen_src_files, best_src = _select_src_combined(
                pgm, regex_mode, pconfig_base, src_pool, src_count_needed,
                SRC_SAMPLE_COUNT * (2 if needs_dual_src else 1),
                freq_cum, tested_srcs, usage_profile=usage_profile
            )
            best_src_score = None

            if len(chosen_src_files) < src_count_needed:
                fill = _pick_random_items(src_pool, src_count_needed - len(chosen_src_files))
                chosen_src_files += fill
        else:
            fallback_src = ""
            chosen_src_files = [fallback_src] * src_count_needed
            best_src = fallback_src
            best_src_score = None


        if not best_src:
            print("[src_file] ERROR: chosen src_file empty")
            exit(1)

        # --- Option selection (combined binary+freq weighted random) ---
        recorded_opts = _load_recorded_options(regex_dir, iteration, options.n_scores)
        if recorded_opts:
            # resume case: keep the recorded values as-is
            chosen_options = recorded_opts
            best_option = recorded_opts[0] if recorded_opts else ""
            best_option_score = None

        else:
            # Fallback candidate pool (used only when no regex options are found):
            # prefer the manual-derived option list, else fall back to --help.
            candidates = list(usage_profile.get("all_options", []))
            if not candidates:
                candidates = _get_help_flag_candidates(pconfig_base, pgm)
            regex_options = list(usage_profile.get("regex_options", []))
            accepts_options = usage_profile.get("accepts_options", True)

            if not accepts_options:
                if regex_options:
                    option_pool = regex_options
                else:
                    chosen_options = [""] * options.n_scores
                    best_option = ""
                    best_option_score = None
            if accepts_options or (not accepts_options and regex_options):
                if regex_options:
                    option_pool = regex_options
                else:
                    option_pool = candidates

                if not option_pool:
                    chosen_options = [""] * options.n_scores
                    best_option = ""
                    best_option_score = None
                else:
                    freq_cum = _load_freq_cum(regex_dir)
                    chosen_options, best_option = _select_options_combined(
                        pgm, regex_mode, pconfig_base, best_src, option_pool,
                        options.n_scores, freq_cum, usage_profile=usage_profile)
                    best_option_score = None


        pconfig_iter = dict(pconfig_base)
        pconfig_iter["src_file"] = best_src
        base_sym_args = pconfig_iter.get("sym_args", "")

        sym_list, sanit_marks = build_sym_options_list(
            regexes,
            chosen_src_files,
            base_sym_args,
            pgm,
            regex_mode,
            profile_path=profile_path,
            extra_flag=chosen_options,
            usage_profile=usage_profile
        )
        pconfig_iter["sym_options_list"] = sym_list
        pconfig_iter["seed_dirs_map"] = seed_dirs_map

        # ── Regex-based state guiding (unless disabled for ablation) ──
        extra_klee_args = pconfig_iter.get("extra_klee_args", [])
        if not options.no_regex_state_pruning:
            extra_klee_args.append("--guide-by-regex")
            # KLEE builds the regex function set for state initialization from the
            # regex source files (all_only).
            extra_klee_args.append(f"-regex-src-files={options.regex_src_files}")
        pconfig_iter["extra_klee_args"] = extra_klee_args

        iter_cfg_path = regex_dir / f"iteration-{iteration}.json"
        with open(iter_cfg_path, "w") as jf:
            json.dump({**pconfig_iter, "generated_regexes": regexes,
                       "sanitization": sanit_marks, "sanitization_version": 8,
                       "regex_mode_effective": regex_mode,
                       "chosen_src_files": chosen_src_files,
                       "best_src_file": best_src,
                       "best_src_score": best_src_score,
                       "chosen_options": chosen_options,
                       "chosen_option": best_option,
                       "chosen_option_score": best_option_score,
                       "option_candidates": chosen_options,
                       "usage_profile": usage_profile},
                      jf, indent=2)

        # ---------- Run KLEE ----------
        # m4: use the no-optimize executor (m4 fails to produce test cases under KLEE --optimize)
        if pgm == "m4":
            ke = klee_executor_regex_no_opt.klee_executor(pconfig_iter, top_dir, options)
        else:
            ke = klee_executor_regex.klee_executor(pconfig_iter, top_dir, options)
        ke.execute_klee(iteration, int(remaining_time))

        # tidy
        try:
            os.chdir(f"{top_dir}/result")
            os.system('find . -type f -name "assembly.ll" -exec rm -f {} +')
        finally:
            os.chdir(root_dir)

        remaining_time = options.total_time - (time.time() - start_time)
        print(f"[DONE] iteration-{iteration}")
        iteration += 1
    # ================== AFTER LOOP ==================
    print("\nTesting Done. Please wait for collecting data")
    final_prev = iteration - 1
    if final_prev >= 0:
        final_src_files = _load_recorded_src_files(regex_dir, final_prev)
        final_src_first = final_src_files[0] if final_src_files else ""
        pconfig_last = dict(pconfig_base)
        if final_src_first:
            pconfig_last["src_file"] = final_src_first

        dg_last = data_generator.data_generator(pconfig_last, top_dir, options); dg_last.generate_data(final_prev)
        fg_last = feature_generator.feature_generator(data, top_dir, options); fg_last.collect(iteration)
    print("Collecting Done")

    try:
        this_txt = regex_dir / f"iteration-{final_prev}.txt"
        regex_list_prev = [l.strip() for l in this_txt.read_text().splitlines() if l.strip()] if this_txt.exists() else []

        covered_sets_final = _covered_sets_for_iteration(top_dir, final_prev, options.n_scores)
        freq_cum_live = _load_freq_cum(regex_dir)

        scores_final = _score_from_freq_map(covered_sets_final, freq_cum_live)
        _save_iteration_score_snapshot(regex_dir, final_prev, scores_final)

        try:
            freq_cum_final = Counter(freq_cum_live)
            for s in covered_sets_final:
                for b in s:
                    freq_cum_final[b] += 1
            _store_best_seed_ktests(top_dir, final_prev, regex_list_prev, freq_cum_final, seed_cache,
                                    filter_regex=not options.no_regex_seed_filter)
            _save_freq_cum(regex_dir, freq_cum_final)
        except Exception as e:
            print(f"[warn] final seed cache update failed: {e}")
    except Exception as e:
        print(f"[warn] final snapshot failed: {e}")

    try:
        for widx in range(options.n_scores):
            src = Path(top_dir) / f"{widx}_result.pkl"
            if src.exists():
                dst_dir = Path(top_dir) / f"data/iteration-{final_prev}"
                dst_dir.mkdir(parents=True, exist_ok=True)
                dst = dst_dir / f"{widx}_result.pkl"
                try: shutil.move(str(src), str(dst))
                except Exception:
                    try: shutil.copy2(str(src), str(dst)); os.remove(str(src))
                    except Exception: pass
    except Exception:
        pass

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

    try:
        os.chdir(top_dir)
        os.system("rm -rf obj-llvm")
        os.system("rm *_result.pkl")
        os.system("rm -r errors")
        os.system("find data -type f -name '*.pkl' -delete")
        os.system("find data -type d -empty -delete")
    finally:
        os.chdir(root_dir)

    os.system(f"find '{top_dir}' -type f -name '*.ktest_gcov' -delete")
    print("\nAll done.")