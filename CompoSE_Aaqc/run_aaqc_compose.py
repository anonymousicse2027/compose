#!/usr/bin/env python3
import argparse, os, sys, subprocess as sp, glob, shlex, random, string, tempfile, signal
import re, shutil, json, math, pickle, uuid, hashlib, time
from pathlib import Path
from _shared import get_regex_mode, compose_root  
from typing import Optional, List, Set, Dict, Tuple, Union
from collections import Counter
from dataclasses import dataclass, asdict, field
from difflib import SequenceMatcher
from compose_common import *
from compose_regex import *
from compose_profile import *
from compose_coverage import *

parser = argparse.ArgumentParser()
parser.add_argument('-t', '--time-budget', default=86400, type=int)
parser.add_argument('-p', '--program', required=True, type=str)
parser.add_argument('--small-budget', default=120, type=int)
parser.add_argument('--n_scores', dest='n_scores', default=20, type=int,
                    help='Number of regexes (sub-runs) per iteration/set (default=20). '
                         'Use multiples of 4 (e.g. 12, 20, 28) for correct round-robin set boundaries.')
parser.add_argument('--regex-mode', type=str, default=None, choices=['bre', 'ere', 'pcre'])
parser.add_argument('--gcov-obj', type=str, default=None, help='gcov binary for coverage collection')
parser.add_argument('--gcov-depth', type=int, default=1)
parser.add_argument('--pgm-config', type=str, default=None, help='FeatMaker pgm_config JSON (uses FeatMaker paths/script_independent)')
parser.add_argument('--w-coverage', default=0.6, type=float, help='Coverage mutation weight (default=0.6)')
parser.add_argument('--w-bug', default=0.4, type=float, help='Bug mutation weight (default=0.4)')
parser.add_argument('--no-regex-seed-filter', action='store_true', default=False,
                    help='Disable regex-reached filtering when storing seeds (for ablation study)')
parser.add_argument('--no-regex-state-pruning', action='store_true', default=False,
                    help='Disable KLEE --guide-by-regex state pruning (for ablation study)')
parser.add_argument('--regex-src-files',
                    default='regex_internal.c,regex_internal.h,regcomp.c,regexec.c,dfa.c,dfasearch.c',
                    help='Comma-separated regex source-file basenames used to build the '
                         'regex function set for KLEE state initialization (all_only)')
args = parser.parse_args(argv)

budget = args.time_budget; prog = args.program; small_budget = args.small_budget
SET_SIZE = args.n_scores  
if SET_SIZE < 4:
    print(f"[WARN] --n_scores={SET_SIZE} < 4 (N_BUILDS); this breaks round-robin set boundaries. Use a multiple of 4 (e.g. 12, 20, 28).")
elif SET_SIZE % 4 != 0:
    print(f"[WARN] --n_scores={SET_SIZE} is not a multiple of 4 (N_BUILDS); set boundaries may drift. Recommended: 12, 20, 28.")
rm = args.regex_mode or get_regex_mode(prog, "ere")

pcfg = None
_pgm_cfg_path = args.pgm_config
if not _pgm_cfg_path:
    _cr = compose_root()
    if _cr:
        _cand = _cr / "pgm_config" / f"{prog}100.json"
        if _cand.exists(): _pgm_cfg_path = str(_cand)
if _pgm_cfg_path:
    cp = Path(_pgm_cfg_path)
    if not cp.exists():
        print(f"[ERROR] pgm-config not found: {cp}"); sys.exit(1)
    try:
        pcfg = json.loads(cp.read_text(encoding='utf-8'))
        if 'pgm' not in pcfg and 'pgm_name' in pcfg: pcfg['pgm'] = pcfg['pgm_name']
        for k in ('pgm', 'pgm_dir', 'gcov_path', 'exec_dir', 'src_file', 'sym_args'): pcfg.setdefault(k, '')
        ROOT = str(compose_root() or Path.cwd())
        for k in ('pgm_dir', 'gcov_path'):
            v = pcfg.get(k, '')
            if v and not os.path.isabs(v):
                resolved = False
                for base in [ROOT, os.getcwd(), str(cp.parent.parent), str(cp.parent)]:
                    c = os.path.join(base, v)
                    if os.path.exists(c):
                        pcfg[k] = c; resolved = True; break
                if not resolved:
                    print(f"[pgm-config] WARNING: could not resolve {k}={v}")
        print(f"[pgm-config] loaded: pgm={pcfg['pgm']}, pgm_dir={pcfg.get('pgm_dir','')}, gcov_path={pcfg.get('gcov_path','')}")
    except Exception as e:
        print(f"[ERROR] pgm-config parse failed: {e}"); sys.exit(1)

llvm_path = ""
if pcfg and pcfg.get("pgm_dir"):
    _ed = pcfg.get("exec_dir", "").strip("/")
    llvm_path = os.path.join(pcfg["pgm_dir"], _ed, f"{prog}.bc") if _ed else os.path.join(pcfg["pgm_dir"], f"{prog}.bc")
if not llvm_path or not os.path.isfile(llvm_path):
    print(f"[ERROR] LLVM bitcode not found: {llvm_path or '(no pgm_dir in pgm-config)'}"); sys.exit(1)
print(f"[llvm] {llvm_path}")

x = input("Trial?")
_exp_root = os.environ.get("AAQC_EXP_ROOT") or str(Path(__file__).resolve().parent / "experiments")
test_path = f"{_exp_root}/Aaqc{test_dir[prog]}_depth_{x}"
os.makedirs(test_path, exist_ok=True)
rdir = Path(test_path) / "regex_state"; rdir.mkdir(parents=True, exist_ok=True)


gcov_obj = args.gcov_obj
if not gcov_obj and pcfg:
    gp = pcfg.get("gcov_path", ""); ed = pcfg.get("exec_dir", "").strip("/")
    cands = []
    if gp:
        if ed: cands.append(os.path.join(gp, ed, prog))
        cands += [os.path.join(gp, "src", prog), os.path.join(gp, prog)]
    for cand in cands:
        if cand and os.path.isfile(cand) and os.access(cand, os.X_OK):
            gcov_obj = cand; break
    if gcov_obj: print(f"[gcov_obj] from pgm-config: {gcov_obj}")
if not gcov_obj:
    print("[gcov_obj] WARNING: not found in pgm-config, coverage-based feedback disabled")


uprof = _get_prof(prog, pcfg)
print(f"[profile] {uprof['arg_order']}/{uprof['uses_slash_wrap']}/{uprof['needs_dual_src']}/{uprof['special_syntax']}/{uprof['regex_prefix']}/{uprof['accepts_options']}/opts={uprof.get('regex_options',[])}/sep={uprof.get('separator_flags',[])}")

src_base = _derive_src_base(prog, pcfg); spool = []
if src_base: spool = _file_pool(src_base); print(f"[src] pool={len(spool)}")
chosen_src_files = []  
tested_srcs = set()   
if spool:
    chosen_src_files, fsrc = _select_src_combined(
        prog, rm, spool, SET_SIZE, SRC_SAMPLE_COUNT,
        Counter(), tested_srcs, prof=uprof, pcfg=pcfg, gcov_depth=args.gcov_depth)
    print(f'[src] initial {len(chosen_src_files)} files, best={fsrc}')
else:
    fsrc = ""
    chosen_src_files = [""] * SET_SIZE
    print("[src] empty pool")
fsrc2 = None
if prog in _DUAL_SRC:
    p2 = [f for f in spool if f != fsrc]
    if p2: fsrc2, _ = _best_src_binary(prog, rm, p2, min(SRC_SAMPLE_COUNT, len(p2)), prof=uprof, pcfg=pcfg)
    else: fsrc2 = fsrc
    print(f"[src2] {fsrc2}")


ropts = list(uprof.get("regex_options", [])); aopts = uprof.get("all_options", [])
accepts_options = uprof.get("accepts_options", True)

opool = []; bopt = ""; bopt_sc = -1.0
chosen_options = []  
if prog in {"m4"}:
    chosen_options = [""] * SET_SIZE
    bopt = ""
    print(f"[option] {prog}: fixed invocation, skipping option selection")
elif not accepts_options:
    if ropts:
        opool = ropts
        chosen_options, bopt = _select_options_combined(
            prog, rm, fsrc, opool, SET_SIZE,
            Counter(), prof=uprof, pcfg=pcfg, gcov_depth=args.gcov_depth)
        print(f'[option] accepts_options=False, regex options: {ropts}, best={bopt}')
    else:
        print(f"[option] accepts_options=False, skipping options")
elif accepts_options or (not accepts_options and ropts):
    opool = ropts if ropts else aopts
    if opool:
        chosen_options, bopt = _select_options_combined(
            prog, rm, fsrc, opool, SET_SIZE,
            Counter(), prof=uprof, pcfg=pcfg, gcov_depth=args.gcov_depth)
        print(f'[option] initial {len(chosen_options)} options, best={bopt} (pool={opool})')
    else:
        print(f"[option] no candidates")

rgx_prof = _build_rgx_profile(prog, rm)
prof_path = rdir / "regexgen_profile.json"
try: prof_path.write_text(json.dumps(rgx_prof, indent=2), encoding='utf-8')
except: prof_path = None

fdb = FragmentDB(rdir / "fragments.pkl")
seed_cache = SeedCache(rdir / "seeds")

_init_bug_corpus(rdir)
w_cov = args.w_coverage; w_bug = args.w_bug
if fdb and w_bug > 0:
    bug_rxs = _load_bug_corpus_fragments(rdir)
    if bug_rxs:
        injected = 0
        for rx in bug_rxs[-200:]:
            try:
                nodes = parse_nodes(rx)
                for nd in nodes:
                    if nd.kind != "LITERAL" and nd.text:
                        key = (nd.kind, nd.text)
                        if key not in fdb.items:
                            fdb.items[key] = FragItem(nd.kind, nd.text, FragStat(reward_sum=0.5, success=1, n=1))
                            injected += 1
            except: pass
        if injected > 0:
            fdb.save()
            print(f'[bug-corpus] Injected {injected} fragments from {len(bug_rxs)} bug regexes')
osp = rdir / "op_stats.json"
set_regexes: Dict[int, Dict[int, str]] = {}
set_ops: Dict[int, Dict[int, List[dict]]] = {}
set_mut_modes: Dict[int, Dict[int, str]] = {}
set_covsets: Dict[int, Dict[int, Set[str]]] = {}
set_rewards: Dict[int, Dict[int, float]] = {}
prev_set_scores: List[List[float]] = []  


N_BUILDS = 4 
SUBS_PER_BUILD = SET_SIZE // N_BUILDS  
build_j_counts = [0] * N_BUILDS


_AAQC_ROOT = Path(__file__).resolve().parent
_VANILLA_KLEE = str(_AAQC_ROOT / "src" / "valina-build" / "bin" / "klee")
_QC_KLEE = str(_AAQC_ROOT / "src" / "qc-build" / "bin" / "klee")

def build_base_cmd(build_idx):
    """Select KLEE build by build index (0-3)."""
    cache_flag = "-use-node-cache-stp -use-global-id"
    remix = "" if args.no_regex_state_pruning else "--guide-by-regex"
    if remix:
        remix += f" -regex-src-files={args.regex_src_files}"
    if build_idx == 0: return f"{_VANILLA_KLEE} {flags.get(prog, '')} -use-cex-cache -use-branch-cache {remix}"
    elif build_idx == 1: return f"{_QC_KLEE} {flags.get(prog, '')} -use-cex-cache -use-branch-cache=false -use-iso-cache {cache_flag} {remix}"
    elif build_idx == 2: return f"{_QC_KLEE} {flags.get(prog, '')} -use-rebase -use-recursive-rebase -reuse-segments -use-cex-cache=false -use-branch-cache {cache_flag} {remix}"
    else: return f"{_QC_KLEE} {flags.get(prog, '')} -use-rebase -use-recursive-rebase -use-cex-cache=false -use-branch-cache=false -use-iso-cache {cache_flag} {remix}"

def extra_flags(build_idx, sub_j):
    if (sub_j % 3) == 0: return "-search=random-path -search=nurs:covnew"
    elif (sub_j % 3) == 1: return "-search=dfs"
    else: return "-search=nurs:md2u"

for bi in range(N_BUILDS): os.makedirs(f"{test_path}/iteration-{bi}", exist_ok=True)

total_remaining = budget
_deadline = time.monotonic() + budget
print(f"[start] budget={total_remaining}s, small={small_budget}s, mode={rm}")

while time.monotonic() < _deadline:
    j = build_j_counts[0] // SUBS_PER_BUILD  

    if j == 0: frag_ratio = 0.0
    elif j == 1: frag_ratio = 0.5
    else: frag_ratio = max(0.3, _frag_eff(_load_ops(osp)))
    nf = max(0, min(SET_SIZE, int(round(SET_SIZE * frag_ratio))))
    print(f"\n===== Set j={j} frag_ratio={frag_ratio:.3f} nf={nf}/{SET_SIZE} =====")

    if spool:
        freq_cum = _load_freq(rdir)
        chosen_src_files, fsrc = _select_src_combined(
            prog, rm, spool, SET_SIZE, SRC_SAMPLE_COUNT,
            freq_cum, tested_srcs, prof=uprof, pcfg=pcfg, gcov_depth=args.gcov_depth)
        print(f'[src-set {j}] re-selected {len(chosen_src_files)} src files')

    if opool:
        freq_cum = _load_freq(rdir)
        chosen_options, bopt = _select_options_combined(
            prog, rm, fsrc, opool, SET_SIZE,
            freq_cum, prof=uprof, pcfg=pcfg, gcov_depth=args.gcov_depth)
        print(f'[opt-set {j}] re-selected {len(chosen_options)} options')

    set_regexes[j] = {}; set_ops[j] = {}; set_covsets[j] = {}; set_mut_modes[j] = {}; set_rewards[j] = {}
    for pos in range(SET_SIZE):
        um_mut = (pos < nf) and fdb and len(fdb.items) > 0
        crx = None; ops = []; mut_mode = "fresh"

        if um_mut and j > 0:
            prev_j = j - 1
            prev_rxs = set_regexes.get(prev_j, {})
            if prev_rxs:
                prev_rw = set_rewards.get(prev_j, {})
                pw = []
                for pi in sorted(prev_rxs.keys()):
                    if pi in prev_rw:
                        s = float(prev_rw[pi])
                    else:
                        cs = set_covsets.get(prev_j, {}).get(pi, set())
                        s = sum(1.0 / math.sqrt(int(_load_freq(rdir).get(b, 0)) + 1.0) for b in cs) if cs else 0.0
                    pw.append(max(0.0, s) + 1e-9)
                chosen_pi = _wsample(list(prev_rxs.keys()), pw, 1)
                parent = prev_rxs[chosen_pi[0]] if chosen_pi else list(prev_rxs.values())[0]

                iu = Counter(); ku = Counter()
                muts, opsall = _mut_cands(parent, fdb, rm, frag_ratio, j * SET_SIZE + pos, 50, iu, ku)
                if muts:
                    scored = sorted([((_pred_quality(opsall[k], fdb)), k) for k in range(len(muts))], key=lambda x: x[0], reverse=True)
                    bi = scored[0][1]
                    if muts[bi] != parent: crx = muts[bi]; ops = opsall[bi]; mut_mode = "mutation"

        if crx is None:
            while crx is None:
                c = _gen_rx(rm, profile_path=prof_path)
                if c:
                    s = _sanitize(prog, c, rm)
                    if s: crx = s
            ops = []; mut_mode = "fresh"

        set_regexes[j][pos] = crx; set_ops[j][pos] = ops; set_mut_modes[j][pos] = mut_mode

    for i in range(SET_SIZE):
        _remain = _deadline - time.monotonic()
        if _remain <= 0:
            break
        if _remain < 10:
            break
        build_idx = i % N_BUILDS
        sub_time = int(min(small_budget, _remain))
        sub_j = build_j_counts[build_idx]
        outdir = f"{test_path}/iteration-{build_idx}/{sub_j}"
        other_settings = f"-libc=uclibc -posix-runtime -external-calls=all -only-output-states-covering-new -output-dir={outdir} -max-time={sub_time}"
        base_cmd = build_base_cmd(build_idx)
        crx = set_regexes[j].get(i, set_regexes[j].get(0, "."))

        seed_dir_for_klee = None
        if j > 0:
            sds = seed_cache.find(crx)
            if sds:
                seed_dir_for_klee = sds[0]
        seed_fl = f"--seed-dir={seed_dir_for_klee} --allow-seed-extension" if seed_dir_for_klee else ""
        xfl = extra_flags(build_idx, sub_j)
        sym_cmd = sym_commands.get(prog, "-sym-args 0 1 10 -sym-args 0 2 2 -sym-files 1 8 -sym-stdin 8 -sym-stdout")

        # Option: use pre-selected combined-score list
        flag = chosen_options[i] if i < len(chosen_options) else (bopt or "")

        # src_file: use pre-selected combined-score list
        cur_src = chosen_src_files[i] if i < len(chosen_src_files) else fsrc

        run_args = _build_run_args(prog, flag, crx, cur_src, fsrc2, prof=uprof, rm=rm)

        if run_args:
            cmd = f"{base_cmd} {seed_fl} {xfl} {other_settings} {llvm_path} {run_args} {sym_cmd}"
        else:
            cmd = f"{base_cmd} {seed_fl} {xfl} {other_settings} {llvm_path} {sym_cmd}"

        print(f"  [iter {build_idx}-{sub_j}] rx={crx[:60]} flag={flag} src={Path(cur_src).name if cur_src else ''}")
        _t0 = time.monotonic()
        _hard_limit = max(sub_time + 60, 90)
        _proc = sp.Popen(cmd, shell=True,
                         stdout=sp.DEVNULL, stderr=sp.DEVNULL,
                         start_new_session=True)
        try:
            _proc.wait(timeout=_hard_limit)
        except sp.TimeoutExpired:
            print(f"  [WARN] KLEE exceeded hard limit {_hard_limit}s -> killing pgid (rx={crx[:40]})")
            try:
                os.killpg(os.getpgid(_proc.pid), signal.SIGKILL)
            except Exception:
                try: _proc.kill()
                except Exception: pass
            try: _proc.wait(timeout=10)
            except Exception: pass

        # Collect coverage
        cov = set()
        if gcov_obj:
            try: cov = _collect_coverage_from_outdir(outdir, gcov_obj, args.gcov_depth)
            except: pass
        _elapsed = time.monotonic() - _t0  # includes KLEE + coverage collection
        set_covsets[j][i] = cov

        # Store seeds (freq-based scoring: rare branches get higher weight)
        try:
            freq_now = _load_freq(rdir)
            freq_score = sum(1.0 / math.sqrt(int(freq_now.get(b, 0)) + 1.0) for b in cov) if cov else 0.0
            seed_cache.store(j, i, crx, outdir, score=freq_score,
                            filter_regex=not args.no_regex_seed_filter)
        except: pass

        # Save iteration metadata
        try: (rdir / f"j{j}-i{i}.json").write_text(json.dumps({
            "j": j, "i": i, "rx": crx, "flag": flag, "src": cur_src, "ops": set_ops[j].get(i, []),
            "cov": len(cov), "mut": bool(set_ops[j].get(i, [])), "mut_mode": set_mut_modes.get(j, {}).get(i, "fresh")}, ensure_ascii=False, indent=2), encoding='utf-8')
        except: pass

        build_j_counts[build_idx] += 1
        # total_remaining is now informational only; the deadline controls stopping.
        total_remaining = max(0, int(_deadline - time.monotonic()))

    # ── End-of-set feedback ──
    try:
        freq_cum = _load_freq(rdir)
        covsets = [set_covsets[j].get(i, set()) for i in range(SET_SIZE)]
        scores = _score_freq(covsets, freq_cum)

        # Update freq_cum
        for cs in covsets:
            for b in cs: freq_cum[b] += 1
        _save_freq(rdir, freq_cum)

        # Update score_maps
        src_sm = _load_smap(rdir / "src_scores.json"); opt_sm = _load_smap(rdir / "option_scores.json")
        for i in range(SET_SIZE):
            sc = scores[i] if i < len(scores) else 0.0
            try:
                meta = json.loads((rdir / f"j{j}-i{i}.json").read_text())
                s = meta.get("src", ""); f = meta.get("flag", "")
                if s: src_sm[s] = float(src_sm.get(s, 0.0)) + sc
                if f: opt_sm[f] = float(opt_sm.get(f, 0.0)) + sc
            except: pass
        _save_smap(rdir / "src_scores.json", src_sm); _save_smap(rdir / "option_scores.json", opt_sm)

        # Fragment reward (j >= 1) — combined coverage + bug
        if j >= 1:
            ops_st = _load_ops(osp); prev_sc = prev_set_scores[-1] if prev_set_scores else [0.0] * SET_SIZE

            # Bug perf: replay-based actual measurement
            for i in range(SET_SIZE):
                sc_now = scores[i] if i < len(scores) else 0.0
                sc_old = prev_sc[i] if i < len(prev_sc) else 0.0
                raw_delta = sc_now - sc_old
                if REWARD_CLAMP_MAX is not None: raw_delta = min(raw_delta, REWARD_CLAMP_MAX)
                cov_reward = math.log1p(max(0.0, sc_now))

                # Bug score: replay ktest → actual time + memory + crash
                build_idx_i = i % N_BUILDS
                sub_j_i = (build_j_counts[build_idx_i] - SUBS_PER_BUILD) + (i // N_BUILDS)
                od = f"{test_path}/iteration-{build_idx_i}/{sub_j_i}"
                replay_time, replay_rss = _measure_replay_perf(od, gcov_obj) if os.path.isdir(od) else (0.0, 0.0)
                ck, cd = classify_klee_error(od) if os.path.isdir(od) else (None, None)
                has_crash = (ck == "CRASH")
                score_bug = _compute_score_bug(replay_time, replay_rss, has_crash)

                # Combined
                # Paper formula: score(r) = log(1 + score_cov(r)) + log(1 + score_bug(r)).
                reward = cov_reward + math.log1p(max(0.0, score_bug))
                set_rewards[j][i] = reward  # used as parent-selection weight in next set

                # Bug corpus logging — only timeout-near or crash regexes
                if (score_bug > 5.0 or has_crash) and set_regexes[j].get(i):
                    _append_bug_entry({"j": j, "i": i, "regex": set_regexes[j][i],
                                       "replay_time": replay_time, "replay_rss_kb": replay_rss,
                                       "has_crash": has_crash, "score_bug": score_bug, "reward": reward})

                jops = set_ops[j].get(i, [])
                hf = any(isinstance(o, dict) and o.get("op") == OP_FRAGMENT for o in jops)
                if hf:
                    s = ops_st.setdefault(OP_FRAGMENT, {"tries": 0, "reward": 0.0, "success": 0})
                    s["tries"] += 1; s["reward"] += reward
                    if reward > 0: s["success"] = s.get("success", 0) + 1
                else:
                    # Random / fresh regex — feeds adaptive frag_ratio comparison.
                    s = ops_st.setdefault(OP_RANDOM, {"tries": 0, "reward": 0.0, "success": 0})
                    s["tries"] += 1; s["reward"] += reward
                    if reward > 0: s["success"] = s.get("success", 0) + 1
                fo = [o for o in jops if isinstance(o, dict) and o.get("op") == OP_FRAGMENT and o.get("to_text")]
                share = reward / max(1, len(fo))
                for o in fo:
                    kn = o.get("to_kind"); tx = o.get("to_text")
                    if kn and tx and kn in ALL_KINDS:
                        fdb.record_reward(kn, tx, share)
            _save_ops(osp, ops_st)

        # Diversity-based fragment collection
        srx = [set_regexes[j].get(i, "") for i in range(SET_SIZE) if set_regexes[j].get(i)]
        if srx and scores:
            top_k = max(1, len(scores) // 4)
            bidxs = sorted(range(len(scores)), key=lambda x: scores[x], reverse=True)[:top_k]
            top_rx = [srx[x] for x in bidxs if x < len(srx)]
            rand_rx = srx[:]; random.shuffle(rand_rx); rand_rx = rand_rx[:max(2, len(srx)//2)]
            diverse_rx = []; ctoks = [_tok(r) for r in (top_rx + rand_rx)]
            for rx in srx:
                if len(diverse_rx) >= max(2, len(srx)//4): break
                t = _tok(rx)
                if not ctoks: diverse_rx.append(rx); ctoks.append(t); continue
                sims = [_jac(t, ct) for ct in ctoks]
                if sims and max(sims) < 0.35: diverse_rx.append(rx); ctoks.append(t)
            fdb.add_from_patterns(top_rx + rand_rx + diverse_rx)
        else:
            fdb.add_from_patterns(srx)

        rm_cnt = fdb.prune(j * SET_SIZE + SET_SIZE - 1)
        if rm_cnt > 0: print(f"  [prune] {rm_cnt} at j={j}")
        fdb.save()
        prev_set_scores.append(scores)
        print(f"  [feedback] j={j} scores={[round(s, 1) for s in scores]} db={len(fdb.items)}")
    except Exception as e:
        print(f"  [feedback] failed: {e}")

print(f"\n[done] total sets completed: {build_j_counts[0] // SUBS_PER_BUILD}")