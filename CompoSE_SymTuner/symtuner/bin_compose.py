from pathlib import Path
import argparse, json, shutil, sys, os, re, math, random, string, pickle
import subprocess, uuid, hashlib
from typing import List, Optional, Any, Set, Tuple, Dict, Union
from collections import Counter
from dataclasses import dataclass, asdict, field
from difflib import SequenceMatcher
from subprocess import run as _run, PIPE, STDOUT

from symtuner.klee import KLEE, KLEESymTuner
from symtuner.logger import get_logger
from symtuner.symtuner import TimeBudgetHandler
from symtuner._shared import get_regex_mode
from symtuner.compose_common import *
from symtuner.compose_regex import *
from symtuner.compose_profile import *
from symtuner.compose_coverage import *

try:
    from symtuner._shared import compose_root as _compose_root
    _cr = _compose_root()
    _klee_bin = _cr / "CompoSE_Aaqc" / "src" / "valina-build" / "bin" if _cr else None
    _DEFAULT_KLEE = str(_klee_bin / "klee") if _klee_bin else "klee"
    _DEFAULT_KLEE_REPLAY = str(_klee_bin / "klee-replay") if _klee_bin else "klee-replay"
except Exception:
    _DEFAULT_KLEE = "klee"
    _DEFAULT_KLEE_REPLAY = "klee-replay"

SET_SIZE = 20
SRC_SAMPLE_COUNT = 100


def main(argv=None):
    global SET_SIZE
    if argv is None: argv = sys.argv[1:]
    pr = argparse.ArgumentParser()
    ex = pr.add_argument_group('executables')
    ex.add_argument('--klee', default=_DEFAULT_KLEE); ex.add_argument('--klee-replay', default=_DEFAULT_KLEE_REPLAY); ex.add_argument('--gcov', default='gcov')
    hp = pr.add_argument_group('hyperparameters')
    hp.add_argument('-s', '--search-space', default=None, metavar='JSON'); hp.add_argument('--exploit-portion', default=0.7, type=float)
    hp.add_argument('--step', default=20, type=int); hp.add_argument('--minimum-time-portion', default=0.005, type=float)
    hp.add_argument('--n_scores', dest='n_scores', default=20, type=int,
                    help='Number of regexes per iteration/set (default=20)')
    hp.add_argument('--increase-ratio', default=2, type=float); hp.add_argument('--minimum-time-budget', default=30, type=int)
    hp.add_argument('--exploration-steps', default=20, type=int)
    pr.add_argument('-d', '--output-dir', default='symtuner-out'); pr.add_argument('--generate-search-space-json', action='store_true')
    pr.add_argument('--debug', action='store_true'); pr.add_argument('--gcov-depth', default=1, type=int)
    rx = pr.add_argument_group('regex & program')
    rx.add_argument('--pgm-config', default=None); rx.add_argument('--regex-mode', default='ere', choices=['ere', 'bre', 'pcre'])
    rx.add_argument('--regexgen-bin', default='regexgen'); rx.add_argument('--regex-per-iter', default=1, type=int)
    rx.add_argument('--w-coverage', default=0.6, type=float, help='Coverage mutation weight (default=0.6)')
    rx.add_argument('--w-bug', default=0.4, type=float, help='Bug mutation weight (default=0.4)')
    rx.add_argument('--regex-src-files',
                    default='regex_internal.c,regex_internal.h,regcomp.c,regexec.c,dfa.c,dfasearch.c',
                    help='Comma-separated regex source-file basenames used to build the '
                         'regex function set for KLEE state initialization (all_only)')
    rq = pr.add_argument_group('required')
    rq.add_argument('-t', '--budget', default=None, type=int)
    rq.add_argument('--fixed-time', default=120, type=int, help='Fixed per-iteration time budget in seconds (default=120)')
    rq.add_argument('llvm_bc', nargs='?', default=None); rq.add_argument('gcov_obj', nargs='?', default=None)
    args = pr.parse_args(argv)
    SET_SIZE = args.n_scores 
    if args.debug: get_logger().setLevel('DEBUG')
    if args.generate_search_space_json:
        with Path('example-space.json').open('w') as f: json.dump(KLEESymTuner.get_default_space_json(), f, indent=4); sys.exit(0)
    if args.llvm_bc is None or args.gcov_obj is None or args.budget is None:
        pr.print_usage(); print('required: -t, llvm_bc, gcov_obj'); sys.exit(1)

    rxseq = _load_rxseq(args.search_space)
    def _rp(rel, cfg=args.pgm_config):
        if not rel or os.path.isabs(rel): return rel
        for b in [os.getcwd(), str(Path(cfg).parent.parent) if cfg else '']:
            if b:
                c = os.path.join(b, rel)
                if os.path.exists(c): return c
        return rel

    pcfg = None; fsrc = ""; fsrc2 = ""; hflags = []; uprof = {}; spool = []
    bopt = ""; bopt_sc = -1.0

    if args.pgm_config:
        cp = Path(args.pgm_config)
        if not cp.exists(): get_logger().fatal(f'Not found: {cp}'); sys.exit(1)
        try:
            pcfg = json.loads(cp.read_text(encoding='utf-8'))
            if 'pgm' not in pcfg and 'pgm_name' in pcfg: pcfg['pgm'] = pcfg['pgm_name']
            for k in ('pgm', 'pgm_dir', 'gcov_path', 'exec_dir', 'src_file', 'sym_args'): pcfg.setdefault(k, '')
        except Exception as e: get_logger().fatal(f'Config error: {e}'); sys.exit(1)
        pgm = pcfg['pgm']; pd = _rp(pcfg['pgm_dir']); gp = _rp(pcfg['gcov_path'])
        args.regex_mode = get_regex_mode(pgm, default=args.regex_mode)
        get_logger().info(f'[regex_mode] {pgm} -> {args.regex_mode}')
        pconfig = dict(pcfg); pconfig['pgm_dir'] = pd; pconfig['gcov_path'] = gp

        if pd:
            sb = _src_base(pd, pgm=pgm)
            if sb.exists(): spool = _file_pool(sb); get_logger().info(f'[src] base={sb}, files={len(spool)}')
        if spool:
            fsrc, ssc = _best_src(pgm, args.regex_mode, pconfig, spool, SRC_SAMPLE_COUNT)
            get_logger().info(f'[src] {"BEST score=" + str(ssc) if ssc > 0 else "random"}: {fsrc}')
        else: fsrc = pcfg.get('src_file', '')

        ed = pcfg['exec_dir'].strip('/'); bp = None
        for b in ([os.path.join(gp, ed, pgm)] if gp and ed else []) + ([os.path.join(gp, 'src', pgm), os.path.join(gp, pgm)] if gp else []) + ([args.gcov_obj] if args.gcov_obj else []):
            if b and os.path.isfile(b) and os.access(b, os.X_OK): bp = b; break
        uprof = _get_prof(bp or "", pgm)
        get_logger().info(f'[profile] {uprof["arg_order"]}/{uprof["uses_slash_wrap"]}/{uprof["needs_dual_src"]}/{uprof["special_syntax"]}/{uprof["regex_prefix"]}/{uprof["accepts_options"]} regex_options={uprof.get("regex_options",[])} sep_flags={uprof.get("separator_flags",[])}')

        ropts = list(uprof.get("regex_options", [])); aopts = uprof.get("all_options", [])
        accepts_options = uprof.get("accepts_options", True)

        opool = []; hflags = []; bopt = ""; bopt_sc = -1.0
        if not accepts_options:
            if ropts:
                get_logger().info(f'[option] accepts_options=False, but found regex options: {ropts}')
                opool = ropts
            else:
                get_logger().info('[option] accepts_options=False, skipping')
        if accepts_options or (not accepts_options and ropts):
            opool = ropts if ropts else aopts
            if opool:
                bopt, bopt_sc = _best_opt(pgm, args.regex_mode, pconfig, fsrc, opool, prof=uprof)
                get_logger().info(f'[option] {"BEST score=" + str(bopt_sc) if bopt_sc > 0 else "random"}: {bopt} (pool={opool})')
                hflags = opool
            else:
                get_logger().info('[option] no candidates')

        if uprof.get("needs_dual_src"):
            p2 = [f for f in spool if f != fsrc]
            if p2: fsrc2, _ = _best_src(pgm, args.regex_mode, pconfig, p2, min(SRC_SAMPLE_COUNT, len(p2)))
            else: fsrc2 = fsrc
            get_logger().info(f'[src2] {fsrc2}')

    odir = Path(args.output_dir)
    if odir.exists(): shutil.rmtree(str(odir))
    odir.mkdir(parents=True); (odir / 'coverage.csv').touch(); (odir / 'found_bugs.txt').touch()
    rdir = odir / 'regex'; rdir.mkdir(parents=True, exist_ok=True)
    if pcfg:
        try: (rdir / f"profile_{pcfg['pgm']}.json").write_text(json.dumps(uprof, indent=2, ensure_ascii=False), encoding='utf-8')
        except: pass
        rgx_prof = _build_rgx_profile(pcfg['pgm'], args.regex_mode)
        prof_path = rdir / "regexgen_profile.json"
        try: prof_path.write_text(json.dumps(rgx_prof, indent=2, ensure_ascii=False), encoding='utf-8')
        except: prof_path = None
    else: prof_path = None

    se = KLEE(args.klee); st = KLEESymTuner(args.klee_replay, args.gcov, 10, args.search_space, args.exploit_portion)
    ea = {'folder_depth': args.gcov_depth}

    fdb = FragmentDB(rdir / "fragments.pkl") if pcfg else None
    sc = SeedCache(rdir / "seeds") if pcfg else None

    if pcfg:
        _init_bug_corpus(rdir)
        if fdb and args.w_bug > 0:
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
                                    boost = _wide_fragment_boost(nd.kind, nd.text)
                                    fdb.items[key] = FragItem(nd.kind, nd.text, FragStat(reward_sum=0.5*boost, success=1, n=1))
                                    injected += 1
                    except: pass
                if injected > 0:
                    fdb.save()
                    get_logger().info(f'[bug-corpus] Injected {injected} fragments from {len(bug_rxs)} bug regexes')
    osp = rdir / "op_stats.json"
    irx: Dict[int, str] = {}; iops: Dict[int, List[dict]] = {}
    prev_scores: List[float] = []
    iter_covsets: Dict[int, Set[str]] = {}
    data_idx_before: Dict[int, int] = {}

    get_logger().info(f'Start (full pipeline, set={SET_SIZE}).')
    tbh = TimeBudgetHandler(args.budget, args.minimum_time_portion, args.step, args.increase_ratio, args.minimum_time_budget)

    for i, tb in enumerate(tbh):
        tb = args.fixed_time 
        idir = odir / f'iteration-{i}'; pol = 'explore' if i < args.exploration_steps else None
        params = st.sample(policy=pol)
        params['--guide-by-regex'] = None
        params['-regex-src-files'] = args.regex_src_files
        data_idx_before[i] = len(st.data)

        if pcfg:
            si = i // SET_SIZE; pi = i % SET_SIZE
            if si == 0: fr = 0.0
            elif si == 1: fr = 0.5
            else: fr = max(0.3, _frag_eff(_load_ops(osp)))
            nf = max(0, min(SET_SIZE, int(round(SET_SIZE * fr))))
            w_cov = args.w_coverage; w_bug = args.w_bug
            nf_cov = int(round(nf * w_cov)); nf_bug = nf - nf_cov
            um_cov = (pi < nf_cov) and fdb and len(fdb.items) > 0
            um_bug = (pi >= nf_cov and pi < nf) and fdb and len(fdb.items) > 0
            if pi == 0: get_logger().info(f'[set {si}] fr={fr:.3f} nf={nf}/{SET_SIZE} (cov={nf_cov}, bug={nf_bug})')

            crx = None; ops = []; mut_mode = "fresh"
            if um_cov:
                prev_iters = [j for j in range(max(0, i - SET_SIZE), i) if j in irx]
                if prev_iters:
                    freq_cum = _load_freq_cum(rdir)
                    pw = []
                    for j in prev_iters:
                        cs = iter_covsets.get(j, set())
                        s = sum(1.0 / math.sqrt(int(freq_cum.get(b, 0)) + 1.0) for b in cs) if cs else 0.0
                        pw.append(max(0.0, s) + 1e-9)
                    chosen_pi = _wsample(prev_iters, pw, 1)
                    parent = irx[chosen_pi[0]] if chosen_pi else irx[prev_iters[0]]
                    iu = Counter(); ku = Counter()
                    muts, opsall = _mut_cands(parent, fdb, args.regex_mode, fr, i, 50, iu, ku)
                    if muts:
                        scored = [(_pred_quality(opsall[j], fdb), j) for j in range(len(muts))]
                        scored = sorted(scored, key=lambda x: x[0], reverse=True)
                        bi = scored[0][1]
                        if muts[bi] != parent:
                            crx = muts[bi]; ops = opsall[bi]; mut_mode = "coverage"

            elif um_bug:
                prev_iters = [j for j in range(max(0, i - SET_SIZE), i) if j in irx]
                if prev_iters:
                    freq_cum = _load_freq_cum(rdir)
                    pw = []
                    for j in prev_iters:
                        cs = iter_covsets.get(j, set())
                        s = sum(1.0 / math.sqrt(int(freq_cum.get(b, 0)) + 1.0) for b in cs) if cs else 0.0
                        pw.append(max(0.0, s) + 1e-9)
                    chosen_pi = _wsample(prev_iters, pw, 1)
                    parent = irx[chosen_pi[0]] if chosen_pi else irx[prev_iters[0]]
                    if random.random() < 0.65:
                        m, bops = mutate_once_bug_exploit(parent, fdb, k=3, current_iteration=i)
                    else:
                        m, bops = mutate_once_bug_explore(parent, fdb, k=3, current_iteration=i)
                    if m and m != parent:
                        s = _sanitize(pcfg['pgm'], m, args.regex_mode)
                        if s:
                            crx = s; ops = bops; mut_mode = "bug"

            if crx is None:
                rtxt = rdir / f'iter-{i}.txt'
                try:
                    _gen_rx(args.regex_per_iter, args.regex_mode, rtxt, args.regexgen_bin, profile_path=prof_path)
                    rs = [ln.strip() for ln in rtxt.read_text(encoding='utf-8').splitlines() if ln.strip()]
                    crx = rs[0] if rs else None
                except: crx = None
                if crx is None:
                    while crx is None:
                        try:
                            _gen_rx(1, args.regex_mode, rtxt, args.regexgen_bin, profile_path=prof_path)
                            rs = [ln.strip() for ln in rtxt.read_text(encoding='utf-8').splitlines() if ln.strip()]
                            if rs and _sanitize(pcfg['pgm'], rs[0], args.regex_mode):
                                crx = rs[0]
                        except: pass
                ops = []; mut_mode = "fresh"

            opt_sm = _load_score_map(rdir / "option_scores.json")
            if hflags:
                if opt_sm and random.random() < 0.5:
                    top = _top_by_score(opt_sm, hflags, 1)
                    flag = top[0] if top else bopt
                elif bopt and random.random() < 0.5: flag = bopt
                else: flag = random.choice(hflags)
            else: flag = ""

            src_sm = _load_score_map(rdir / "src_scores.json")
            if spool and src_sm and random.random() < 0.3:
                top = _top_by_score(src_sm, spool, 1)
                cur_src = top[0] if top else fsrc
            else: cur_src = fsrc
            cur_src2 = fsrc2

            sds = sc.find(crx) if (sc and si > 0) else []
            if sds:
                sf = params.get('-seed-file') or params.get('--seed-file')
                if isinstance(sf, (list, tuple)): sf = sf[0] if sf else None
                if sf:
                    merge_dir = (rdir / f"merged_seeds_i{i}").resolve()
                    merge_dir.mkdir(parents=True, exist_ok=True)
                    sfp = Path(str(sf))
                    if sfp.exists():
                        try: shutil.copy2(str(sfp), str(merge_dir / sfp.name))
                        except: pass
                    try:
                        for kt in Path(sds[0]).glob("*.ktest"):
                            dst = merge_dir / f"sc_{kt.name}"
                            if not dst.exists(): shutil.copy2(str(kt), str(dst))
                    except: pass
                    params.pop('-seed-file', None); params.pop('--seed-file', None)
                    params['-seed-dir'] = str(merge_dir)
                else:
                    params['-seed-dir'] = str(Path(sds[0]).resolve())

            sym = _build_sym(pcfg['pgm'], crx, cur_src, flag, cur_src2, uprof, args.regex_mode).strip()
            params['-regex-options'] = [sym]
            irx[i] = crx; iops[i] = ops

            snap = {'i': i, 'set': si, 'pos': pi, 'fr': fr, 'mut': bool(ops), 'mut_mode': mut_mode,
                    'pgm': pcfg['pgm'], 'src': cur_src, 'rx': crx, 'flag': flag, 'sym': sym, 'ops': ops}
            try: (rdir / f'iter-{i}.json').write_text(json.dumps(snap, ensure_ascii=False, indent=2), encoding='utf-8')
            except: pass

        elif rxseq:
            params['-regex-options'] = [rxseq[i % len(rxseq)]]

        params[se.get_time_parameter()] = tb; params['-output-dir'] = str(idir)

        _sym_keys = ['sym-arg', 'sym-args', 'sym-files', 'sym-stdin', 'sym-stdout']
        for k in list(params.keys()):
            stripped = k.lstrip('-').split()[0]
            if stripped in _sym_keys and k.startswith('--'):
                del params[k]

        tcs = se.run(args.llvm_bc, params)

        pst = {k: v for k, v in params.items() if k not in ['-regex-options', '--regex-options', '-seed-dir', '--seed-dir']}
        try:
            st.add(args.gcov_obj, pst, tcs, ea)
        except FileNotFoundError as e:
            get_logger().warning(f'[iter {i}] gcov file not found, skipping: {e}')
        except Exception as e:
            get_logger().warning(f'[iter {i}] coverage collection failed: {e}')

        if pcfg:
            di_before = data_idx_before.get(i, 0)
            iter_cov = set()
            for cov, _, _, _ in st.data[di_before:]:
                iter_cov |= cov
            iter_covsets[i] = iter_cov

            if sc and i in irx:
                try:
                    freq_now = _load_freq_cum(rdir)
                    freq_score = sum(1.0 / math.sqrt(int(freq_now.get(b, 0)) + 1.0) for b in iter_cov) if iter_cov else 0.0
                    sc.store(i, irx[i], tcs, score=freq_score)
                except: pass

            if pi == SET_SIZE - 1:
                si_iters = list(range(si * SET_SIZE, si * SET_SIZE + SET_SIZE))
                try:
                    freq_cum = _load_freq_cum(rdir)
                    set_covsets = [iter_covsets.get(j, set()) for j in si_iters]
                    set_scores = _score_from_freq(set_covsets, freq_cum)

                    for cs in set_covsets:
                        for b in cs: freq_cum[b] += 1
                    _save_freq_cum(rdir, freq_cum)

                    prev_set_scores = prev_scores[-SET_SIZE:] if prev_scores else [0.0] * SET_SIZE
                    if len(prev_set_scores) < SET_SIZE:
                        prev_set_scores += [0.0] * (SET_SIZE - len(prev_set_scores))

                    src_sm = _load_score_map(rdir / "src_scores.json")
                    opt_sm = _load_score_map(rdir / "option_scores.json")
                    for j_idx, j in enumerate(si_iters):
                        sc_now = set_scores[j_idx] if j_idx < len(set_scores) else 0.0
                        try:
                            meta = json.loads((rdir / f'iter-{j}.json').read_text())
                            s = meta.get("src", ""); f = meta.get("flag", "")
                            if s: src_sm[s] = float(src_sm.get(s, 0.0)) + sc_now
                            if f: opt_sm[f] = float(opt_sm.get(f, 0.0)) + sc_now
                        except: pass
                    _save_score_map(rdir / "src_scores.json", src_sm)
                    _save_score_map(rdir / "option_scores.json", opt_sm)

                    if si >= 1:
                        ops_st = _load_ops(osp)

                        slow_raw_list = []; mem_raw_list = []
                        for j in si_iters:
                            idir_j = odir / f'iteration-{j}'
                            s_raw, m_raw = _load_perf_from_istats(idir_j) if idir_j.exists() else (0.0, 0.0)
                            slow_raw_list.append(s_raw); mem_raw_list.append(m_raw)
                        slow_norm_list = _normalize_log_list(slow_raw_list)
                        mem_norm_list = _normalize_log_list(mem_raw_list)

                        for j_idx, j in enumerate(si_iters):
                            sc_now = set_scores[j_idx] if j_idx < len(set_scores) else 0.0
                            cov_reward = math.log1p(max(0.0, sc_now))

                            idir_bj = odir / f'iteration-{j}'
                            el_j, _rss_j = _load_perf_from_istats(idir_bj) if idir_bj.exists() else (0.0, 0.0)
                            has_crash_j = False
                            if idir_bj.exists():
                                _ck0, _cd0 = classify_klee_error(idir_bj)
                                has_crash_j = (_ck0 == "CRASH")
                            score_bug = _compute_score_bug(el_j, 0.0, has_crash_j)

                            reward = cov_reward + math.log1p(max(0.0, score_bug))

                            sn = slow_norm_list[j_idx] if j_idx < len(slow_norm_list) else 0.0
                            mn = mem_norm_list[j_idx] if j_idx < len(mem_norm_list) else 0.0

                            idir_j = odir / f'iteration-{j}'
                            bug_tags = []
                            if idir_j.exists():
                                ck, cd = classify_klee_error(idir_j)
                                if ck == "CRASH": bug_tags.append("CRASH")
                            if sn >= PERF_NORM_THRESH: bug_tags.append("PERF_TIME")
                            if mn >= PERF_NORM_THRESH: bug_tags.append("PERF_MEM")
                            if bug_tags and j in irx:
                                _append_bug_entry({"iteration": j, "regex": irx[j], "tags": bug_tags,
                                                   "slow_norm": sn, "mem_norm": mn, "reward": reward})

                            jops = iops.get(j, [])
                            hf = any(isinstance(o, dict) and o.get("op") == OP_FRAGMENT for o in jops)
                            if hf:
                                s = ops_st.setdefault(OP_FRAGMENT, {"tries": 0, "reward": 0.0, "success": 0})
                                s["tries"] += 1; s["reward"] += reward
                                if reward > 0: s["success"] = s.get("success", 0) + 1
                            fo = [o for o in jops if isinstance(o, dict) and o.get("op") == OP_FRAGMENT and o.get("to_text")]
                            share = reward / max(1, len(fo))
                            for o in fo:
                                kn = o.get("to_kind"); tx = o.get("to_text")
                                if kn and tx and kn in ALL_KINDS:
                                    boosted = share * _wide_fragment_boost(kn, tx) if w_bug > 0 else share
                                    fdb.record_reward(kn, tx, boosted)
                        _save_ops(osp, ops_st)

                    set_rx = [irx[j] for j in si_iters if j in irx]
                    if set_rx and set_scores:
                        top_k = max(1, len(set_scores) // 4)
                        best_idxs = sorted(range(len(set_scores)), key=lambda x: set_scores[x], reverse=True)[:top_k]
                        top_rx = [set_rx[x] for x in best_idxs if x < len(set_rx)]
                        rand_rx = set_rx[:]; random.shuffle(rand_rx); rand_rx = rand_rx[:max(2, len(set_rx)//2)]
                        diverse_rx = []; chosen_toks = [_tok(r) for r in (top_rx + rand_rx)]
                        for rx in set_rx:
                            if len(diverse_rx) >= max(2, len(set_rx)//4): break
                            t = _tok(rx)
                            if not chosen_toks: diverse_rx.append(rx); chosen_toks.append(t); continue
                            sims = [_jac(t, ct) for ct in chosen_toks]
                            if sims and max(sims) < 0.35: diverse_rx.append(rx); chosen_toks.append(t)
                        fdb.add_from_patterns(top_rx + rand_rx + diverse_rx)
                    else:
                        fdb.add_from_patterns(set_rx)

                    rm = fdb.prune(i)
                    if rm > 0: get_logger().info(f'[prune] {rm} at set {si}')
                    fdb.save(); fdb.export_preview(rdir / "fragments_preview.tsv")
                    prev_scores.extend(set_scores)
                    get_logger().info(f'[feedback] set={si} scores={[round(s, 1) for s in set_scores]} db={len(fdb.items)}')
                except Exception as e: get_logger().warning(f'[feedback] failed: {e}')

        el = tbh.elapsed; cov, bugs = st.get_coverage_and_bugs()
        get_logger().info(f'Iter: {i+1} Budget: {tb} Elapsed: {el} Cov: {len(cov)} Bugs: {len(bugs)}')
        try:
            with (odir / 'coverage.csv').open('a') as f: f.write(f'{el}, {len(cov)}\n')
        except Exception: pass
        try:
            with (odir / 'found_bugs.txt').open('w') as f:
                f.writelines(f'Testcase: {Path(st.get_testcase_causing_bug(b)).absolute()} Bug: {b}\n' for b in bugs)
        except Exception: pass

    cov, bugs = st.get_coverage_and_bugs()
    get_logger().info(f'Done. Cov: {len(cov)}, Bugs: {len(bugs)}')