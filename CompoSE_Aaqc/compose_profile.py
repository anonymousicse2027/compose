"""Auto-split from AAQC compose: profile."""
import argparse, os, sys, subprocess as sp, glob, shlex, random, string, tempfile, signal
import re, shutil, json, math, pickle, uuid, hashlib, time
from pathlib import Path
from _shared import get_regex_mode  # shared BRE/ERE table
from typing import Optional, List, Set, Dict, Tuple, Union
from collections import Counter
from dataclasses import dataclass, asdict, field
from difflib import SequenceMatcher
from compose_common import *
from compose_regex import *

# ---- defs ----
def _derive_src_base(prog, pcfg=None):
    """Derive the source-tree base dir from pgm-config (parent of obj-llvm)."""
    if pcfg:
        pd = pcfg.get("pgm_dir", "")
        if pd:
            p = Path(pd).resolve()
            parts = list(p.parts)
            if "obj-llvm" in parts:
                return Path(*parts[:parts.index("obj-llvm")])
            return p.parent
    return None
def _file_pool(base):
    pool = []
    if not base or not base.exists(): return pool
    try:
        for p in base.rglob("*"):
            try:
                if p.is_file() and '/obj-gcov' not in str(p): pool.append(str(p.resolve()))
            except: continue
    except: pass
    return pool
def _find_bin_aaqc(prog, pcfg=None):
    """Find program binary from pgm-config gcov_path (+ exec_dir), then PATH."""
    cs = []
    if pcfg:
        gp = pcfg.get("gcov_path", ""); ed = pcfg.get("exec_dir", "").strip("/")
        if gp:
            if ed: cs.append(os.path.join(gp, ed, prog))
            cs += [os.path.join(gp, "src", prog), os.path.join(gp, prog)]
    try:
        w = shutil.which(prog)
        if w: cs.append(w)
    except: pass
    for c in cs:
        if c and os.path.isfile(c) and os.access(c, os.X_OK): return c
    return None
def _exec_dir_from_cfg(pcfg):
    """Directory holding the gcov binary, from pgm-config (gcov_path + exec_dir).
    Branch coverage is collected in-code by _run_binary_get_branches; no external script needed."""
    if pcfg:
        gp = pcfg.get("gcov_path", ""); ed = pcfg.get("exec_dir", "").strip("/")
        if gp:
            return (Path(gp) / ed) if ed else Path(gp)
    return None
def _build_test_cmd(prog, inv, rx, sf, rm, flag="", prof=None):
    # m4: fixed invocation (bypass profile logic, regex from CompoSE only)
    if prog == "m4":
        q = _esq(rx.strip())
        return f"{inv} --warn-macro-sequence='{q}' {sf}".strip()
    if prof is None: prof = {}
    q = _esq(rx.strip()); qs = _esl(q); wr = f"/{qs}/"
    sl = prof.get("uses_slash_wrap", False) or prog in _MANUAL_SLASH
    px = prof.get("regex_prefix", ""); od = prof.get("arg_order", "regex_first")
    sps = prof.get("special_syntax")
    sep_flags = prof.get("separator_flags", []); sep_val = prof.get("separator_value_flag", "")
    qp = f"{px}{q}" if px else q
    if sps == "string_colon_regex":
        t = _rnd_txt().replace('"', '\\"'); return f'{inv} {flag + " " if flag else ""}"{t}" : \'{qp}\''.strip()
    if sps == "plus_slash_regex":
        q_slash = q.replace("/", r"\/")
        ef = flag.strip() if flag else ""
        prefix = f"{ef} " if ef else ""
        return f"{inv} {prefix}'+/{q_slash}' {sf}".strip()
    r = f"'{wr}'" if sl else f"'{qp}'"
    # Selected option always immediately before regex
    ef = flag.strip() if flag else ""
    regex_part = f"{ef} {r}" if ef else r
    # Separator boolean flags only
    fp_parts = []
    for ssf in sep_flags:
        sc = ssf.strip()
        if sc and sc != sep_val and sc not in fp_parts: fp_parts.append(sc)
    fp = " ".join(fp_parts)
    fp = f"{fp} " if fp else ""
    if od == "file_first": return f"{inv} {sf} {fp}{regex_part}".strip()
    if od == "no_file": return f"{inv} {fp}{regex_part}".strip()
    return f"{inv} {fp}{regex_part} {sf}".strip()
def _best_src_binary(prog, rm, pool, n, prof=None, pcfg=None):
    if not pool: return "", -1
    bp = _find_bin_aaqc(prog, pcfg); ed = _exec_dir_from_cfg(pcfg)
    if not bp or not ed: return random.choice(pool), -1
    cs = _pick(pool, n)
    cmds = [_build_test_cmd(prog, bp, SAMPLE_REGEX, sf, rm, prof=prof) for sf in cs]
    bm = _run_binary_get_branches(bp, ed, cmds, cs)
    sc = sorted([(len(bm.get(s, set())), s) for s in cs], key=lambda t: t[0], reverse=True)
    return (sc[0][1], sc[0][0]) if sc and sc[0][0] > 0 else (random.choice(pool), -1)
def _run_binary_get_branches(gcov_obj, exec_dir, cmds, src_files, gcov_depth=1, timeout=10):
    """Run each binary command, collect covered branches via gcov -b.
    Returns: {src_file: Set[str]} mapping each src to its branch keys.
    """
    result = {}
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
        branches = set()
        try:
            sp.run(f'find {base} -name "*.gcda" -delete 2>/dev/null', shell=True, check=False, timeout=10)
            sp.run(f'find {base} -name "*.gcov" -delete 2>/dev/null', shell=True, check=False, timeout=10)
            sp.run(cmd, shell=True, cwd=str(exec_dir),
                   stdout=sp.DEVNULL, stderr=sp.DEVNULL, check=False, timeout=timeout)
            os.chdir(str(target.parent))
            gcda_files = list(Path().glob(gcda_pat))
            # Exclude signal.gcda: its gcov section is huge and blows up memory (matches featmaker/vanilla)
            gcda_files = [g for g in gcda_files if 'signal.gcda' not in str(g)]
            if gcda_files:
                sp.run(f'gcov -b {" ".join(str(g) for g in gcda_files)}',
                       shell=True, stdout=sp.DEVNULL, stderr=sp.DEVNULL, check=False)
                # Defensive: drop any signal.c.gcov before parsing (cross-contamination / huge file)
                sp.run(f'find {base} -name "signal.c.gcov" -delete 2>/dev/null', shell=True, check=False)
                for gf in Path().glob(gcov_pat):
                    try:
                        with gf.open(errors='replace') as fh:
                            fn = fh.readline().strip().split(':')[-1]
                            for li, line in enumerate(fh):
                                if 'branch' in line and 'never' not in line and 'taken 0%' not in line:
                                    branches.add(f'{fn} {li}')
                    except: pass
            os.chdir(orig)
        except Exception:
            try: os.chdir(orig)
            except: pass
        result[sf] = branches
    try:
        sp.run(f'find {base} -name "*.gcda" -delete 2>/dev/null', shell=True, check=False, timeout=10)
        sp.run(f'find {base} -name "*.gcov" -delete 2>/dev/null', shell=True, check=False, timeout=10)
    except: pass
    return result
def _select_src_combined(prog, rm, pool, n_select, sample_count, freq_cum, tested_set, prof=None, pcfg=None, gcov_depth=1):
    """Select top n_select src files via binary branch test + freq_cum scoring.

    1. Filter pool to untested files (reset if all tested)
    2. Sample candidates
    3. Binary run → branch set per src
    4. Score: sum(1/sqrt(freq_cum[b]+1) for b in branches)
    5. Top n_select by score
    6. Mark candidates as tested
    """
    if not pool:
        return [""] * n_select, ""
    gcov_obj = _find_bin_aaqc(prog, pcfg)
    ed = _exec_dir_from_cfg(pcfg)
    if not gcov_obj or not ed:
        pk = random.sample(pool, min(n_select, len(pool)))
        if pk and len(pk) < n_select: pk += [pk[0]] * (n_select - len(pk))
        return pk, (pk[0] if pk else "")

    # 1. Untested filtering
    untested = [f for f in pool if f not in tested_set]
    if not untested:
        tested_set.clear()
        untested = list(pool)
    # 2. Sample
    candidates = random.sample(untested, min(sample_count, len(untested)))
    # 3. Binary → branch sets
    cmds = [_build_test_cmd(prog, gcov_obj, SAMPLE_REGEX, sf, rm, prof=prof) for sf in candidates]
    branch_map = _run_binary_get_branches(gcov_obj, ed, cmds, candidates, gcov_depth)
    # 4. freq_cum scoring
    scored = []
    for sf in candidates:
        bs = branch_map.get(sf, set())
        sc = sum(1.0 / math.sqrt(int(freq_cum.get(b, 0)) + 1.0) for b in bs) if bs else 0.0
        scored.append((sc, sf))
    scored.sort(key=lambda x: x[0], reverse=True)
    # 5. Top n_select
    top = [sf for _, sf in scored[:n_select]]
    if not top: top = [random.choice(pool)] * n_select
    elif len(top) < n_select: top += [top[0]] * (n_select - len(top))
    # 6. Mark tested
    tested_set.update(candidates)
    best = top[0] if top else ""
    best_sc = f'{scored[0][0]:.2f}' if scored else 'N/A'
    print(f'[src-combined] top {n_select} from {len(candidates)} candidates '
          f'(untested_remaining={len(untested)-len(candidates)}, best_score={best_sc})')
    return top, best
def _best_opt_binary(prog, rm, bsrc, pool, prof=None, pcfg=None):
    if not pool: return "", -1.0, []
    bp = _find_bin_aaqc(prog, pcfg); ed = _exec_dir_from_cfg(pcfg)
    if not bp or not ed: return random.choice(pool), -1.0, [(1, f) for f in pool]
    cmds = [_build_test_cmd(prog, bp, SAMPLE_REGEX, bsrc, rm, flag=f, prof=prof) for f in pool]
    bm = _run_binary_get_branches(bp, ed, cmds, pool)
    sc = sorted([(len(bm.get(f, set())), f) for f in pool], key=lambda t: t[0], reverse=True)
    best = (sc[0][1], float(sc[0][0])) if sc and sc[0][0] > 0 else (random.choice(pool), -1.0)
    return best[0], best[1], sc
def _weighted_random_opt(scored, opt_sm=None):
    """Pick one option via coverage-proportional weighted random."""
    if not scored: return ""
    if opt_sm:
        merged = [(s + int(opt_sm.get(f, 0)), f) for s, f in scored]
    else:
        merged = scored
    flags = [f for _, f in merged]
    weights = [max(s, 0) + 1 for s, _ in merged]
    return random.choices(flags, weights=weights, k=1)[0]
def _select_options_combined(prog, rm, bsrc, pool, n_select, freq_cum, prof=None, pcfg=None, gcov_depth=1):
    """Select n_select options via binary branch test + freq_cum weighted random.

    1. For each option: binary run with that option → branch set
    2. Score: sum(1/sqrt(freq_cum[b]+1)) for branches
    3. Weighted random selection using scores as weights
    """
    if not pool:
        return [""] * n_select, ""
    gcov_obj = _find_bin_aaqc(prog, pcfg)
    ed = _exec_dir_from_cfg(pcfg)
    if not gcov_obj or not ed:
        return [random.choice(pool) for _ in range(n_select)], random.choice(pool)
    cmds = [_build_test_cmd(prog, gcov_obj, SAMPLE_REGEX, bsrc, rm, flag=f, prof=prof) for f in pool]
    branch_map = _run_binary_get_branches(gcov_obj, ed, cmds, pool, gcov_depth)
    scored = []
    for f in pool:
        bs = branch_map.get(f, set())
        sc = sum(1.0 / math.sqrt(int(freq_cum.get(b, 0)) + 1.0) for b in bs) if bs else 0.0
        scored.append((sc, f))
    weights = [max(sc, 0.0) + 1.0 for sc, _ in scored]
    chosen = random.choices([f for _, f in scored], weights=weights, k=n_select)
    best_sc = max(scored, key=lambda x: x[0])
    best = best_sc[1]
    print(f'[opt-combined] weighted random {n_select} from {len(pool)} options '
          f'(best={best}, score={best_sc[0]:.2f})')
    return chosen, best
def _extr_flags(ht):
    _RL = re.compile(r"--[A-Za-z0-9][A-Za-z0-9\-]*"); _RS = re.compile(r"(?<!-)-[A-Za-z]\b")
    _RSL = re.compile(r"(?<![A-Za-z0-9\-])-[A-Za-z][A-Za-z0-9]*")
    _STV = re.compile(r'^\s*(-[A-Za-z])(?:\[|\s+[a-z]|\s+<|\s+\')')
    _LTV = re.compile(r'(--[A-Za-z0-9][A-Za-z0-9\-]*)(?:\[?=)')
    res = []
    for ln in ht.splitlines():
        if not ln.lstrip().startswith('-'): continue
        vf = {m.group(1) for m in _STV.finditer(ln)}
        vl = {m.group(1) for m in _LTV.finditer(ln)}
        shorts = []; longs = []; sdl = []
        for m in _RS.finditer(ln):
            f = m.group(0).rstrip(",.;:)=]")
            if f not in shorts and f not in vf: shorts.append(f)
        for m in _RL.finditer(ln):
            f = m.group(0).rstrip(",.;:)=]")
            if f not in longs and f not in vl: longs.append(f)
        for m in _RSL.finditer(ln):
            f = m.group(0).rstrip(",.;:)=]")
            if len(f) > 2 and f not in shorts and f not in longs and f not in sdl: sdl.append(f)
        if shorts and longs:
            fs = shorts + sdl
        else:
            fs = shorts + longs + sdl
        takes_file_arg = bool(_TAKES_VALUE_RE.search(ln))
        for f in fs:
            if f not in _DISALLOWED:
                res.append((f, ln, takes_file_arg))
    return res
def _parse_prof(ht, pgm):
    p = {"arg_order": "regex_first", "regex_prefix": "", "regex_options": [], "all_options": [],
         "special_syntax": None, "uses_slash_wrap": pgm in _MANUAL_SLASH,
         "needs_dual_src": pgm in _DUAL_SRC, "accepts_options": True,
         "separator_flags": [], "separator_value_flag": None}
    if not ht: return p
    uls = [ln for ln in ht.splitlines() if ln.strip().lower().startswith('usage:')]
    ho = False
    for u in uls:
        uu = u.upper()
        if '[OPTION]' in uu or '[OPTIONS]' in uu: ho = True; break
        if re.search(r'\[[^\]]*\bOPTIONS?\b[^\]]*\]', uu): ho = True; break
        if re.search(r'\[-[A-Za-z]', u) or re.search(r'\[--[A-Za-z]', u): ho = True; break
    p["accepts_options"] = ho
    for u in uls:
        uu = u.upper()
        fp = min((uu.find(k) for k in _FILE_KW if uu.find(k) != -1), default=None)
        pp = min((uu.find(k) for k in _PAT_KW if uu.find(k) != -1), default=None)
        if fp is not None and pp is not None: p["arg_order"] = "file_first" if fp < pp else "regex_first"
        elif fp is None and pp is not None: p["arg_order"] = "no_file"
        break
    if re.search(r'STRING\s*:\s*REGEXP', ht, re.IGNORECASE):
        p["special_syntax"] = "string_colon_regex"; p["arg_order"] = "no_file"; p["accepts_options"] = False
    # ed style: "+/RE" or "+?RE" (regex passed as +/regex argument)
    if re.search(r'\+/RE\b', ht):
        p["special_syntax"] = "plus_slash_regex"; p["arg_order"] = "regex_first"
    if re.search(r'\bpBRE\b', ht): p["regex_prefix"] = "p"
    if re.search(r'/REGEXP/', ht): p["uses_slash_wrap"] = True

    # Detect "-flag PATTERN" style (e.g., find's "-regex PATTERN", "-iregex PATTERN")
    _PAT_WORDS = {'PATTERN', 'REGEXP', 'REGEX', 'BRE', 'ERE'}
    _rf_re = re.compile(r'(-[A-Za-z][\w-]*)\s+(' + '|'.join(_PAT_WORDS) + r')\b')
    regex_flag_cands = []
    for ln in ht.splitlines():
        for m in _rf_re.finditer(ln):
            fl = m.group(1)
            if fl.lstrip('-').lower() in ('regex', 'iregex', 'regexp'):
                regex_flag_cands.append(fl)
    if regex_flag_cands and not p.get("special_syntax"):
        p["regex_options"] = list(dict.fromkeys(regex_flag_cands))
        p["arg_order"] = "file_first"
        p["accepts_options"] = False

    if p["accepts_options"]:
        fwd = _extr_flags(ht)
        def _is_rx(flag, desc):
            # Strong signals: always regex
            if re.search(r'\bregex\b|\bregexp\b|\bregular\s+expression|\bBRE\b|\bERE\b', desc, re.IGNORECASE): return True
            if re.search(r'\bRE\b', desc): return True
            if re.search(r'regexp|regex', flag, re.IGNORECASE): return True
            if re.search(r'=\s*(REGEXP|REGEX|RE)\b', desc): return True
            # Weak signal: "pattern" in desc — but NOT if it's a file-glob context
            if re.search(r'\bpattern\b', desc, re.IGNORECASE):
                if re.search(r'\bexclude\b|\bfiles?\s+that\s+match\b|\bfile\s*name\b|\bglob\b|\bwildcard\b|\bshell\b', desc, re.IGNORECASE):
                    return False
                return True
            return False
        p["all_options"] = sorted(set(f for f, _, takes_file in fwd if f not in _DISALLOWED and not takes_file),
                                  key=lambda x: (0 if x.startswith("--") else 1, x))
        regex_flags = list(dict.fromkeys(
            f for f, d, takes_file in fwd
            if _is_rx(f, d) and f not in _DISALLOWED))
        # Also scan raw help for value-taking flags excluded from fwd (e.g. "-Q <regex>")
        _VRX = re.compile(r'^\s*(-[A-Za-z])\s+<(regex|regexp|re|pattern)>', re.IGNORECASE)
        for ln in ht.splitlines():
            m = _VRX.match(ln)
            if m and m.group(1) not in regex_flags and m.group(1) not in _DISALLOWED:
                regex_flags.append(m.group(1))
            if not m:
                m2 = re.match(r'^\s*(-[A-Za-z])\s+<\S+>', ln)
                if m2 and _is_rx(m2.group(1), ln) and m2.group(1) not in regex_flags and m2.group(1) not in _DISALLOWED:
                    regex_flags.append(m2.group(1))
        # ── Separator-based option discovery ──
        separator_flags = []; separator_value_flag = None
        if any(_is_rx(f, d) and re.search(r'\bseparator\b', d, re.IGNORECASE) for f, d, _ in fwd):
            for f, d, _ in fwd:
                if re.search(r'\bseparator\b', d, re.IGNORECASE):
                    if f not in separator_flags: separator_flags.append(f)
                    if re.search(r'=\s*(STRING|REGEXP|REGEX|PATTERN|RE)\b', d, re.IGNORECASE):
                        separator_value_flag = f
            for sf in separator_flags:
                if sf not in regex_flags: regex_flags.append(sf)
        p["separator_flags"] = separator_flags
        p["separator_value_flag"] = separator_value_flag
        # When separator flags exist, only the value flag (-s) should be in the pool.
        if separator_flags and separator_value_flag:
            regex_flags = [separator_value_flag]
        # find-style programs: regex via explicit -regex/-iregex flag
        for f, d, _ in fwd:
            if re.search(r'^-i?regex$', f, re.IGNORECASE):
                p["accepts_options"] = False
                if f not in regex_flags: regex_flags.append(f)
                break
        p["regex_options"] = regex_flags
    else:
        # Find-style fallback: scan entire help text for -regex/-iregex tokens
        if not p["regex_options"]:
            _FIND_TOKEN = re.compile(r'(?<![A-Za-z0-9])-([a-z][a-z0-9_]*)\b')
            find_rx = []
            for m in _FIND_TOKEN.finditer(ht):
                tok = f"-{m.group(1)}"
                if re.search(r'^-i?regex$', tok, re.IGNORECASE) and tok not in find_rx:
                    find_rx.append(tok)
            if find_rx:
                p["regex_options"] = find_rx; p["all_options"] = find_rx
        p["separator_flags"] = []; p["separator_value_flag"] = None
    return p
def _get_prof(prog, pcfg=None):
    bp = _find_bin_aaqc(prog, pcfg)
    ht = ""
    if bp:
        try: ht = sp.run([bp, "--help"], stdout=sp.PIPE, stderr=sp.STDOUT, universal_newlines=True, check=False, timeout=10).stdout or ""
        except: pass
    p = _parse_prof(ht, prog)
    # Fallback: if help text was empty/unavailable, apply known program defaults
    _FALLBACK_PROF = {
        "tac":    {"regex_options": ["-s"], "separator_flags": ["-b", "-r", "-s"], "separator_value_flag": "-s", "arg_order": "regex_first", "accepts_options": True},
        "ptx":    {"regex_options": ["-S", "-W"], "arg_order": "regex_first", "accepts_options": True},
        "find":   {"regex_options": ["-regex"], "arg_order": "file_first", "accepts_options": False},
        "diff":   {"regex_options": ["-F", "-I"], "arg_order": "regex_first", "accepts_options": True},
        "nano":   {"regex_options": ["-Q"], "arg_order": "regex_first", "accepts_options": True},
    }
    if not ht and prog in _FALLBACK_PROF:
        for k, v in _FALLBACK_PROF[prog].items():
            if not p.get(k): p[k] = v
    return p
def _build_run_args(prog, flag, regex, src, src2=None, prof=None, rm="ere"):
    if prof is None: prof = {}
    san = _sanitize(prog, regex, rm) or regex.strip()
    q = _esq(san); qs = _esl(q); wr = f"/{qs}/"
    sf1 = shlex.quote(src) if src else ""; sf2 = shlex.quote(src2) if src2 else sf1
    # m4: fixed invocation (bypass profile logic, regex from CompoSE only)
    if prog == "m4":
        return f"--warn-macro-sequence='{q}' {sf1}".strip()
    sl = prof.get("uses_slash_wrap", False) or prog in _MANUAL_SLASH
    px = prof.get("regex_prefix", ""); od = prof.get("arg_order", "regex_first")
    sps = prof.get("special_syntax")
    sep_flags = prof.get("separator_flags", [])
    sep_val = prof.get("separator_value_flag", "")
    qp = f"{px}{q}" if px else q
    regex_token = f"'{wr}'" if sl else f"'{qp}'"

    # Build flag_prefix: separator boolean flags only
    fp_parts = []
    for ssf in sep_flags:
        sc = ssf.strip()
        if sc and sc != sep_val and sc not in fp_parts:
            fp_parts.append(sc)
    fp = " ".join(fp_parts)
    fp = f"{fp} " if fp else ""

    # Selected option goes immediately before regex
    ef = flag.strip() if flag else ""
    regex_part = f"{ef} {regex_token}" if ef else regex_token

    if sps == "string_colon_regex":
        t = _rnd_txt().replace('"', '\\"'); return f'{fp}"{t}" : \'{qp}\''.strip()
    if sps == "plus_slash_regex":
        q_slash = q.replace("/", r"\/")
        prefix = f"{fp}" if fp else ""
        return f"{prefix}'+/{q_slash}' {sf1}".strip()
    if prog in _DUAL_SRC: return f"{fp}{regex_part} {sf1} {sf2}".strip()
    if od == "file_first": return f"{sf1} {fp}{regex_part}".strip()
    if od == "no_file": return f"{fp}{regex_part}".strip()
    return f"{fp}{regex_part} {sf1}".strip()

__all__ = ['_derive_src_base', '_file_pool', '_find_bin_aaqc', '_build_test_cmd', '_best_src_binary', '_run_binary_get_branches', '_select_src_combined', '_best_opt_binary', '_weighted_random_opt', '_select_options_combined', '_extr_flags', '_parse_prof', '_get_prof', '_build_run_args']