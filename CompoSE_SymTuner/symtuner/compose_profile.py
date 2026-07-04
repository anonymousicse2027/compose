"""CompoSE (SymTuner) usage profiling: src_file pool, script_independent binary probing, --help profile."""

from pathlib import Path
import os, re, json, math, random, string, pickle, subprocess, uuid, hashlib, shutil, sys
from typing import List, Optional, Any, Set, Tuple, Dict, Union
from collections import Counter
from dataclasses import dataclass, asdict, field
from difflib import SequenceMatcher
from subprocess import run as _run, PIPE, STDOUT
from symtuner.logger import get_logger
from symtuner.compose_common import *
from symtuner._shared import manual_path as _shared_manual_path, build_profile as _shared_build_profile


def _src_base(pgm_dir, pgm=""):
    p = Path(pgm_dir).resolve(); parts = list(p.parts)
    return Path(*parts[:parts.index("obj-llvm")]) if "obj-llvm" in parts else p.parent


def _file_pool(base):
    pool = []
    if not base.exists(): return pool
    try:
        for p in base.rglob("*"):
            try:
                if p.is_file() and '/obj-gcov' not in str(p): pool.append(str(p.resolve()))
            except: continue
    except: pass
    return pool


def _exec_dir(pc):
    g = pc.get("gcov_path") or ""; e = pc.get("exec_dir", "").strip("/")
    return Path(g) / e if g and e else (Path(g) if g else None)




def _find_bin(pc, pgm):
    g = pc.get("gcov_path") or ""; e = pc.get("exec_dir", "").strip("/")
    cs = []
    if g:
        if e: cs.append(os.path.join(g, e, pgm))
        cs += [os.path.join(g, "src", pgm), os.path.join(g, pgm)]
    try:
        w = shutil.which(pgm)
        if w: cs.append(w)
    except: pass
    for c in cs:
        if c and os.path.isfile(c) and os.access(c, os.X_OK): return c
    return None


def _prog_inv(pc, pgm, ed):
    bp = _find_bin(pc, pgm)
    if bp:
        try:
            if ed and ed.resolve() == Path(bp).resolve().parent: return f"./{Path(bp).name}"
        except: pass
        return bp
    return pgm






def _run_binary_get_branches(gcov_obj, exec_dir, cmds, keys, gcov_depth=1, timeout=10):
    """Run each command, collect covered branches via gcov -b (in-code; no external script)."""
    result = {}
    target = Path(gcov_obj).resolve()
    if not target.exists():
        return {k: set() for k in keys}
    base = target.parent
    for _ in range(gcov_depth): base = base.parent
    base = base.resolve()
    gcda_pat = str(Path(*(['..'] * gcov_depth)) / '**/*.gcda')
    gcov_pat = str(Path(*(['..'] * gcov_depth)) / '**/*.gcov')
    orig = os.getcwd()
    for k, cmd in zip(keys, cmds):
        branches = set()
        try:
            subprocess.run(f'find {base} -name "*.gcda" -delete 2>/dev/null', shell=True, check=False, timeout=10)
            subprocess.run(f'find {base} -name "*.gcov" -delete 2>/dev/null', shell=True, check=False, timeout=10)
            subprocess.run(cmd, shell=True, cwd=str(exec_dir),
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, timeout=timeout)
            os.chdir(str(target.parent))
            gcda_files = [g for g in Path().glob(gcda_pat) if 'signal.gcda' not in str(g)]
            if gcda_files:
                subprocess.run(f'gcov -b {" ".join(str(g) for g in gcda_files)}',
                               shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                subprocess.run(f'find {base} -name "signal.c.gcov" -delete 2>/dev/null', shell=True, check=False)
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
        result[k] = branches
    try:
        subprocess.run(f'find {base} -name "*.gcda" -delete 2>/dev/null', shell=True, check=False, timeout=10)
        subprocess.run(f'find {base} -name "*.gcov" -delete 2>/dev/null', shell=True, check=False, timeout=10)
    except: pass
    return result


def _build_cmd(pgm, inv, rx, sf, rm, flag="", prof=None):
    if prof is None: prof = {}
    q = _esq(rx.strip()); qs = _esl(q); wr = f"/{qs}/"
    sl = prof.get("uses_slash_wrap", False) or pgm in _MANUAL_SLASH_WRAP
    px = prof.get("regex_prefix", ""); od = prof.get("arg_order", "regex_first"); sp = prof.get("special_syntax")
    sep_flags = prof.get("separator_flags", []); sep_val = prof.get("separator_value_flag", "")
    qp = f"{px}{q}" if px else q
    if sp == "string_colon_regex":
        t = _rnd_txt().replace('"', '\\"'); return f'{inv} {flag + " " if flag else ""}"{t}" : \'{qp}\''.strip()
    regex_token = f"'{wr}'" if sl else f"'{qp}'"
    # Selected option goes before regex
    ef = flag.strip() if flag else ""
    regex_part = f"{ef} {regex_token}" if ef else regex_token
    # Separator boolean flags only
    fp_parts = []
    for s in sep_flags:
        sc = s.strip()
        if sc and sc != sep_val and sc not in fp_parts: fp_parts.append(sc)
    fp = " ".join(fp_parts)
    fp = f"{fp} " if fp else ""
    if od == "file_first": return f"{inv} {sf} {fp}{regex_part}".strip()
    if od == "no_file": return f"{inv} {fp}{regex_part}".strip()
    return f"{inv} {fp}{regex_part} {sf}".strip()


def _best_src(pgm, rm, pc, pool, n, prof=None):
    if not pool: return "", -1
    ed = _exec_dir(pc); bp = _find_bin(pc, pgm)
    if not ed or not bp: return random.choice(pool), -1
    inv = _prog_inv(pc, pgm, ed); cs = _pick(pool, n)
    cmds = [_build_cmd(pgm, inv, SAMPLE_REGEX, sf, rm, prof=prof) for sf in cs]
    bm = _run_binary_get_branches(bp, ed, cmds, cs)
    sc = sorted([(len(bm.get(s, set())), s) for s in cs], key=lambda t: t[0], reverse=True)
    return (sc[0][1], sc[0][0]) if sc and sc[0][0] > 0 else (random.choice(pool), -1)


def _best_opt(pgm, rm, pc, bsrc, pool, prof=None):
    if not pool: return "", -1.0
    ed = _exec_dir(pc); bp = _find_bin(pc, pgm)
    if not ed or not bp: return random.choice(pool), -1.0
    inv = _prog_inv(pc, pgm, ed)
    cmds = [_build_cmd(pgm, inv, SAMPLE_REGEX, bsrc, rm, flag=f, prof=prof) for f in pool]
    bm = _run_binary_get_branches(bp, ed, cmds, pool)
    sc = sorted([(len(bm.get(f, set())), f) for f in pool], key=lambda t: t[0], reverse=True)
    return (sc[0][1], float(sc[0][0])) if sc and sc[0][0] > 0 else (random.choice(pool), -1.0)


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
        for f in fs:
            if f not in _DISALLOWED: res.append((f, ln))
    return res


def _parse_prof(ht, pgm):
    p = {"arg_order": "regex_first", "regex_prefix": "", "regex_options": [], "all_options": [],
         "special_syntax": None, "uses_slash_wrap": pgm in _MANUAL_SLASH_WRAP,
         "needs_dual_src": pgm in _MANUAL_DUAL_SRC, "accepts_options": True,
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
        p["special_syntax"] = "string_colon_regex"; p["arg_order"] = "no_file"
    if re.search(r'\bpBRE\b', ht): p["regex_prefix"] = "p"
    if re.search(r'/REGEXP/', ht): p["uses_slash_wrap"] = True
    if p["accepts_options"]:
        fwd = _extr_flags(ht)
        p["all_options"] = sorted(set(f for f, _ in fwd if f not in _DISALLOWED), key=lambda x: (0 if x.startswith("--") else 1, x))
        # Improved regex-related detection: check description AND flag name
        def _is_rx(flag, desc):
            # Strong signals: always regex
            if re.search(r'\bregex\b|\bregexp\b|\bregular\s+expression|\bBRE\b|\bERE\b', desc, re.IGNORECASE): return True
            if re.search(r'\bRE\b', desc): return True
            if re.search(r'regexp|regex', flag, re.IGNORECASE): return True
            if re.search(r'=\s*(REGEXP|REGEX|RE)\b', desc): return True
            # Weak signal: "pattern" in desc — but NOT if it's a file-glob context
            if re.search(r'\bpattern\b', desc, re.IGNORECASE):
                # File-glob indicators: exclude, files, file name, directory
                if re.search(r'\bexclude\b|\bfiles?\s+that\s+match\b|\bfile\s*name\b|\bglob\b|\bwildcard\b|\bshell\b', desc, re.IGNORECASE):
                    return False
                return True
            return False
        regex_flags = list(dict.fromkeys(f for f, d in fwd if _is_rx(f, d) and f not in _DISALLOWED))
        # Also scan raw help for value-taking flags excluded from fwd (e.g. "-Q <regex>")
        _VRX = re.compile(r'^\s*(-[A-Za-z])\s+<(regex|regexp|re|pattern)>', re.IGNORECASE)
        for ln in ht.splitlines():
            m = _VRX.match(ln)
            if m and m.group(1) not in regex_flags and m.group(1) not in _DISALLOWED:
                regex_flags.append(m.group(1))
            # Also catch if description mentions regex/regular expression
            if not m:
                m2 = re.match(r'^\s*(-[A-Za-z])\s+<\S+>', ln)
                if m2 and _is_rx(m2.group(1), ln) and m2.group(1) not in regex_flags and m2.group(1) not in _DISALLOWED:
                    regex_flags.append(m2.group(1))
        # Separator-based option discovery
        separator_flags = []
        separator_value_flag = None
        regex_mentions_sep = any(_is_rx(f, d) and re.search(r'\bseparator\b', d, re.IGNORECASE) for f, d in fwd)
        if regex_mentions_sep:
            for f, d in fwd:
                if re.search(r'\bseparator\b', d, re.IGNORECASE) and f not in separator_flags:
                    separator_flags.append(f)
                    if re.search(r'=\s*(STRING|REGEXP|REGEX|PATTERN|RE)\b', d, re.IGNORECASE):
                        separator_value_flag = f
            for sf in separator_flags:
                if sf not in regex_flags: regex_flags.append(sf)
        p["separator_flags"] = separator_flags
        p["separator_value_flag"] = separator_value_flag
        # When separator flags exist, only the value flag (-s) should be in the pool.
        # Boolean separator flags (-b, -r) are always added via flag_prefix in _build_sym.
        if separator_flags and separator_value_flag:
            regex_flags = [separator_value_flag]
        # find-style programs: regex via explicit -regex/-iregex flag
        for f, d in fwd:
            if re.search(r'^-i?regex$', f, re.IGNORECASE):
                p["accepts_options"] = False
                if f not in regex_flags: regex_flags.append(f)
                break
        p["regex_options"] = [f for f in regex_flags if f not in _DISALLOWED]
    return p


def _get_prof(bp, pgm):
    if pgm not in _PROF_CACHE:
        p = None
        # Manual-based profile via the shared builder (identical to CompoSE+FeatMaker
        # and CompoSE+AAQC). Falls back to --help parsing when no manual is found.
        mp = _shared_manual_path(pgm)
        if mp:
            binary = bp if (bp and os.path.isfile(bp)) else None
            p = _shared_build_profile(mp, binary, pgm)
            if p is not None:
                get_logger().info(f"[profile] {pgm}: source=manual ({os.path.basename(mp)}) regex_options={p.get('regex_options')}")
        if p is None:
            ht = ""
            if bp and os.path.isfile(bp):
                try: ht = _run([bp, "--help"], stdout=PIPE, stderr=STDOUT, universal_newlines=True, check=False, timeout=10).stdout or ""
                except: pass
            p = _parse_prof(ht, pgm)
            # Fallback: if help text was empty/unavailable, apply known program defaults
            _FB = {
                "tac":  {"regex_options": ["-s"], "separator_flags": ["-b", "-r", "-s"], "separator_value_flag": "-s", "arg_order": "regex_first", "accepts_options": True},
                "ptx":  {"regex_options": ["-S", "-W"], "arg_order": "regex_first", "accepts_options": True},
                "find": {"regex_options": ["-regex"], "arg_order": "file_first", "accepts_options": False},
                "diff": {"regex_options": ["-F", "-I"], "arg_order": "regex_first", "accepts_options": True},
                "nano": {"regex_options": ["-Q"], "arg_order": "regex_first", "accepts_options": True},
            }
            if not ht and pgm in _FB:
                for k, v in _FB[pgm].items():
                    if not p.get(k): p[k] = v
        _PROF_CACHE[pgm] = p
    return _PROF_CACHE[pgm]

__all__ = ['_src_base', '_file_pool', '_exec_dir', '_find_bin', '_prog_inv', '_build_cmd', '_best_src', '_best_opt', '_extr_flags', '_parse_prof', '_get_prof']