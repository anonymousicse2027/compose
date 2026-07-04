import argparse, os, sys, subprocess as sp, glob, shlex, random, string, tempfile, signal
import re, shutil, json, math, pickle, uuid, hashlib, time
from pathlib import Path
from _shared import get_regex_mode
from typing import Optional, List, Set, Dict, Tuple, Union
from collections import Counter
from dataclasses import dataclass, asdict, field
from difflib import SequenceMatcher
from compose_common import *


def _measure_replay_perf(idx_dir, binary_path, klee_replay_bin="klee-replay", timeout=10):
    idx_dir = Path(idx_dir)
    ktests = list(idx_dir.glob("*.ktest"))
    if not ktests or not binary_path: return 0.0, 0.0
    max_time, max_rss_kb = 0.0, 0.0
    for kt in ktests:
        try:
            cmd = f"/usr/bin/time -v {klee_replay_bin} {binary_path} {kt}"
            result = sp.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            for line in result.stderr.splitlines():
                line = line.strip()
                if "Elapsed (wall clock) time" in line:
                    ts = line.split(": ")[-1].strip(); parts = ts.split(":")
                    if len(parts) == 3: t = float(parts[0])*3600 + float(parts[1])*60 + float(parts[2])
                    elif len(parts) == 2: t = float(parts[0])*60 + float(parts[1])
                    else: t = float(parts[0])
                    max_time = max(max_time, t)
                elif "Maximum resident set size" in line:
                    max_rss_kb = max(max_rss_kb, float(line.split(": ")[-1].strip()))
        except sp.TimeoutExpired: max_time = max(max_time, float(timeout))
        except: pass
    try:
        (idx_dir / "perf.json").write_text(json.dumps({"elapsed_sec": max_time, "max_rss_kb": max_rss_kb, "source": "replay"}, indent=2))
    except: pass
    return max_time, max_rss_kb
def _compute_score_bug(elapsed_sec, rss_kb, has_crash):



    del rss_kb
    return elapsed_sec + (BUG_BONUS_CRASH if has_crash else 0.0)
def _atomic_write(path, text):
    tmp = Path(str(path) + ".tmp"); tmp.write_text(text, encoding="utf-8"); os.replace(tmp, path)
def _load_smap(p):
    if not Path(p).exists(): return {}
    try: d = json.loads(Path(p).read_text()); return {str(k): float(v) for k, v in d.items()} if isinstance(d, dict) else {}
    except: return {}
def _save_smap(p, m): _atomic_write(Path(p), json.dumps({k: float(v) for k, v in m.items()}, ensure_ascii=False, indent=2))
def _top_score(m, pool, k):
    if not m or not pool or k <= 0: return []
    return [it for _, it in sorted([(m.get(it, 0.0), it) for it in set(pool)], key=lambda x: x[0], reverse=True)[:k]]
def _load_freq(rdir):
    p = Path(rdir) / "freq_cum.json"
    if not p.exists(): return Counter()
    try: d = json.loads(p.read_text()); return Counter({k: int(v) for k, v in d.items()}) if isinstance(d, dict) else Counter()
    except: return Counter()
def _save_freq(rdir, freq): _atomic_write(Path(rdir) / "freq_cum.json", json.dumps({k: int(v) for k, v in freq.items()}, ensure_ascii=False, indent=2))
def _score_freq(covsets, freq):
    return [sum(1.0 / math.sqrt(int(freq.get(b, 0)) + 1.0) for b in s) for s in covsets]
def _collect_coverage_from_outdir(outdir, gcov_obj, gcov_depth=1):
    od = Path(outdir)
    if not od.exists(): return set()
    ktests = list(od.glob("*.ktest"))
    if not ktests: return set()
    covered = set()
    target = Path(gcov_obj)
    base = target.parent
    for _ in range(gcov_depth): base = base / '..'
    for kt in ktests:
        try:

            sp.run(f'rm -f {base}/**/*.gcda {base}/**/*.gcov', shell=True, check=False)

            sp.run(f'klee-replay {gcov_obj} {kt}', shell=True, stdout=sp.DEVNULL, stderr=sp.DEVNULL, check=False, timeout=30)

            orig = Path.cwd(); os.chdir(str(target.parent))
            sp.run(f'gcov -b {" ".join(str(g) for g in Path().glob(str(Path(*([".."]*gcov_depth)) / "**/*.gcda")))}',
                   shell=True, stdout=sp.DEVNULL, stderr=sp.DEVNULL, check=False)
            for gcov_file in Path().glob(str(Path(*([".."]*gcov_depth)) / "**/*.gcov")):
                try:
                    with gcov_file.open(errors='replace') as f:
                        fn = f.readline().strip().split(':')[-1]
                        for li, line in enumerate(f):
                            if 'branch' in line and 'never' not in line and 'taken 0%' not in line:
                                covered.add(f'{fn} {li}')
                except: pass
            os.chdir(str(orig))
        except: pass
    return covered
class SeedCache:
    def __init__(self, root):
        self.root = Path(root).resolve(); self.root.mkdir(parents=True, exist_ok=True)
        self.idx_path = self.root / "seed_index.json"
        self.index = self._load()
    def _load(self):
        try: return json.loads(self.idx_path.read_text(encoding="utf-8"))
        except: return {}
    def _save(self): _atomic_write(self.idx_path, json.dumps(self.index, ensure_ascii=False, indent=2))
    @staticmethod
    def _n(rx): return re.sub(r"\s+", "", rx.strip())
    @staticmethod
    def _h(rx): return hashlib.sha1(rx.encode("utf-8", "ignore")).hexdigest()[:12]
    def prep(self, rx, j, i):
        k = self._n(rx); h = self.index.get(k, {}).get("hash") or self._h(k)
        sd = self.root / h / f"j{j}-i{i}"; sd.mkdir(parents=True, exist_ok=True); return sd
    def add(self, rx, j, i, sd, score, files):
        k = self._n(rx)
        rec = self.index.setdefault(k, {"hash": self._h(k), "entries": []})
        rec["pattern"] = rx; rec["tokens"] = sorted(_tok(k))
        rec.setdefault("entries", []).append({"j": j, "i": i, "score": float(score),
            "dir": os.path.relpath(sd, self.root), "files": sorted(list(files))})
        self._save()
    def find(self, rx):
        tgt = self._n(rx); tt = _tok(tgt); bs = 0.0; br = None
        for sk, rec in self.index.items():
            kn = self._n(rec.get("pattern", sk))
            s = 1.0 if kn == tgt else _lcs_dice(tgt, kn)
            if s > bs: bs = s; br = rec
        if not br or bs <= 0: return []
        es = sorted(br.get("entries", []), key=lambda e: float(e.get("score", 0)), reverse=True)
        if not es: return []
        sd = self.root / es[0].get("dir", "")
        return [str(sd)] if sd.exists() else []
    def store(self, j, i, rx, outdir, score=0.0, filter_regex=True):
        kts = list(Path(outdir).glob("*.ktest"))
        if not kts: return

        if filter_regex:
            reached = [kt for kt in kts if _ktest_phase(kt) >= 1]
            if not reached: return
            chosen = random.choice(reached)
        else:
            chosen = random.choice(kts)
        sd = self.prep(rx, j, i); copied = []
        try: shutil.copy2(str(chosen), str(sd / chosen.name)); copied.append(chosen.name)
        except: pass
        rd_file = chosen.with_suffix(".regex_data")
        if rd_file.exists():
            try: shutil.copy2(str(rd_file), str(sd / rd_file.name))
            except: pass
        if copied: self.add(rx, j, i, sd, score, copied)
def _parse_regex_data_compose(rd_path):
    try:
        text = Path(rd_path).read_text(encoding="utf-8", errors="replace").strip()
        if not text: return None
        result = {"regex_compile_reached": False, "regex_match_reached": False, "regex_functions": []}
        for line in text.split("\n"):
            s = line.strip()
            if s.startswith("regex_compile_reached="): result["regex_compile_reached"] = s.endswith("true")
            elif s.startswith("regex_match_reached="): result["regex_match_reached"] = s.endswith("true")
            elif s.startswith("regex_functions="):
                fs = s[len("regex_functions="):]
                if fs: result["regex_functions"] = [f.strip() for f in fs.split(",") if f.strip()]
        return result
    except: return None
def _ktest_reached_regex(ktest_path):
    rd_path = Path(ktest_path).with_suffix(".regex_data")
    if not rd_path.exists(): return True
    data = _parse_regex_data_compose(rd_path)
    if data is None: return True
    return data.get("regex_compile_reached", False) or data.get("regex_match_reached", False)
def _ktest_phase(ktest_path):
    rd_path = Path(ktest_path).with_suffix(".regex_data")
    if not rd_path.exists(): return 0
    data = _parse_regex_data_compose(rd_path)
    if data is None: return 0
    return 1 if data.get("regex_compile_reached", False) else 0
def _load_ops(p):
    default = {OP_FRAGMENT: {"tries": 0, "reward": 0.0, "success": 0},
               OP_RANDOM:   {"tries": 0, "reward": 0.0, "success": 0}}
    if not Path(p).exists(): return default
    try:
        d = json.loads(Path(p).read_text())
        for k in (OP_FRAGMENT, OP_RANDOM):
            d.setdefault(k, {"tries": 0, "reward": 0.0, "success": 0})
        return d
    except: return default
def _save_ops(p, d): Path(p).write_text(json.dumps(d, ensure_ascii=False, indent=2), encoding='utf-8')
def _load_perf_from_istats(idx_dir):
    p=Path(idx_dir)/"perf.json"
    if p.exists():
        try:m=json.loads(p.read_text(encoding="utf-8"));return float(m.get("elapsed_sec",0.0)),float(m.get("max_rss_kb",0.0))
        except:pass
    ist=list(Path(idx_dir).glob("*.istats"))
    if not ist:return 0.0,0.0
    try:text=ist[0].read_text(encoding="utf-8",errors="ignore")
    except:return 0.0,0.0
    lines=[ln.strip() for ln in text.splitlines() if ln.strip()]
    ev_line=None
    for ln in lines:
        if ln.startswith("events:"):ev_line=ln;break
    if not ev_line:return 0.0,0.0
    parts=ev_line.split();events=parts[1:]
    def _idx(e):
        try:return 2+events.index(e)
        except:return None
    ir,rt,qt,si=_idx("Ireal"),_idx("Rtime"),_idx("Qtime"),_idx("States")
    slow,mem=0.0,0.0
    for ln in lines:
        if not ln or not(ln[0].isdigit() or ln[0]=='-'):continue
        cols=ln.split()
        if len(cols)<3:continue
        def gv(idx):
            if idx is None or idx>=len(cols):return 0.0
            try:return float(cols[idx])
            except:return 0.0
        slow+=gv(ir)+gv(rt)+gv(qt)
        st=gv(si)
        if st>mem:mem=st
    return slow,mem
def _normalize_log_list(vals):
    logs=[math.log1p(max(0.0,v)) for v in vals]
    mx=max(logs) if logs else 0.0
    return [x/mx if mx>0 else 0.0 for x in logs]
def classify_klee_error(idx_dir):
    errs=list(Path(idx_dir).glob("*.err"))
    if not errs:return None,None
    p=errs[0]
    try:txt=p.read_text(errors="ignore")
    except:txt=""
    nm=p.name.lower()
    if "assert" in nm or "assert" in txt:return "CRASH","ASSERTION"
    if "invalid read" in txt or "invalid write" in txt or "ptr" in nm:return "CRASH","INVALID_MEM"
    if "abort" in nm or "abort" in txt:return "CRASH","ABORT"
    return "CRASH","UNKNOWN"
def _check_regex_timeout(regex, pcfg_dict, timeout_sec=5):
    import glob as _glob
    gcov_path=Path(pcfg_dict.get("gcov_path",""))
    exec_rel=pcfg_dict.get("exec_dir","").lstrip("/")
    exec_dir=gcov_path/exec_rel if exec_rel else gcov_path
    tool=pcfg_dict.get("pgm","")
    src_f=(pcfg_dict.get("src_file","") or "").strip()
    src2_f=(pcfg_dict.get("src_file_2","") or "").strip()
    def _pi(sf):
        if not sf:return None
        if any(c in sf for c in "*?[]"):
            hits=[p for p in _glob.glob(sf) if os.path.isfile(p)];return hits[0] if hits else None
        if os.path.isdir(sf):
            for r,_,fs in os.walk(sf):
                for fn in fs:
                    p=os.path.join(r,fn)
                    if os.path.isfile(p):return p
            return None
        return sf if os.path.isfile(sf) else None
    inp=_pi(src_f);tmo=f"{timeout_sec}s";q=regex
    if tool=="grep":
        bp=exec_dir/"grep"
        if not bp.exists():return False
        cmd=["timeout",tmo,str(bp),"-E",q,inp or "/dev/null"]
    elif tool=="sed":
        bp=exec_dir/"sed"
        if not bp.exists():return False
        cmd=["timeout",tmo,str(bp),"-E","-n",f"/{q.replace('/',chr(92)+'/')}/p",inp or "/dev/null"]
    elif tool=="gawk":
        bp=exec_dir/"gawk"
        if not bp.exists():return False
        cmd=["timeout",tmo,str(bp),f"/{q.replace('/',chr(92)+'/')}/ {{print $0}}",inp or "/dev/null"]
    elif tool=="csplit":
        bp=exec_dir/"csplit"
        if not bp.exists() or not inp:return False
        cmd=["timeout",tmo,str(bp),inp,f"/{q.replace('/',chr(92)+'/')}/","{{*}}"]
    elif tool=="diff":
        bp=exec_dir/"diff"
        if not bp.exists():return False
        inp2=_pi(src2_f) or inp or "/dev/null"
        cmd=["timeout",tmo,str(bp),"-I",q,inp or "/dev/null",inp2]
    elif tool=="expr":
        bp=exec_dir/"expr"
        if not bp.exists():return False
        rs=''.join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789",k=16))
        cmd=["timeout",tmo,str(bp),rs,":",q]
    elif tool=="find":
        bp=exec_dir/"find"
        if not bp.exists():return False
        sd=inp if inp and os.path.isdir(inp) else str(exec_dir)
        cmd=["timeout",tmo,str(bp),sd,"-type","f","-regex",q]
    elif tool=="nano":
        bp=exec_dir/"nano"
        if not bp.exists():return False
        cmd=["timeout",tmo,str(bp),"-Q",q,inp or "/dev/null"]
    elif tool=="nl":
        bp=exec_dir/"nl"
        if not bp.exists():return False
        cmd=["timeout",tmo,str(bp),"-b",f"p{q}",inp or "/dev/null"]
    elif tool=="ptx":
        bp=exec_dir/"ptx"
        if not bp.exists():return False
        cmd=["timeout",tmo,str(bp),"-W",q,inp or "/dev/null"]
    elif tool=="tac":
        bp=exec_dir/"tac"
        if not bp.exists():return False
        cmd=["timeout",tmo,str(bp),"-r","-s",q,inp or "/dev/null"]
    elif tool=="m4":
        bp=exec_dir/"m4"
        if not bp.exists():return False
        cmd=["timeout",tmo,str(bp),f"--warn-macro-sequence={q}",inp or "/dev/null"]
    else:return False
    try:
        from subprocess import run as _srun
        result=_srun(cmd,cwd=str(exec_dir),stdout=sp.DEVNULL,stderr=sp.DEVNULL)
        return result.returncode==124
    except:return False
def _init_bug_corpus(rdir_path):
    global _BUG_CORPUS_PATH;_BUG_CORPUS_PATH=Path(rdir_path)/"bug_corpus.jsonl"
def _append_bug_entry(entry):
    if _BUG_CORPUS_PATH is None:return
    try:
        with open(_BUG_CORPUS_PATH,"a",encoding="utf-8") as f:f.write(json.dumps(entry,ensure_ascii=False)+"\n")
    except:pass
def _load_bug_corpus_fragments(rdir_path):
    path=Path(rdir_path)/"bug_corpus.jsonl"
    if not path.exists():return []
    frags=[]
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():continue
            e=json.loads(line);rx=e.get("regex")
            if rx:frags.append(rx)
    except:pass
    return frags

__all__ = ['_measure_replay_perf', '_compute_score_bug', '_atomic_write', '_load_smap', '_save_smap', '_top_score', '_load_freq', '_save_freq', '_score_freq', '_collect_coverage_from_outdir', 'SeedCache', '_parse_regex_data_compose', '_ktest_reached_regex', '_ktest_phase', '_load_ops', '_save_ops', '_load_perf_from_istats', '_normalize_log_list', 'classify_klee_error', '_check_regex_timeout', '_init_bug_corpus', '_append_bug_entry', '_load_bug_corpus_fragments']