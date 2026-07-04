from pathlib import Path
import os, re, json, math, random, string, pickle, subprocess, uuid, hashlib, shutil, sys
from typing import List, Optional, Any, Set, Tuple, Dict, Union
from collections import Counter
from dataclasses import dataclass, asdict, field
from difflib import SequenceMatcher
from subprocess import run as _run, PIPE, STDOUT
from symtuner.logger import get_logger
from symtuner.compose_common import *


def _atomic_write(path, text):
    tmp = path.with_suffix(path.suffix + ".tmp"); tmp.write_text(text, encoding="utf-8"); os.replace(tmp, path)


def _load_score_map(path):
    if not path.exists(): return {}
    try:
        d = json.loads(path.read_text()); return {str(k): float(v) for k, v in d.items()} if isinstance(d, dict) else {}
    except: return {}


def _save_score_map(path, m): _atomic_write(path, json.dumps({k: float(v) for k, v in m.items()}, ensure_ascii=False, indent=2))


def _top_by_score(m, pool, k):
    if not m or not pool or k <= 0: return []
    return [it for _, it in sorted([(m.get(it, 0.0), it) for it in set(pool)], key=lambda x: x[0], reverse=True)[:k]]


def _load_freq_cum(rdir):
    p = rdir / "freq_cum.json"
    if not p.exists(): return Counter()
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
        return Counter({k: int(v) for k, v in d.items()}) if isinstance(d, dict) else Counter()
    except: return Counter()


def _save_freq_cum(rdir, freq):
    _atomic_write(rdir / "freq_cum.json", json.dumps({k: int(v) for k, v in freq.items()}, ensure_ascii=False, indent=2))


def _score_from_freq(covered_sets, freq):
    scores = []
    for s in covered_sets:
        scores.append(sum(1.0 / math.sqrt(int(freq.get(b, 0)) + 1.0) for b in s))
    return scores


def _timeout_base_kinds_for_tool(pgm):
    return TOOL_TIMEOUT_BASE_KINDS.get(pgm, ["CLASS","GROUP","WILDCARD","QUANT","ALT_BRANCH","REDOS_AMBIG","ESCAPE"])


def _compute_score_bug(elapsed_sec, rss_kb, has_crash):

    del rss_kb
    return float(elapsed_sec) + (BUG_BONUS_CRASH if has_crash else 0.0)


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


def bug_bonus_from_tags(tags):
    b=0.0
    if "CRASH" in tags:b+=BUG_BONUS_CRASH
    if "PERF_TIME" in tags:b+=BUG_BONUS_PERF
    if "PERF_MEM" in tags:b+=BUG_BONUS_PERF
    return b


def _check_regex_timeout(regex, pconfig, timeout_sec=5):
    import glob as _glob
    gcov_path=Path(pconfig.get("gcov_path",""))
    exec_rel=pconfig.get("exec_dir","").lstrip("/")
    exec_dir=gcov_path/exec_rel if exec_rel else gcov_path
    tool=pconfig.get("pgm","")
    src=(pconfig.get("src_file","") or "").strip()
    src2=(pconfig.get("src_file_2","") or "").strip()
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
    inp=_pi(src);tmo=f"{timeout_sec}s";q=regex
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
        cmd=["timeout",tmo,str(bp),inp,f"/{q.replace('/',chr(92)+'/')}/","{*}"]
    elif tool=="diff":
        bp=exec_dir/"diff"
        if not bp.exists():return False
        inp2=_pi(src2) or inp or "/dev/null"
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
    else:return False
    try:
        result=_run(cmd,cwd=str(exec_dir),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        return result.returncode==124
    except:return False


_BUG_CORPUS_PATH: Optional[Path] = None


def _init_bug_corpus(rdir):
    global _BUG_CORPUS_PATH;_BUG_CORPUS_PATH=Path(rdir)/"bug_corpus.jsonl"


def _append_bug_entry(entry):
    if _BUG_CORPUS_PATH is None:return
    try:
        with open(_BUG_CORPUS_PATH,"a",encoding="utf-8") as f:f.write(json.dumps(entry,ensure_ascii=False)+"\n")
    except:pass


def _load_bug_corpus_fragments(rdir):
    path=Path(rdir)/"bug_corpus.jsonl"
    if not path.exists():return []
    frags=[]
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():continue
            e=json.loads(line);rx=e.get("regex")
            if rx:frags.append(rx)
    except:pass
    return frags


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
    def prep(self, rx, it, idx=0):
        k = self._n(rx); h = self.index.get(k, {}).get("hash") or self._h(k)
        sd = self.root / h / f"i{it}-{idx}"; sd.mkdir(parents=True, exist_ok=True); return sd
    def add(self, rx, it, sd, score, files, idx=0):
        k = self._n(rx); toks = sorted(_tok(k))
        rec = self.index.setdefault(k, {"hash": self._h(k), "entries": []})
        rec["pattern"] = rx; rec["tokens"] = toks
        rec.setdefault("entries", []).append({"it": it, "idx": idx, "score": float(score),
            "dir": os.path.relpath(sd, self.root), "files": sorted(list(files))})
        self._save()
    def find(self, rx):
        tgt = self._n(rx); tt = _tok(tgt); bs = 0.0; br = None
        for sk, rec in self.index.items():
            kn = self._n(rec.get("pattern", sk))
            st = 1.0 if kn == tgt else SequenceMatcher(None, tgt, kn).ratio()
            stk = _jac(tt, set(rec.get("tokens") or [])); s = st * stk
            if s > bs: bs = s; br = rec
        if not br or bs <= 0: return []
        es = sorted(br.get("entries", []), key=lambda e: float(e.get("score", 0)), reverse=True)
        if not es: return []
        sd = self.root / es[0].get("dir", "")
        return [str(sd)] if sd.exists() else []
    def store(self, it, rx, testcases, score=0.0):
        kts = [tc for tc in testcases if str(tc).endswith('.ktest')]
        if not kts: return

        reached = [kt for kt in kts if _ktest_phase(kt) >= 1]
        if not reached: return
        chosen = random.choice(reached)
        sd = self.prep(rx, it); copied = []
        kp = Path(chosen)
        if kp.exists():
            try: shutil.copy2(str(kp), str(sd / kp.name)); copied.append(kp.name)
            except: pass
            rd = kp.with_suffix(".regex_data")
            if rd.exists():
                try: shutil.copy2(str(rd), str(sd / rd.name))
                except: pass
        if copied: self.add(rx, it, sd, score, copied)


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
    if not p.exists(): return {OP_FRAGMENT: {"tries": 0, "reward": 0.0, "success": 0}}
    try: d = json.loads(p.read_text()); d.setdefault(OP_FRAGMENT, {"tries": 0, "reward": 0.0, "success": 0}); return d
    except: return {OP_FRAGMENT: {"tries": 0, "reward": 0.0, "success": 0}}


def _save_ops(p, d): p.write_text(json.dumps(d, ensure_ascii=False, indent=2), encoding='utf-8')

__all__ = ['_atomic_write', '_load_score_map', '_save_score_map', '_top_by_score', '_load_freq_cum', '_save_freq_cum', '_score_from_freq', '_timeout_base_kinds_for_tool', '_compute_score_bug', '_load_perf_from_istats', '_normalize_log_list', 'classify_klee_error', 'bug_bonus_from_tags', '_check_regex_timeout', '_BUG_CORPUS_PATH', '_init_bug_corpus', '_append_bug_entry', '_load_bug_corpus_fragments', 'SeedCache', '_parse_regex_data_compose', '_ktest_reached_regex', '_ktest_phase', '_load_ops', '_save_ops']