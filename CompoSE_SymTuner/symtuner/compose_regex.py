from pathlib import Path
import os, re, json, math, random, string, pickle, subprocess, uuid, hashlib, shutil, sys
from typing import List, Optional, Any, Set, Tuple, Dict, Union
from collections import Counter
from dataclasses import dataclass, asdict, field
from difflib import SequenceMatcher
from subprocess import run as _run, PIPE, STDOUT
from symtuner.logger import get_logger
from symtuner.compose_common import *


def _depth_ok(s, lim=_MAX_DEPTH):
    d = 0; esc = False; ic = False
    for c in s:
        if esc: esc = False; continue
        if c == '\\': esc = True; continue
        if ic:
            if c == ']': ic = False
            continue
        if c == '[': ic = True; continue
        if c == '(': d += 1
        elif c == ')': d = max(0, d - 1)
        if d > lim: return False
    return True


def _cap_ds(s):
    return s


def _strip_mid(s): return _RE_MID.sub('', s)


def _pcre_only(s): return bool(_RE_LOOK.search(s) or _RE_PCRE.search(s))


def _rm_wb(s): return _RE_WB.sub('', s)


def _ere2bre(p):
    o = []; esc = False; ic = False
    for c in p:
        if esc: o.append('\\' + c); esc = False; continue
        if c == '\\': esc = True; continue
        if ic:
            o.append(c)
            if c == ']': ic = False
            continue
        if c == '[': ic = True; o.append(c); continue
        if c in '()|+?{}': o.append('\\' + c)
        else: o.append(c)
    if esc: o.append('\\')
    return ''.join(o)


def _bre2ere(p):
    o = []; i = 0; n = len(p); ic = False
    while i < n:
        c = p[i]
        if ic:
            o.append(c)
            if c == ']': ic = False
            i += 1; continue
        if c == '[': ic = True; o.append(c); i += 1; continue
        if c == '\\' and i + 1 < n:
            nx = p[i + 1]
            if nx in '()|+?{}': o.append(nx); i += 2; continue
            o.append(c); o.append(nx); i += 2; continue
        o.append(c); i += 1
    return ''.join(o)


def _too_complex(pgm, s, rm):
    L = len(s)
    if rm == "ere" and _RE_BREF.search(s): return True
    if L > _MAX_LEN or not _depth_ok(s): return True
    if len(_RE_POSIX.findall(s)) > _MAX_POSIX: return True
    if len(_RE_WB.findall(s)) > _MAX_WB: return True
    if len(_RE_ALT.findall(s)) > _MAX_ALT: return True
    if _RE_NQ.search(s): return True

    if pgm in ('tac', 'nl'):
        if L > _MAX_LEN_TAC_NL or len(_RE_CTRL.findall(s)) > 4: return True
        if rm != "bre" and _RE_BREF.search(s): return True
    if pgm in ('expr', 'csplit'):
        if L > _MAX_LEN_EXPR_CSPLIT: return True
        if rm != "bre" and _RE_BREF.search(s): return True
    if pgm in ('grep', 'find', 'ptx'):
        if rm != "bre" and _RE_BREF.search(s): return True
    return False


def _sanitize(pgm, pat, rm):
    if rm not in ("bre", "ere"): return None
    s = (pat or "").strip()
    if not s or _pcre_only(s): return None
    s = _cap_ds(s); s = _strip_mid(s); s = _rm_wb(s)
    if rm == "ere":
        s = _bre2ere(s)
    elif rm == "bre": s = _ere2bre(s)
    b = s.strip()
    return b if b and b not in ('^', '$', '^$') else None


def _grep_ok(pat, rm):
    try:
        p = subprocess.run(["grep", "-E" if rm == "ere" else "-G", "--", pat],
                           input="", universal_newlines=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return p.returncode != 2
    except Exception: return False


def _wide_fragment_boost(kind, text):

    return 1.0
    b = 1.0
    if kind in ("BACKREF","BACKREF_SEQ"): b *= 1.8
    if kind == "GROUP":
        if ".*" in text or ".{" in text: b *= 2.0
        if r"\w" in text or r"\d" in text or "[[:alnum:]]" in text: b *= 1.6
    if kind in ("WILDCARD","CLASS"):
        if ".*" in text or ".{" in text or "+" in text: b *= 1.5
    return b


def _collect_group_count(pat):
    cnt=0;i=0;n=len(pat);esc=False;ic=False
    while i<n:
        ch=pat[i]
        if esc:esc=False;i+=1;continue
        if ch=='\\':esc=True;i+=1;continue
        if ic:
            if ch==']':ic=False
            i+=1;continue
        if ch=='[':ic=True;i+=1;continue
        if ch=='(':
            if pat.startswith('(?:',i):i+=1
            else:cnt+=1
            i+=1;continue
        i+=1
    return cnt


def _balanced_groups_bug(s):
    dp=0;dc=0;esc=False
    for ch in s:
        if esc:esc=False;continue
        if ch=='\\':esc=True;continue
        if ch=='[':dc+=1;continue
        if ch==']':
            if dc==0:return False
            dc-=1;continue
        if dc>0:continue
        if ch=='(':dp+=1
        elif ch==')':
            if dp==0:return False
            dp-=1
    return dp==0 and dc==0


def _mirror_tail_insert(pat, prob=0.20):
    if random.random()>=prob:return pat,None
    g=_collect_group_count(pat)
    tc=[("ALT_BRANCH","(a|aa)+"),("ALT_BRANCH","(ab|a)+"),("QUANT","(a+)+"),("QUANT","(.+)+"),("OVERLAP_PREFIX","(ab|aba)+"),("OVERLAP_PREFIX","(a|ab)a+")]
    if g>=2:
        L=random.randint(2,min(4,g));br=list(range(max(1,g-L+1),g+1))
        if len(br)>=3 and random.random()<0.35:mid=br[1:-1];random.shuffle(mid);seq=[br[0]]+mid+[br[-1]]
        else:seq=list(reversed(br))
        tc.append(("BACKREF_SEQ",''.join(f"\\{k}" for k in seq)))
    kind,tail=random.choice(tc)
    return pat+tail,{"op":OP_MIRROR_TAIL,"to_kind":kind,"to_text":tail}


def mutate_once_bug_exploit(pattern, fdb, max_trials=50, k=3, current_iteration=-1):
    try:base_nodes=parse_nodes(pattern)
    except:return pattern,[]
    if not base_nodes or not fdb.items or k<=0:
        m2,op2=_mirror_tail_insert(pattern);return (m2,[op2] if op2 else [])
    for _ in range(max_trials):
        nodes=base_nodes[:];random.shuffle(nodes)
        nodes.sort(key=lambda nd:-(MUTATE_KIND_WEIGHTS.get(nd.kind,40)*random.random()))
        picked,used_pairs,used_ops=[],[],[]
        for nd in nodes:
            if len(picked)>=k:break
            if nd.kind in MUTATE_SKIP_KINDS_BUG:continue
            if any(not(nd.end<=p.start or nd.start>=p.end) for p in picked):continue
            repl=fdb.pick(nd.kind,ci=current_iteration)
            if not repl or repl==nd.text:continue
            picked.append(nd);used_pairs.append((nd,repl))
            used_ops.append({"op":OP_FRAGMENT,"to_kind":nd.kind,"to_text":repl,"from_kind":nd.kind,"from_text":nd.text})
            fdb.record_use(nd.kind,repl,current_iteration)
        if not used_pairs:
            m2,op2=_mirror_tail_insert(pattern)
            if op2:return m2,[op2]
            continue
        used_pairs.sort(key=lambda t:t[0].start);out=[];last=0
        for nd,repl in used_pairs:out.append(pattern[last:nd.start]);out.append(repl);last=nd.end
        out.append(pattern[last:]);mutated=''.join(out)
        mutated2,mt_op=_mirror_tail_insert(mutated)
        if mt_op:used_ops.append(mt_op)
        if not _balanced_groups_bug(mutated2):
            if mt_op and _balanced_groups_bug(mutated):
                try:re.compile(mutated);return mutated,used_ops[:-1]
                except:pass
            continue
        try:re.compile(mutated2)
        except:
            if mt_op and _balanced_groups_bug(mutated):
                try:re.compile(mutated);return mutated,used_ops[:-1]
                except:pass
            continue
        return mutated2,used_ops
    m2,op2=_mirror_tail_insert(pattern);return (m2,[op2] if op2 else [])


def mutate_once_bug_explore(pattern, fdb, max_trials=50, k=3, current_iteration=-1):
    try:base_nodes=parse_nodes(pattern)
    except:return pattern,[]
    if not base_nodes or not fdb.items or k<=0:
        m2,op2=_mirror_tail_insert(pattern);return (m2,[op2] if op2 else [])
    for _ in range(max_trials):
        nodes=base_nodes[:];random.shuffle(nodes)
        nodes.sort(key=lambda nd:-(MUTATE_KIND_WEIGHTS.get(nd.kind,40)*random.random()))
        picked,used_pairs,used_ops=[],[],[]
        for nd in nodes:
            if len(picked)>=k:break
            if nd.kind in MUTATE_SKIP_KINDS_BUG:continue
            if any(not(nd.end<=p.start or nd.start>=p.end) for p in picked):continue
            pool=[v for (kk,_),v in fdb.items.items() if kk==nd.kind]
            if not pool:continue
            repl=random.choice(pool).text
            if not repl or repl==nd.text:continue
            picked.append(nd);used_pairs.append((nd,repl))
            used_ops.append({"op":OP_FRAGMENT,"to_kind":nd.kind,"to_text":repl,"from_kind":nd.kind,"from_text":nd.text})
            fdb.record_use(nd.kind,repl,current_iteration)
        if not used_pairs:
            m2,op2=_mirror_tail_insert(pattern)
            if op2:return m2,[op2]
            continue
        used_pairs.sort(key=lambda t:t[0].start);out=[];last=0
        for nd,repl in used_pairs:out.append(pattern[last:nd.start]);out.append(repl);last=nd.end
        out.append(pattern[last:]);mutated=''.join(out)
        mutated2,mt_op=_mirror_tail_insert(mutated)
        if mt_op:used_ops.append(mt_op)
        if not _balanced_groups_bug(mutated2):
            if mt_op and _balanced_groups_bug(mutated):
                try:re.compile(mutated);return mutated,used_ops[:-1]
                except:pass
            continue
        try:re.compile(mutated2)
        except:
            if mt_op and _balanced_groups_bug(mutated):
                try:re.compile(mutated);return mutated,used_ops[:-1]
                except:pass
            continue
        return mutated2,used_ops
    m2,op2=_mirror_tail_insert(pattern);return (m2,[op2] if op2 else [])


@dataclass
class FragStat:
    n: int = 0; reward_sum: float = 0.0; success: int = 0
    fail_compile: int = 0; last_used_iter: int = -1; ewma: float = 0.0


@dataclass
class FragItem:
    kind: str; text: str; stat: FragStat


@dataclass
class RNode:
    kind: str; start: int; end: int; text: str


def _norm_sig(kind, text):
    t = re.sub(r"\s+", "", text)
    t = re.sub(r"\.\{0,\d+\}", ".{0,N}", t); t = re.sub(r"\.\{1,\d+\}", ".{1,N}", t)
    t = re.sub(r"\{0,\d+\}", "{0,N}", t); t = re.sub(r"\{1,\d+\}", "{1,N}", t)
    t = re.sub(r"\{\d+\}", "{K}", t); t = re.sub(r"\{\d+,\}", "{K,}", t); t = re.sub(r"\{\d+,\d+\}", "{K,M}", t)
    if kind == "LITERAL": t = re.sub(r"[A-Za-z0-9]{3,}", "AAA", t)
    return f"{kind}:{t}"


def _resc(p, i):
    n = len(p)
    if i >= n or p[i] != '\\': return i + 1
    i += 1
    if i >= n: return i
    if p[i] in ('p', 'P') and i + 1 < n and p[i+1] == '{':
        j = i + 2; d = 1
        while j < n and d > 0:
            if p[j] == '{': d += 1
            elif p[j] == '}': d -= 1
            j += 1
        return j
    return i + 1


def _rcc(p, i):
    n = len(p); i += 1; cl = False
    while i < n:
        if p[i] == '\\': i = _resc(p, i); continue
        if p[i] == ']': i += 1; cl = True; break
        i += 1
    return i, cl


def _rgrp(p, i):
    n = len(p); i += 1; d = 1
    while i < n and d > 0:
        c = p[i]
        if c == '\\': i = _resc(p, i); continue
        if c == '[': i, _ = _rcc(p, i); continue
        if c == '(': d += 1; i += 1; continue
        if c == ')': d -= 1; i += 1; continue
        i += 1
    return i


def _rq(p, i):
    if i >= len(p): return i
    m = _QRE.match(p[i:]); return i + m.end() if m else i


def _mq(p, pos):
    if pos < len(p) and p[pos] in _QS:
        e = _rq(p, pos)
        if e > pos: return (pos, e)
    return None


def parse_nodes(pat):
    n = len(pat); nds = []; i = 0
    while i < n:
        c = pat[i]
        if c == '\\':
            ee = _resc(pat, i); tk = pat[i:ee]
            if tk in _BS: nds.append(RNode("BOUNDARY", i, ee, tk)); i = ee; continue
            if tk in _EC:
                nds.append(RNode("ESCAPE", i, ee, tk))
                q = _mq(pat, ee)
                if q: nds.append(RNode("QUANT", q[0], q[1], pat[q[0]:q[1]])); i = q[1]
                else: i = ee
                continue
            nds.append(RNode("ESCAPED", i, ee, tk))
            q = _mq(pat, ee)
            if q: nds.append(RNode("QUANT", q[0], q[1], pat[q[0]:q[1]])); i = q[1]
            else: i = ee
            continue
        if c == '[':
            cc, cl = _rcc(pat, i)
            if cl:
                nds.append(RNode("CLASS", i, cc, pat[i:cc]))
                q = _mq(pat, cc)
                if q: nds.append(RNode("QUANT", q[0], q[1], pat[q[0]:q[1]])); i = q[1]
                else: i = cc
            else: i = cc
            continue
        if c == '(':
            ge = _rgrp(pat, i); nds.append(RNode("GROUP", i, ge, pat[i:ge]))
            q = _mq(pat, ge)
            if q: nds.append(RNode("QUANT", q[0], q[1], pat[q[0]:q[1]])); i = q[1]
            else: i = ge
            continue
        if c == '.':
            nds.append(RNode("WILDCARD", i, i+1, '.'))
            q = _mq(pat, i+1)
            if q: nds.append(RNode("QUANT", q[0], q[1], pat[q[0]:q[1]])); i = q[1]
            else: i += 1
            continue
        if c in ('^', '$'): nds.append(RNode("ANCHOR", i, i+1, c)); i += 1; continue
        if c == '|': nds.append(RNode("ALT_BRANCH", i, i+1, c)); i += 1; continue
        if c in _QS:
            qe = _rq(pat, i)
            if qe > i: nds.append(RNode("QUANT", i, qe, pat[i:qe])); i = qe
            else: nds.append(RNode("LITERAL", i, i+1, c)); i += 1
            continue
        j = i
        while j < n and pat[j] not in _MC and pat[j] != '\\': j += 1
        j = max(j, i + 1); nds.append(RNode("LITERAL", i, j, pat[i:j])); i = j
    return nds


def _cnt_nl(nds): return sum(1 for nd in nds if nd.kind != "LITERAL")


def _uniq_nlk(nds): return {nd.kind for nd in nds if nd.kind != "LITERAL"}


class FragmentDB:
    def __init__(self, path):
        self.path = Path(path); self.items: Dict[Tuple[str, str], FragItem] = {}
        self._load(); self._purge()
    def _purge(self):
        for k in [k for k, it in self.items.items() if int(getattr(it.stat, "fail_compile", 0)) > 0]:
            self.items.pop(k, None)
    def _load(self):
        self.items = {}
        if not self.path.exists(): return
        try:
            raw = pickle.load(open(self.path, "rb"))
            if isinstance(raw, dict):
                for k, v in raw.items():
                    if isinstance(k, tuple) and len(k) == 2:
                        kk, tt = k
                        if isinstance(v, dict):
                            si = v.get("stat", {}) if isinstance(v.get("stat"), dict) else {}
                            st = FragStat(**{**FragStat().__dict__, **si})
                            kind = v.get("kind", kk); text = v.get("text", tt)
                            if kind in ALL_KINDS: self.items[(kind, text)] = FragItem(kind, text, st)
                        elif isinstance(v, FragItem) and v.kind in ALL_KINDS: self.items[(v.kind, v.text)] = v
            elif isinstance(raw, list):
                for it in raw:
                    try:
                        k, t = it
                        if k in ALL_KINDS: self.items[(k, t)] = FragItem(k, t, FragStat())
                    except: continue
        except: self.items = {}
    def save(self):
        self._purge()
        pickle.dump({(k, t): {"kind": v.kind, "text": v.text, "stat": asdict(v.stat)} for (k, t), v in self.items.items()},
                     open(self.path, "wb"))
    def add_from_patterns(self, patterns):
        seen_keys = set(self.items.keys()); seen_sigs = {_norm_sig(k, t) for (k, t) in self.items}
        for p in patterns:
            try:
                for nd in parse_nodes(p):
                    sig = _norm_sig(nd.kind, nd.text); key = (nd.kind, nd.text)
                    if sig not in seen_sigs and key not in seen_keys:
                        self.items[key] = FragItem(nd.kind, nd.text, FragStat())
                        seen_keys.add(key); seen_sigs.add(sig)
            except: continue
        self._purge()
    def record_use(self, k, t, it):
        x = self.items.get((k, t))
        if x: x.stat.n += 1; x.stat.last_used_iter = it
    def record_reward(self, k, t, r):
        x = self.items.get((k, t))
        if x:
            x.stat.reward_sum += float(r)
            if r > 0: x.stat.success += 1
            x.stat.ewma = x.stat.reward_sum / max(1, x.stat.n)
    def record_fail(self, k, t): self.items.pop((k, t), None)
    def kpool(self, k): return sum(1 for (kk, _) in self.items if kk == k)
    def prune(self, ci):
        if not self.items: return 0
        bk: Dict[str, List[FragItem]] = {}
        for (_, _), it in self.items.items(): bk.setdefault(it.kind, []).append(it)
        keep = set()
        for kind, items in bk.items():
            if not items: continue
            N = sum(max(0, int(it.stat.n)) for it in items)
            lt = math.log(1.0 + max(0, N))
            sc = sorted([((it.stat.reward_sum / max(1, int(it.stat.n))) + math.sqrt(lt / (1.0 + max(0, int(it.stat.n)))), (it.kind, it.text))
                          for it in items], key=lambda x: x[0], reverse=True)
            for _, key in sc[:max(50, int(0.2 * len(items)))]: keep.add(key)
        dl = [k for k, it in self.items.items() if k not in keep and max(0, int(it.stat.n)) > 0 and it.stat.reward_sum == 0.0]
        for k in dl: self.items.pop(k, None)
        return len(dl)
    def pick(self, kind, avoid=None, ci=-1, iu=None):
        avoid = avoid or set(); iu = iu or Counter()
        pool = [v for (k, _), v in self.items.items() if k == kind and v.text not in avoid and int(getattr(v.stat, "fail_compile", 0)) == 0]
        if not pool: return None
        p2 = [v for v in pool if iu[(kind, v.text)] == 0]
        if p2: pool = p2
        N = sum(max(0, v.stat.n) for v in pool); lt = math.log(1.0 + max(0, N))
        best = None; bs = -1e18
        for v in pool:
            n = max(0, int(v.stat.n))
            s = ((v.stat.reward_sum / n) if n > 0 else 0.0) + (math.sqrt(lt / (1.0 + n)) if lt > 0 else 0.0)
            if s > bs or (s == bs and random.random() < 0.5): best = v; bs = s
        return best.text if best else None
    def export_preview(self, path, lim=300):
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("kind\ttext\tn\treward\tsuccess\tfail\n")
                for i, ((_, _), v) in enumerate(self.items.items()):
                    if i >= lim: break
                    f.write(f"{v.kind}\t{v.text}\t{v.stat.n}\t{v.stat.reward_sum:.4f}\t{v.stat.success}\t{v.stat.fail_compile}\n")
        except: pass


def _kpri(nds, fdb, ku):
    return sorted(nds, key=lambda nd: (1 if ku.get(nd.kind, 0) > 0 else 0, fdb.kpool(nd.kind),
        0 if nd.kind in STRUCT_KINDS else 1, 1 if nd.kind == "LITERAL" else 0, nd.start, random.random()))


def _mutate1(pat, fdb, rm, trials=50, k=1, ci=-1, iu=None, ku=None):
    try: bn = parse_nodes(pat)
    except: return pat, []
    if not bn or not fdb.items or k <= 0: return pat, []
    iu = iu or Counter(); ku = ku or Counter()
    cands = [nd for nd in bn if nd.kind != "LITERAL"]
    if not cands: return pat, []
    for _ in range(trials):
        nds = _kpri(cands[:], fdb, ku)
        pk = []; prs = []; ops = []; uk = set(); ut = set(); av = {}
        for nd in [n for n in nds if n.kind in STRUCT_KINDS]:
            if any(not (nd.end <= p.start or nd.start >= p.end) for p in pk): continue
            a = av.setdefault(nd.kind, set())
            r = fdb.pick(nd.kind, avoid=(ut | a), ci=ci, iu=iu)
            if not r or r == nd.text: continue
            pk.append(nd); prs.append((nd, r))
            ops.append({"op": OP_FRAGMENT, "to_kind": nd.kind, "to_text": r, "from_kind": nd.kind, "from_text": nd.text})
            fdb.record_use(nd.kind, r, ci); iu[(nd.kind, r)] += 1; ku[nd.kind] += 1
            uk.add(nd.kind); ut.add(r); a.add(r); break
        for pn in (1, 2):
            for nd in nds:
                if len(pk) >= k: break
                if any(not (nd.end <= p.start or nd.start >= p.end) for p in pk): continue
                if pn == 1 and nd.kind in uk: continue
                a = av.setdefault(nd.kind, set())
                r = fdb.pick(nd.kind, avoid=(ut | a), ci=ci, iu=iu)
                if not r or r == nd.text: continue
                pk.append(nd); prs.append((nd, r))
                ops.append({"op": OP_FRAGMENT, "to_kind": nd.kind, "to_text": r, "from_kind": nd.kind, "from_text": nd.text})
                fdb.record_use(nd.kind, r, ci); iu[(nd.kind, r)] += 1; ku[nd.kind] += 1
                uk.add(nd.kind); ut.add(r); a.add(r)
            if len(pk) >= k: break
        if not prs: continue
        prs.sort(key=lambda t: t[0].start)
        o = []; last = 0
        for nd, r in prs: o.append(pat[last:nd.start]); o.append(r); last = nd.end
        o.append(pat[last:]); mut = ''.join(o)
        if not _grep_ok(mut, rm):
            for nd, r in prs: fdb.record_fail(nd.kind, r)
            continue
        return mut, ops
    return pat, []


def _compute_k(par, fr):
    try: nds = parse_nodes(par)
    except: return 0
    m = _cnt_nl(nds)
    return min(max(0, int(math.ceil(m * float(fr)))), m) if m > 0 else 0


def _mut_cands(base, fdb, rm, fr, ci, trials, iu, ku):
    try: nds = parse_nodes(base)
    except: return [], []
    uk = _uniq_nlk(nds); k = _compute_k(base, fr)
    if k <= 0: return [], []
    cn = 1 + k + len(uk); muts = []; opsall = []
    for _ in range(max(1, cn)):
        m, ops = _mutate1(base, fdb, rm, trials=trials, k=k, ci=ci, iu=iu, ku=ku)
        muts.append(m); opsall.append(ops)
    return muts, opsall


def _pred_quality(ops, fdb):
    vals = []
    for op in (ops or []):
        if not isinstance(op, dict) or op.get("op") != OP_FRAGMENT: continue
        it = fdb.items.get((op.get("to_kind"), op.get("to_text")))
        if not it: continue
        n = max(0, int(it.stat.n))
        vals.append((it.stat.reward_sum / n) if n > 0 else 0.0)
    return sum(vals) / len(vals) if vals else 0.0


def _frag_eff(ops):
    st = ops.get(OP_FRAGMENT, {"tries": 0, "success": 0})
    t = int(st.get("tries", 0))
    return float(st.get("success", 0)) / max(1, t) if t > 0 else 1.0


def _build_rgx_profile(pgm, rm):
    p = {"mode": rm, "slots": {"char": 30, "class": 20, "alt": 8, "anchor": 12, "boundary": 10, "lookaround": 0, "backref": 0},
         "char_dist": [5, 5, 40, 40, 10], "class_dist": [50, 40, 10], "rep_dist": [10, 20, 20, 50],
         "knobs": {"max_group_depth": 3, "posix_class_max": 8, "word_boundary_limit": 4, "alt_max": 6, "no_cap_dotstar": True},
         "allow": {"literal_meta": True, "fixed_count": True, "open_count": True, "bare_alt": True, "composite_class": True, "pcre_backref": False},
         "prefer_tokens": [], "avoid_tokens": []}
    if pgm in ("expr", "csplit", "nl") and rm == "bre":
        p["prefer_tokens"] += [r"\<", r"\>"]
    return p


def _build_sym(pgm, rx, sf, flag="", sf2="", prof=None, rm="ere"):
    if prof is None: prof = {}
    sl = prof.get("uses_slash_wrap", False) or pgm in _MANUAL_SLASH_WRAP
    du = prof.get("needs_dual_src", False) or pgm in _MANUAL_DUAL_SRC
    px = prof.get("regex_prefix", ""); od = prof.get("arg_order", "regex_first")
    sp = prof.get("special_syntax")
    sep_flags = prof.get("separator_flags", []); sep_val = prof.get("separator_value_flag", "")
    san = _sanitize(pgm, rx, rm) or rx.strip()
    q = _esq(san); qs = _esl(q); wr = f"/{qs}/"; qp = f"{px}{q}" if px else q
    s1 = sf or ""; s2 = sf2 or s1
    regex_token = f"'{wr}'" if sl else f"'{qp}'"


    fp_parts = []
    for s in sep_flags:
        sc = s.strip()
        if sc and sc != sep_val and sc not in fp_parts: fp_parts.append(sc)
    fp = " ".join(fp_parts)
    fp = f"{fp} " if fp else ""


    ef = flag.strip() if flag else ""
    regex_part = f"{ef} {regex_token}" if ef else regex_token

    if sp == "string_colon_regex":
        t = _rnd_txt().replace('"', '\\"')
        return f'{fp}"{t}" : \'{qp}\''.strip()
    if du: return f"{fp}{regex_part} {s1} {s2}".strip()
    if od == "file_first": return f"{s1} {fp}{regex_part}".strip()
    if od == "no_file": return f"{fp}{regex_part}".strip()
    return f"{fp}{regex_part} {s1}".strip()


def _gen_rx(n, mode, outf, rbin="regexgen", profile_path=None):
    Path(outf).parent.mkdir(parents=True, exist_ok=True)
    cmd = [rbin, "-c", str(n), "--mode", mode, "-f", str(outf)]
    if profile_path: cmd += ["--profile", str(profile_path)]
    _run(cmd, check=True)


def _load_rxseq(ssp):
    if not ssp: return None
    p = Path(ssp)
    if not p.exists(): return None
    try: raw = json.loads(p.read_text(encoding='utf-8'))
    except: return None
    sp = raw.get('space') if isinstance(raw, dict) else None
    c = None
    if isinstance(sp, dict): c = sp.get('-regex-options') or sp.get('regex-options')
    elif isinstance(raw, dict): c = raw.get('-regex-options') or raw.get('regex-options')
    if c is None: return None
    if isinstance(c, list):
        sq = c[0] if c and isinstance(c[0], list) else c
        sq = [str(x).strip() for x in sq if str(x).strip()]
        return sq if sq else None
    return [c.strip()] if isinstance(c, str) and c.strip() else None

__all__ = ['_depth_ok', '_cap_ds', '_strip_mid', '_pcre_only', '_rm_wb', '_ere2bre', '_bre2ere', '_too_complex', '_sanitize', '_grep_ok', '_wide_fragment_boost', '_collect_group_count', '_balanced_groups_bug', '_mirror_tail_insert', 'mutate_once_bug_exploit', 'mutate_once_bug_explore', 'FragStat', 'FragItem', 'RNode', '_norm_sig', '_resc', '_rcc', '_rgrp', '_rq', '_mq', 'parse_nodes', '_cnt_nl', '_uniq_nlk', 'FragmentDB', '_kpri', '_mutate1', '_compute_k', '_mut_cands', '_pred_quality', '_frag_eff', '_build_rgx_profile', '_build_sym', '_gen_rx', '_load_rxseq']