#!/usr/bin/env python3
import os, re, sys, json, time, math, random, uuid, hashlib, pickle, shutil
import subprocess
from subprocess import run
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple, Union
from collections import Counter
from dataclasses import dataclass, asdict
from compose_common import (_MANUAL_DUAL_SRC_PROGRAMS, _MANUAL_SLASH_WRAP_PROGRAMS,
    _escape_regex_delim_slash, _regex_compiles_with_grep, escape_single_quotes)
from sniffles.regex_generator import verify_bre_escapes

__all__ = [
    '_RE_LOOKAROUND',
    '_RE_PCRE_VERB',
    '_RE_WBOUND',
    '_RE_MID_ANCHORS',
    '_cap_dotstar',
    '_strip_mid_anchors',
    '_contains_pcre_only',
    '_remove_word_boundaries_posix_safe',
    '_ere_to_bre',
    '_bre_to_ere',
    '_sanitize_for_program',
    'RNode',
    '_QUANT_START',
    '_META_CHARS',
    '_BOUNDARY_SET',
    '_ESCAPE_CLASSES',
    '_QUANT_TOKEN_RE',
    '_read_escape',
    '_read_char_class',
    '_read_group',
    '_read_literal_run',
    '_read_quantifier',
    '_maybe_quant_range',
    '_top_level_alt_splits',
    '_append_alt_branches',
    '_emit_literal_slices',
    'parse_regex_nodes',
    'FragStat',
    'FragItem',
    '_jaccard_tokens',
    '_tokenize_regex_for_diversity',
    '_normalized_frag_signature',
    'ALL_KINDS',
    '_map_old_kind_to_new',
    'FragmentDB',
    'OP_FRAGMENT',
    'OP_RANDOM',
    'MUTATE_KIND_WEIGHTS',
    'TOOL_TIMEOUT_BASE_KINDS',
    '_kind_priority_order',
    '_count_nonliteral_nodes',
    '_unique_nonliteral_kinds',
    '_compute_k_for_parent',
    'mutate_once_fragment_multi',
    'mutate_candidates_for_parent',
    '_predict_mutant_quality',
    'generate_regexes',
    'generate_random_text',
    'build_sym_options_list'
]

_RE_LOOKAROUND   = re.compile(r'\(\?[:=!<]')

_RE_PCRE_VERB    = re.compile(r'\\[KR]')

_RE_WBOUND       = re.compile(r'(?:\\b|\\<|\\>)')

_RE_MID_ANCHORS  = re.compile(r'(?<!^)\^|\$(?!$)')

def _cap_dotstar(s: str) -> str:
    return s

def _strip_mid_anchors(s: str) -> str:
    return _RE_MID_ANCHORS.sub('', s)

def _contains_pcre_only(s: str) -> bool:
    return bool(_RE_LOOKAROUND.search(s) or _RE_PCRE_VERB.search(s))

def _remove_word_boundaries_posix_safe(s: str) -> str:
    return _RE_WBOUND.sub('', s)

def _ere_to_bre(pattern: str) -> str:
    out = []
    esc = False
    in_class = False
    for ch in pattern:
        if esc:
            out.append('\\' + ch)
            esc = False
            continue
        if ch == '\\':
            esc = True
            continue
        if in_class:
            out.append(ch)
            if ch == ']':
                in_class = False
            continue
        if ch == '[':
            in_class = True
            out.append(ch)
            continue
        if ch in '()|+?{}':
            out.append('\\' + ch)
        else:
            out.append(ch)
    if esc:
        out.append('\\')
    return ''.join(out)

def _bre_to_ere(pattern: str) -> str:
    out = []
    i = 0
    n = len(pattern)
    in_class = False
    while i < n:
        ch = pattern[i]
        if in_class:
            out.append(ch)
            if ch == ']':
                in_class = False
            i += 1
            continue
        if ch == '[':
            in_class = True
            out.append(ch)
            i += 1
            continue
        if ch == '\\' and i + 1 < n:
            nx = pattern[i+1]
            if nx in '()|+?{}':
                out.append(nx)
                i += 2
                continue
            out.append(ch)
            out.append(nx)
            i += 2
            continue
        out.append(ch)
        i += 1
    return ''.join(out)

def _sanitize_for_program(pgm: str, pattern: str, regex_mode: str) -> Optional[str]:
    if regex_mode not in ("bre", "ere"):
        return None

    s = (pattern or "").strip()
    if not s:
        return None

    if _contains_pcre_only(s):
        return None

    s = _cap_dotstar(s)
    s = _strip_mid_anchors(s)
    s = _remove_word_boundaries_posix_safe(s)

    if regex_mode == "ere":
        s = _bre_to_ere(s)

    elif regex_mode == "bre":
        s = _ere_to_bre(s)
        try:
            if verify_bre_escapes(s):
                return None
        except Exception:
            return None

    body = s.strip()
    if not body or body in ('^', '$', '^$'):
        return None

    return body

@dataclass
class RNode:
    kind: str
    start: int
    end: int
    text: str

_QUANT_START = set(['*', '+', '?', '{'])

_META_CHARS = set(r"\.^$|?*+()[]{}")

_BOUNDARY_SET = {r'\b', r'\<', r'\>'}

_ESCAPE_CLASSES = {r'\d', r'\s', r'\w', r'\D', r'\S', r'\W'}

_QUANT_TOKEN_RE = re.compile(r'(?:\?|\*|\+|\{[0-9]+(?:,[0-9]*)?\})')

def _read_escape(pat: str, i: int) -> int:
    n = len(pat)
    if i >= n or pat[i] != '\\':
        return i + 1
    i += 1
    if i >= n:
        return i
    ch = pat[i]
    if ch in ('p', 'P') and i + 1 < n and pat[i+1] == '{':
        j = i + 2; depth = 1
        while j < n and depth > 0:
            if pat[j] == '{': depth += 1
            elif pat[j] == '}': depth -= 1
            j += 1
        return j
    return i + 1

def _read_char_class(pat: str, i: int) -> Tuple[int, bool]:
    n = len(pat)
    assert pat[i] == '['
    i += 1
    closed = False
    while i < n:
        if pat[i] == '\\':
            i = _read_escape(pat, i)
            continue
        if pat[i] == ']':
            i += 1
            closed = True
            break
        i += 1
    return i, closed

def _read_group(pat: str, i: int) -> int:
    n = len(pat); assert pat[i] == '('
    i += 1; depth = 1
    while i < n and depth > 0:
        ch = pat[i]
        if ch == '\\':
            i = _read_escape(pat, i); continue
        if ch == '[':
            i, _ = _read_char_class(pat, i); continue
        if ch == '(':
            depth += 1; i += 1; continue
        if ch == ')':
            depth -= 1; i += 1
            if depth == 0: break
            continue
        i += 1
    return i

def _read_literal_run(pat: str, i: int) -> int:
    n = len(pat)
    j = i
    while j < n:
        cj = pat[j]
        if cj == '\\' or cj in _META_CHARS:
            break
        j += 1
    return max(j, i + 1)

def _read_quantifier(pat: str, i: int) -> int:
    n = len(pat)
    if i >= n: return i
    m = _QUANT_TOKEN_RE.match(pat[i:])
    if not m: return i
    return i + m.end()

def _maybe_quant_range(pat: str, pos: int) -> Optional[Tuple[int,int]]:
    if pos < len(pat) and pat[pos] in _QUANT_START:
        end = _read_quantifier(pat, pos)
        if end > pos:
            return (pos, end)
    return None

def _top_level_alt_splits(pat: str, start: int, end: int) -> List[Tuple[int, int]]:
    spans = []
    depth = 0; i = start; seg = start; in_class = False; esc = False
    while i < end:
        ch = pat[i]
        if esc:
            esc = False; i += 1; continue
        if ch == '\\':
            esc = True; i += 1; continue
        if in_class:
            if ch == ']': in_class = False
            i += 1; continue
        if ch == '[':
            in_class = True; i += 1; continue
        if ch == '(':
            depth += 1; i += 1; continue
        if ch == ')':
            depth = max(0, depth-1); i += 1; continue
        if ch == '|' and depth == 0:
            spans.append((seg, i))
            seg = i + 1
            i += 1; continue
        i += 1
    spans.append((seg, end))
    return spans

def _append_alt_branches(pattern: str, start: int, end: int, nodes: List[RNode]):
    spans = _top_level_alt_splits(pattern, start, end)
    if len(spans) >= 2:
        for a, b in spans:
            if a < b:
                nodes.append(RNode("ALT_BRANCH", a, b, pattern[a:b]))

def _emit_literal_slices(pat: str, start: int, end: int, nodes: List[RNode], max_slice: int = 4):
    i = start
    while i < end:
        j = min(end, i + max_slice)
        nodes.append(RNode("LITERAL", i, j, pat[i:j]))
        i = j

def parse_regex_nodes(pattern: str) -> List[RNode]:
    n = len(pattern); nodes: List[RNode] = []
    i = 0
    while i < n:
        ch = pattern[i]

        if ch == '\\':
            esc_end = _read_escape(pattern, i)
            tok = pattern[i:esc_end]
            if tok in _BOUNDARY_SET:
                nodes.append(RNode("BOUNDARY", i, esc_end, tok))
                i = esc_end; continue
            if tok in _ESCAPE_CLASSES:
                q = _maybe_quant_range(pattern, esc_end)
                nodes.append(RNode("ESCAPE", i, esc_end, pattern[i:esc_end]))
                if q:
                    qs, qe = q
                    nodes.append(RNode("QUANT", qs, qe, pattern[qs:qe]))
                    i = qe; continue
                i = esc_end; continue
            if len(tok) == 2 and tok[0] == '\\' and tok[1] in '123456789':
                q = _maybe_quant_range(pattern, esc_end)
                nodes.append(RNode("BACKREF", i, esc_end, tok))
                if q:
                    qs, qe = q
                    nodes.append(RNode("QUANT", qs, qe, pattern[qs:qe]))
                    i = qe; continue
                i = esc_end; continue

            nodes.append(RNode("ESCAPED", i, esc_end, pattern[i:esc_end]))
            q = _maybe_quant_range(pattern, esc_end)
            if q:
                qs, qe = q
                nodes.append(RNode("QUANT", qs, qe, pattern[qs:qe]))
                i = qe; continue
            i = esc_end; continue

        if ch == '[':
            cc_end, closed = _read_char_class(pattern, i)
            if closed:
                nodes.append(RNode("CLASS", i, cc_end, pattern[i:cc_end]))
                q = _maybe_quant_range(pattern, cc_end)
                if q:
                    qs, qe = q
                    nodes.append(RNode("QUANT", qs, qe, pattern[qs:qe]))
                    i = qe; continue
                i = cc_end; continue
            else:
                nodes.append(RNode("LITERAL", i, i+1, ch))
                i += 1; continue

        if ch == '(':
            g_end = _read_group(pattern, i)
            nodes.append(RNode("GROUP", i, g_end, pattern[i:g_end]))
            q = _maybe_quant_range(pattern, g_end)
            if q:
                qs, qe = q
                nodes.append(RNode("QUANT", qs, qe, pattern[qs:qe]))
                i = qe; continue
            i = g_end; continue

        if ch in _QUANT_START:
            end = _read_quantifier(pattern, i)
            if end > i:
                nodes.append(RNode("QUANT", i, end, pattern[i:end]))
                i = end; continue

        if ch == '|':
            nodes.append(RNode("ALT", i, i+1, ch))
            i += 1; continue

        if ch in ('^', '$'):
            nodes.append(RNode("ANCHOR", i, i+1, ch))
            i += 1; continue

        j = _read_literal_run(pattern, i)
        _emit_literal_slices(pattern, i, j, nodes)
        i = j

    _append_alt_branches(pattern, 0, len(pattern), nodes)
    return nodes

@dataclass
class FragStat:
    n: int = 0
    reward_sum: float = 0.0
    success: int = 0
    fail_compile: int = 0
    last_used_iter: int = -1
    ewma: float = 0.0  

@dataclass
class FragItem:
    kind: str
    text: str
    stat: FragStat

def _jaccard_tokens(a: Set[str], b: Set[str]) -> float:
    if not a and not b: return 1.0
    if not a or not b: return 0.0
    inter = len(a & b)
    uni = len(a | b)
    return inter / uni if uni else 0.0

def _tokenize_regex_for_diversity(rx: str) -> Set[str]:
    toks = re.findall(r"\\.|\[:[a-z]+:\]|\w+|\W", rx)
    return {t for t in toks if t.strip()}

def _normalized_frag_signature(kind: str, text: str) -> str:
    t = re.sub(r"\s+", "", text)

    t = re.sub(r"\.\{0,\d+\}", ".{0,N}", t)
    t = re.sub(r"\.\{1,\d+\}", ".{1,N}", t)

    t = re.sub(r"\{0,\d+\}", "{0,N}", t)
    t = re.sub(r"\{1,\d+\}", "{1,N}", t)
    t = re.sub(r"\{\d+\}", "{K}", t)
    t = re.sub(r"\{\d+,\}", "{K,}", t)
    t = re.sub(r"\{\d+,\d+\}", "{K,M}", t)

    if kind == "LITERAL":
        t = re.sub(r"[A-Za-z0-9]{3,}", "AAA", t)

    return f"{kind}:{t}"

ALL_KINDS = {
    "GROUP", "ALT_BRANCH", "CLASS", "WILDCARD", "ANCHOR",
    "BOUNDARY", "ESCAPE", "LITERAL", "QUANT", "BACKREF"
}

def _map_old_kind_to_new(kind: str, text: str) -> Optional[str]:
    if not kind:
        return None
    k = str(kind).strip()

    # already current
    if k in ALL_KINDS:
        return k

    t = (text or "")

    if k in ("COLL_ELEM_SINGLE", "ORD_CHAR", "QUOTED_CHAR"):
        return "LITERAL"

    if k in ("COLL_ELEM_MULTI",):
        if t.startswith("[") and t.endswith("]"):
            return "CLASS"
        if t.startswith("(") and t.endswith(")"):
            return "GROUP"
        if "|" in t:
            return "ALT_BRANCH"
        return "GROUP"

    if k in ("DUP_COUNT",):
        return "QUANT"

    if k in ("META_CHAR", "SPEC_CHAR"):
        if t in ("^", "$"):
            return "ANCHOR"
        if t == ".":
            return "WILDCARD"
        if t in ("*", "+", "?") or t.strip().startswith("{"):
            return "QUANT"
        return "LITERAL"

    if k in ("L_ANCHOR", "R_ANCHOR"):
        return "ANCHOR"

    if k in ("CHARCLASS",):
        return "CLASS"

    if k in ("WILDCARD", "DOT"):
        return "WILDCARD"

    if k in ("ANCHOR",):
        return "ANCHOR"

    if k in ("BOUNDARY",):
        return "BOUNDARY"

    if k in ("ESCAPE",):
        return "ESCAPE"

    if k in ("LITERAL",):
        return "LITERAL"

    if k in ("QUANT",):
        return "QUANT"

    if k in ("GROUP", "CLASS", "ALT_BRANCH"):
        return k

    return None

class FragmentDB:
    def __init__(self, path: Path):
        self.path = path
        self.items: Dict[Tuple[str, str], FragItem] = {}
        self.entries: List[Tuple[str, str, float]] = []
        self._load()
        self.purge_fail_compile_items()

    def purge_fail_compile_items(self) -> int:
        to_del = []
        for k, it in self.items.items():
            try:
                if int(getattr(it.stat, "fail_compile", 0)) > 0:
                    to_del.append(k)
            except Exception:
                continue
        for k in to_del:
            self.items.pop(k, None)
        return len(to_del)

    def _load(self):
        self.items = {}
        self.entries = []
        if not self.path.exists():
            return
        try:
            raw = pickle.load(open(self.path, "rb"))

            def _insert(kind: str, text: str, stat: Optional[FragStat] = None):
                nk = _map_old_kind_to_new(kind, text)
                if nk is None:
                    return
                if nk not in ALL_KINDS:
                    return
                key = (nk, text)
                if key not in self.items:
                    self.items[key] = FragItem(nk, text, stat or FragStat())

            if isinstance(raw, dict) and "items" in raw and "entries" in raw:
                items_dict = raw.get("items", {}) or {}
                for k, v in items_dict.items():
                    try:
                        if isinstance(k, tuple) and len(k) == 2:
                            kk, tt = k
                        else:
                            continue
                        if isinstance(v, FragItem):
                            _insert(v.kind, v.text, v.stat if isinstance(v.stat, FragStat) else FragStat())
                        elif isinstance(v, dict):
                            kind = v.get("kind", kk)
                            text = v.get("text", tt)
                            stat_in = v.get("stat", {}) if isinstance(v.get("stat", {}), dict) else {}
                            stat = FragStat(**{**FragStat().__dict__, **stat_in})
                            _insert(kind, text, stat)
                        else:
                            _insert(kk, tt, FragStat())
                    except Exception:
                        continue
                ents_in = raw.get("entries", []) or []
                for trip in ents_in:
                    try:
                        k_, t_, s_ = trip
                        self.entries.append((str(k_), str(t_), float(s_)))
                    except Exception:
                        continue

            elif isinstance(raw, list):
                for it in raw:
                    try:
                        k, t = it
                        _insert(k, t, FragStat())
                    except Exception:
                        continue

            elif isinstance(raw, dict):
                for k, v in raw.items():
                    try:
                        if isinstance(k, tuple) and len(k) == 2:
                            kk, tt = k
                        else:
                            continue

                        if isinstance(v, FragItem):
                            _insert(v.kind, v.text, v.stat if isinstance(v.stat, FragStat) else FragStat())
                        elif isinstance(v, dict):
                            kind = v.get("kind", kk)
                            text = v.get("text", tt)
                            stat_in = v.get("stat", {}) if isinstance(v.get("stat", {}), dict) else {}
                            stat = FragStat(**{**FragStat().__dict__, **stat_in})
                            _insert(kind, text, stat)
                        elif isinstance(v, tuple):
                            _insert(kk, tt, FragStat())
                        else:
                            _insert(kk, tt, FragStat())
                    except Exception:
                        continue
            else:
                self.items = {}

        except Exception:
            self.items = {}
            self.entries = []

    def save(self):
        self.purge_fail_compile_items()

        serial = {}
        for (k, t), v in self.items.items():
            serial[(k, t)] = {
                "kind": v.kind,
                "text": v.text,
                "stat": asdict(v.stat)
            }
        pickle.dump({"items": serial, "entries": list(self.entries)},
                    open(self.path, "wb"))

    def _existing_norm_signatures(self) -> Set[str]:
        sigs = set()
        for (k, t) in self.items.keys():
            sigs.add(_normalized_frag_signature(k, t))
        return sigs

    def add_from_patterns(self, patterns: List[str]):
        seen_keys = set(self.items.keys())
        seen_norm = self._existing_norm_signatures()
        for p in patterns:
            try:
                for nd in parse_regex_nodes(p):
                    sig = _normalized_frag_signature(nd.kind, nd.text)
                    if sig in seen_norm:
                        continue
                    key = (nd.kind, nd.text)
                    if key not in seen_keys:
                        self.items[key] = FragItem(nd.kind, nd.text, FragStat())
                        seen_keys.add(key)
                        seen_norm.add(sig)
            except Exception:
                continue

        self.purge_fail_compile_items()


    def record_use(self, kind: str, text: str, iteration: int):
        it = self.items.get((kind, text))
        if it:
            it.stat.n += 1
            it.stat.last_used_iter = iteration

    def record_reward(self, kind: str, text: str, reward: float):
        self.entries.append((kind, text, float(reward)))
        it = self.items.get((kind, text))
        if it:
            it.stat.reward_sum += float(reward)
            if reward > 0:
                it.stat.success += 1
            n = max(1, it.stat.n)
            it.stat.ewma = it.stat.reward_sum / n

    def record_fail_compile(self, kind: str, text: str):
        it = self.items.get((kind, text))
        if it:
            it.stat.fail_compile += 1
        self.items.pop((kind, text), None)

    def prune(self, cur_iter: int) -> int:
        if cur_iter < 0 or not self.items:
            return 0

        by_kind: Dict[str, List[FragItem]] = {k: [] for k in ALL_KINDS}
        for (_, _), it in self.items.items():
            by_kind.setdefault(it.kind, []).append(it)

        keep_keys: Set[Tuple[str, str]] = set()

        removed = 0
        for kind, items in by_kind.items():
            if not items:
                continue

            N = sum(max(0, int(it.stat.n)) for it in items)
            log_term = math.log(1.0 + max(0, N))

            scored: List[Tuple[float, Tuple[str, str]]] = []
            for it in items:
                n = max(0, int(it.stat.n))
                mean = (it.stat.reward_sum / n) if n > 0 else 0.0
                bonus = math.sqrt(log_term / (1.0 + n)) if log_term > 0 else 0.0
                score = mean + bonus
                scored.append((score, (it.kind, it.text)))

            scored.sort(key=lambda x: x[0], reverse=True)

            size = len(items)
            keep_k = max(50, int(0.2 * size))
            keep_k = min(keep_k, size)

            for _, key in scored[:keep_k]:
                keep_keys.add(key)

        to_del = []
        for key, it in self.items.items():
            if key in keep_keys:
                continue

            n = max(0, int(getattr(it.stat, "n", 0)))
            rs = float(getattr(it.stat, "reward_sum", 0.0))

            if n > 0 and rs == 0.0:
                to_del.append(key)


        for k in to_del:
            self.items.pop(k, None)
            removed += 1

        return removed

    def pick_simple(self,
                    kind: str,
                    avoid_texts: Optional[Set[str]] = None,
                    cur_iter: int = -1,
                    iter_used: Optional[Counter] = None,
                    parent_regex: Optional[str] = None,
                    regex_mode: Optional[str] = None,
                    self_text: Optional[str] = None) -> Optional[str]:
        avoid_texts = set(avoid_texts) if avoid_texts else set()
        if self_text:
            avoid_texts.add(self_text)
        iter_used = iter_used or Counter()

        pool_all = [v for ((k, _), v) in self.items.items() if k == kind and v.text not in avoid_texts]
        if not pool_all:
            return None

        pool = [v for v in pool_all if int(getattr(v.stat, "fail_compile", 0)) == 0]
        if not pool:
            return None

        pool2 = [v for v in pool if iter_used[(kind, v.text)] == 0]
        if pool2:
            pool = pool2

        N = sum(max(0, v.stat.n) for v in pool)
        log_term = math.log(1.0 + max(0, N))

        weights: List[float] = []
        for v in pool:
            n = max(0, int(v.stat.n))
            mean = (v.stat.reward_sum / n) if n > 0 else 0.0
            bonus = math.sqrt(log_term / (1.0 + n)) if log_term > 0 else 0.0
            ucb = mean + bonus
            weights.append(max(0.0, ucb) + 1e-9)

        try:
            chosen = random.choices(pool, weights=weights, k=1)[0]
        except Exception:
            chosen = random.choice(pool)
        return chosen.text

    def export_preview(self, out_path: Path, limit: int = 300):
        try:
            with open(out_path, "w", encoding="utf-8") as f:
                f.write("kind\ttext\tn\treward_sum\tsuccess\tewma\tfail_compile\tlast_used_iter\n")
                i = 0
                for (_, _), v in self.items.items():
                    if i >= limit: break
                    s = v.stat
                    f.write(f"{v.kind}\t{v.text}\t{s.n}\t{s.reward_sum:.4f}\t{s.success}\t{s.ewma:.4f}\t{s.fail_compile}\t{s.last_used_iter}\n")
                    i += 1
        except Exception:
            pass

OP_FRAGMENT = "fragment_replace"

OP_RANDOM   = "random_regex"   

MUTATE_KIND_WEIGHTS = {
    "BACKREF": 60, "GROUP": 60, "WILDCARD": 60, "QUANT": 60,
    "LITERAL": 0,
    "ESCAPE": 0, "BOUNDARY": 0, 
}

TOOL_TIMEOUT_BASE_KINDS: Dict[str, List[str]] = {
    "grep": ["CLASS","BACKREF","GROUP","WILDCARD","QUANT","ALT_BRANCH","REDOS_AMBIG","ESCAPE","BACKREF","QUANT","ALT_BRANCH","WILDCARD"],
    "sed": ["CLASS","BACKREF","GROUP","WILDCARD","QUANT","ALT_BRANCH","REDOS_AMBIG","ESCAPE","GROUP","BACKREF","WILDCARD","QUANT","ALT_BRANCH"],
    "gawk": ["CLASS","BACKREF","GROUP","WILDCARD","QUANT","ALT_BRANCH","REDOS_AMBIG","ESCAPE","GROUP","BACKREF","WILDCARD","QUANT","ALT_BRANCH"],
}

def _kind_priority_order(nodes: List[RNode],
                         fdb: FragmentDB,
                         kind_recent_used: Counter) -> List[RNode]:
    """
    Weighted-random ordering:
    - Each node's effective weight = MUTATE_KIND_WEIGHTS[kind] * uniform(0,1)
    - Higher weight kinds (BACKREF/GROUP/WILDCARD/QUANT) tend to come first
    - LITERAL has weight 0 → effectively excluded
    - fdb / kind_recent_used kept in signature for caller compatibility (unused)
    """
    del fdb, kind_recent_used 
    def key(nd: RNode):
        w = MUTATE_KIND_WEIGHTS.get(nd.kind, 40)
        return -(w * random.random())
    return sorted(nodes, key=key)

def _count_nonliteral_nodes(nodes: List[RNode]) -> int:
    return sum(1 for nd in nodes if nd.kind != "LITERAL")

def _unique_nonliteral_kinds(nodes: List[RNode]) -> Set[str]:
    return {nd.kind for nd in nodes if nd.kind != "LITERAL"}

def _compute_k_for_parent(parent_regex: str, frag_ratio: float) -> int:
    try:
        nodes = parse_regex_nodes(parent_regex)
    except Exception:
        return 0
    m = _count_nonliteral_nodes(nodes)
    if m <= 0:
        return 0
    k = int(math.floor(m * float(frag_ratio)))
    if k <= 0:
        return 0
    return min(k, m)

def mutate_once_fragment_multi(pattern: str,
                               fdb: FragmentDB,
                               regex_mode: str,
                               max_trials: int = 50,
                               k: int = 1,
                               current_iteration: int = -1,
                               iter_used_counter: Optional[Counter] = None,
                               kind_used_counter: Optional[Counter] = None) -> Tuple[str, List[dict]]:
    try:
        base_nodes = parse_regex_nodes(pattern)
    except Exception:
        return pattern, []
    if not base_nodes or not fdb.items or k <= 0:
        return pattern, []

    iter_used_counter = iter_used_counter or Counter()
    kind_used_counter = kind_used_counter or Counter()

    candidate_nodes = [nd for nd in base_nodes if nd.kind != "LITERAL"]
    if not candidate_nodes:
        return pattern, []

    trials = 0
    while trials < max_trials:
        trials += 1

        nodes = _kind_priority_order(candidate_nodes[:], fdb, kind_recent_used=kind_used_counter)

        picked: List[RNode] = []
        used_pairs: List[Tuple[RNode, str]] = []
        used_ops: List[dict] = []

        used_kinds: Set[str] = set()
        used_texts: Set[str] = set()
        avoid_by_kind: Dict[str, Set[str]] = {}
        for pass_no in (1, 2):
            for nd in nodes:
                if len(picked) >= k:
                    break
                if any(not (nd.end <= p.start or nd.start >= p.end) for p in picked):
                    continue

                if pass_no == 1 and nd.kind in used_kinds:
                    continue

                avoid_kind = avoid_by_kind.setdefault(nd.kind, set())
                repl = fdb.pick_simple(
                    nd.kind,
                    avoid_texts=(used_texts | avoid_kind),
                    cur_iter=current_iteration,
                    iter_used=iter_used_counter,
                    parent_regex=pattern,
                    regex_mode=regex_mode,
                    self_text=nd.text
                )
                if not repl or repl == nd.text:
                    continue

                picked.append(nd)
                used_pairs.append((nd, repl))
                used_ops.append({
                    "op": OP_FRAGMENT,
                    "to_kind": nd.kind,
                    "to_text": repl,
                    "from_kind": nd.kind,
                    "from_text": nd.text,
                })

                fdb.record_use(nd.kind, repl, current_iteration)
                iter_used_counter[(nd.kind, repl)] += 1
                kind_used_counter[nd.kind] += 1
                used_kinds.add(nd.kind)
                used_texts.add(repl)
                avoid_kind.add(repl)

            if len(picked) >= k:
                break

        if not used_pairs:
            continue

        used_pairs.sort(key=lambda t: t[0].start)
        out = []
        last = 0
        for nd, repl in used_pairs:
            out.append(pattern[last:nd.start])
            out.append(repl)
            last = nd.end
        out.append(pattern[last:])
        mutated = ''.join(out)

        if not _regex_compiles_with_grep(mutated, regex_mode):
            for nd, repl in used_pairs:
                fdb.record_fail_compile(nd.kind, repl)
            continue

        return mutated, used_ops

    return pattern, []

def mutate_candidates_for_parent(base: str,
                                fdb: FragmentDB,
                                regex_mode: str,
                                frag_ratio: float,
                                current_iteration: int,
                                max_trials: int,
                                iter_used_counter: Counter,
                                kind_used_counter: Counter) -> Tuple[List[str], List[List[dict]]]:
    try:
        nodes = parse_regex_nodes(base)
    except Exception:
        return [], []

    uniq_kinds = _unique_nonliteral_kinds(nodes)
    k = _compute_k_for_parent(base, frag_ratio)
    if k <= 0:
        return [], []

    cand_n = 1 + k + len(uniq_kinds)

    muts: List[str] = []
    ops_all: List[List[dict]] = []

    for _ in range(max(1, cand_n)):
        m, ops = mutate_once_fragment_multi(
            base,
            fdb,
            regex_mode=regex_mode,
            max_trials=max_trials,
            k=k,
            current_iteration=current_iteration,
            iter_used_counter=iter_used_counter,
            kind_used_counter=kind_used_counter
        )
        muts.append(m)
        ops_all.append(ops)

    return muts, ops_all

def _predict_mutant_quality(ops_used: List[dict], fdb: FragmentDB) -> float:
    vals: List[float] = []
    for op in ops_used or []:
        if not isinstance(op, dict):
            continue
        if op.get("op") != OP_FRAGMENT:
            continue
        k = op.get("to_kind")
        t = op.get("to_text")
        if not k or not t:
            continue
        it = fdb.items.get((k, t))
        if not it:
            continue
        s = it.stat
        n = max(0, int(s.n))
        mean = (s.reward_sum / n) if n > 0 else 0.0
        vals.append(mean)
    if not vals:
        return 0.0
    return float(sum(vals) / len(vals))

def generate_regexes(n: int, mode: str, outfile: Path, profile_path: Optional[Path] = None):
    cmd = ["regexgen", "-c", str(n), "--mode", mode, "-f", str(outfile)]
    if profile_path: cmd += ["--profile", str(profile_path)]
    run(cmd, check=True)

def generate_random_text(length=8):
    import string
    chars = string.ascii_letters + string.digits + " _"
    return ''.join(random.choices(chars, k=length))

def build_sym_options_list(
    regexes,
    src_file,
    sym_args,
    pgm,
    regex_mode: str,
    profile_path: Optional[Path],
    extra_flag: Union[str, List[str]] = "",
    usage_profile: Optional[dict] = None
):
    import glob, shlex

    sym_list = []
    sanitization_marks: List[str] = []
    
    if usage_profile is None:
        usage_profile = {}
    needs_dual_src = usage_profile.get("needs_dual_src", False) or pgm in _MANUAL_DUAL_SRC_PROGRAMS
    uses_slash_wrap = usage_profile.get("uses_slash_wrap", False) or pgm in _MANUAL_SLASH_WRAP_PROGRAMS
    regex_prefix = usage_profile.get("regex_prefix", "")
    arg_order = usage_profile.get("arg_order", "regex_first")
    special_syntax = usage_profile.get("special_syntax")
    separator_flags = usage_profile.get("separator_flags", [])
    separator_value_flag = usage_profile.get("separator_value_flag", "")

    if isinstance(src_file, (list, tuple)):
        src_files = list(src_file)
    else:
        src_files = [src_file] * len(regexes)
    if not src_files:
        src_files = [""]

    src_pairs = []
    if needs_dual_src:
        for i in range(len(regexes)):
            idx1 = (i * 2) % len(src_files) if len(src_files) > 1 else 0
            idx2 = (i * 2 + 1) % len(src_files) if len(src_files) > 1 else 0
            src_pairs.append((src_files[idx1], src_files[idx2]))
    
    if isinstance(extra_flag, (list, tuple)):
        extra_flags = list(extra_flag)
    else:
        extra_flags = []
        
    for rgx in regexes:
        raw = rgx.strip()
        sanitized = _sanitize_for_program(pgm, raw, regex_mode)

        if sanitized is None:
            regen_ok = None
            tmp_path = Path("/tmp/.regexgen-one.txt")
            for _ in range(200):
                try:
                    generate_regexes(1, regex_mode, tmp_path, profile_path=profile_path)
                    cand = tmp_path.read_text(encoding="utf-8").strip()
                    s2 = _sanitize_for_program(pgm, cand, regex_mode)
                    if s2:
                        regen_ok = s2; break
                except Exception:
                    pass

            if regen_ok is None:
                while regen_ok is None:
                    try:
                        generate_regexes(1, regex_mode, tmp_path, profile_path=profile_path)
                        cand = tmp_path.read_text(encoding="utf-8").strip()
                        s2 = _sanitize_for_program(pgm, cand, regex_mode)
                        if s2:
                            regen_ok = s2
                    except Exception:
                        pass
                sanitization_marks.append("regexgen_retry")
            else:
                sanitization_marks.append("ok")
            sanitized = regen_ok
        elif sanitized != raw:
            sanitization_marks.append("sanitized")
        else:
            sanitization_marks.append("ok")

        q = escape_single_quotes(sanitized)
        q_for_slash = _escape_regex_delim_slash(q)
        wrapped = f"/{q_for_slash}/"
        idx = len(sym_list)
        
        if needs_dual_src and src_pairs:
            src_item1, src_item2 = src_pairs[idx % len(src_pairs)]
            src_item = src_item1
        else:
            src_item = src_files[idx % len(src_files)] if src_files else ""
            src_item1, src_item2 = src_item, ""
            
        if extra_flags:
            flag = extra_flags[idx % len(extra_flags)]
        else:
            flag = extra_flag

        q_with_prefix = f"{regex_prefix}{q}" if regex_prefix else q
        regex_token = f"'{wrapped}'" if uses_slash_wrap else f"'{q_with_prefix}'"

        flag_parts = []
        for sf in separator_flags:
            sf_clean = sf.strip()
            if sf_clean and sf_clean != separator_value_flag and sf_clean not in flag_parts:
                flag_parts.append(sf_clean)
        flag_prefix = " ".join(flag_parts)
        flag_prefix = f"{flag_prefix} " if flag_prefix else ""

        ef = str(flag).strip() if flag else ""
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
            sym_list.append(f"{flag_prefix}\"{esc_text}\" : '{q_with_prefix}' {sym_args}".strip())
        
        elif needs_dual_src:
            sym_list.append(f"{flag_prefix}{regex_part} {src_item1} {src_item2} {sym_args}".strip())
        
        elif arg_order == "file_first":
            sym_list.append(f"{src_item} {flag_prefix}{regex_part} {sym_args}".strip())
        
        elif arg_order == "no_file":
            sym_list.append(f"{flag_prefix}{regex_part} {sym_args}".strip())
        
        else:
            sym_list.append(f"{flag_prefix}{regex_part} {src_item} {sym_args}".strip())

    return sym_list, sanitization_marks
