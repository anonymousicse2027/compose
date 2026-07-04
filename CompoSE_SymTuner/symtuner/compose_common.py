from pathlib import Path
import os, re, json, math, random, string, pickle, subprocess, uuid, hashlib, shutil, sys
from typing import List, Optional, Any, Set, Tuple, Dict, Union
from collections import Counter
from dataclasses import dataclass, asdict, field
from difflib import SequenceMatcher
from subprocess import run as _run, PIPE, STDOUT
from symtuner.logger import get_logger


SAMPLE_REGEX = "[a-z]"


REWARD_CLAMP_MAX = None


_MANUAL_SLASH_WRAP = {"csplit", "gawk", "sed"}


_MANUAL_DUAL_SRC = {"diff"}


_RX_KW = [r'\bregex\b', r'\bregexp\b', r'\bregular\s+expression', r'\bpattern\b',
           r'\bBRE\b', r'\bERE\b', r'\bextended.*regular', r'\bbasic.*regular',
           r'\bperl.*regexp', r'\bposix.*regular']


_RX_KW_RE = re.compile('|'.join(_RX_KW), re.IGNORECASE)


_FILE_KW = ['FILE', 'PATH', 'INPUT', 'DIR', 'SOURCE']


_PAT_KW = ['PATTERN', 'REGEXP', 'REGEX', 'EXPRESSION', 'BRE', 'ERE']


_DISALLOWED = {"--debug"}


OP_FRAGMENT = "fragment_replace"


OP_MIRROR_TAIL = "mirror_tail"


STRUCT_KINDS = {"GROUP", "ALT_BRANCH", "CLASS", "ANCHOR", "BOUNDARY"}


ALL_KINDS = {"GROUP", "ALT_BRANCH", "CLASS", "WILDCARD", "ANCHOR", "BOUNDARY", "ESCAPE", "LITERAL", "QUANT"}


W_SLOW = 0.5; W_MEM = 0.5; PERF_NORM_THRESH = 0.8


W_SLOW = 0.5; W_MEM = 0.5; PERF_NORM_THRESH = 0.8


W_SLOW = 0.5; W_MEM = 0.5; PERF_NORM_THRESH = 0.8


BUG_BONUS_CRASH = 50.0; BUG_BONUS_PERF = 1.0


BUG_BONUS_CRASH = 50.0; BUG_BONUS_PERF = 1.0


MUTATE_SKIP_KINDS_BUG = {"LITERAL", "ESCAPE", "BOUNDARY"}


MUTATE_KIND_PRIORITY_BUG = {"BACKREF":5,"BACKREF_SEQ":4,"GROUP":4,"WILDCARD":3,"QUANT":3,"CLASS":2,"ALT_BRANCH":2,"ESCAPE":1,"ANCHOR":0}


MUTATE_KIND_WEIGHTS = {"BACKREF":60,"GROUP":60,"WILDCARD":60,"QUANT":60,"LITERAL":0,
                       "ESCAPE":0,"BOUNDARY":0}


TOOL_TIMEOUT_BASE_KINDS: Dict[str, List[str]] = {
    "grep": ["CLASS","BACKREF","GROUP","WILDCARD","QUANT","ALT_BRANCH","REDOS_AMBIG","ESCAPE","BACKREF","QUANT","ALT_BRANCH","WILDCARD"],
    "sed": ["CLASS","BACKREF","GROUP","WILDCARD","QUANT","ALT_BRANCH","REDOS_AMBIG","ESCAPE","GROUP","BACKREF","WILDCARD","QUANT","ALT_BRANCH"],
    "gawk": ["CLASS","BACKREF","GROUP","WILDCARD","QUANT","ALT_BRANCH","REDOS_AMBIG","ESCAPE","GROUP","BACKREF","WILDCARD","QUANT","ALT_BRANCH"],
}


_MAX_LEN = 600; _MAX_LEN_TAC_NL = 360; _MAX_LEN_EXPR_CSPLIT = 420


_MAX_LEN = 600; _MAX_LEN_TAC_NL = 360; _MAX_LEN_EXPR_CSPLIT = 420


_MAX_LEN = 600; _MAX_LEN_TAC_NL = 360; _MAX_LEN_EXPR_CSPLIT = 420


_MAX_POSIX = 8; _MAX_WB = 2; _MAX_ALT = 6; _MAX_DEPTH = 3; _DOTSTAR_CAP = 12


_MAX_POSIX = 8; _MAX_WB = 2; _MAX_ALT = 6; _MAX_DEPTH = 3; _DOTSTAR_CAP = 12


_MAX_POSIX = 8; _MAX_WB = 2; _MAX_ALT = 6; _MAX_DEPTH = 3; _DOTSTAR_CAP = 12


_MAX_POSIX = 8; _MAX_WB = 2; _MAX_ALT = 6; _MAX_DEPTH = 3; _DOTSTAR_CAP = 12


_MAX_POSIX = 8; _MAX_WB = 2; _MAX_ALT = 6; _MAX_DEPTH = 3; _DOTSTAR_CAP = 12


_RE_LOOK = re.compile(r'\(\?[:=!<]'); _RE_PCRE = re.compile(r'\\[KR]')


_RE_LOOK = re.compile(r'\(\?[:=!<]'); _RE_PCRE = re.compile(r'\\[KR]')


_RE_BREF = re.compile(r'(?<!\\)(?:\\\\)*\\[1-9]')


_RE_POSIX = re.compile(r'\[:[a-z]+:\]'); _RE_WB = re.compile(r'(?:\\b|\\<|\\>)')


_RE_POSIX = re.compile(r'\[:[a-z]+:\]'); _RE_WB = re.compile(r'(?:\\b|\\<|\\>)')


_RE_ALT = re.compile(r'(?<!\\)\|'); _RE_NQ = re.compile(r'(?:\([^\)]*\)[*+]){2,}')


_RE_ALT = re.compile(r'(?<!\\)\|'); _RE_NQ = re.compile(r'(?:\([^\)]*\)[*+]){2,}')


_RE_MID = re.compile(r'(?<!^)\^|\$(?!$)'); _RE_CTRL = re.compile(r'\\x[0-9a-fA-F]{2}|\\[0-7]{1,3}')


_RE_MID = re.compile(r'(?<!^)\^|\$(?!$)'); _RE_CTRL = re.compile(r'\\x[0-9a-fA-F]{2}|\\[0-7]{1,3}')


_PROF_CACHE: Dict[str, dict] = {}


def _esq(s): return s.replace("'", "'\"'\"'")


def _esl(p): return p.replace('/', r'\/')


def _rnd_txt(n=8): return ''.join(random.choices(string.ascii_letters + string.digits + " _", k=n))


def _pick(pool, k):
    if not pool or k <= 0: return []
    return random.sample(pool, min(k, len(pool))) if len(pool) >= k else random.choices(pool, k=k)


def _jac(a, b):
    if not a and not b: return 1.0
    if not a or not b: return 0.0
    return len(a & b) / len(a | b)


def _tok(rx): return {t for t in re.findall(r"\\.|\[:[a-z]+:\]|\w+|\W", rx) if t.strip()}


def _wsample(idxs, weights, k):
    k = min(k, len(idxs))
    if k <= 0: return []
    items = list(zip(idxs, weights)); chosen = []
    for _ in range(k):
        total = sum(w for _, w in items)
        if total <= 0: chosen.append(items.pop(random.randrange(len(items)))[0]); continue
        r = random.random() * total; acc = 0.0; pi = 0
        for j, (idx, w) in enumerate(items):
            acc += w
            if acc >= r: pi = j; break
        chosen.append(items.pop(pi)[0])
    return chosen


_QS = set(['*', '+', '?', '{']); _MC = set(r"\.^$|?*+()[]{}")


_QS = set(['*', '+', '?', '{']); _MC = set(r"\.^$|?*+()[]{}")


_BS = {r'\b', r'\<', r'\>'}; _EC = {r'\d', r'\s', r'\w', r'\D', r'\S', r'\W'}


_BS = {r'\b', r'\<', r'\>'}; _EC = {r'\d', r'\s', r'\w', r'\D', r'\S', r'\W'}


_QRE = re.compile(r'(?:\?|\*|\+|\{[0-9]+(?:,[0-9]*)?\})')

__all__ = ['SAMPLE_REGEX', 'REWARD_CLAMP_MAX', '_MANUAL_SLASH_WRAP', '_MANUAL_DUAL_SRC', '_RX_KW', '_RX_KW_RE', '_FILE_KW', '_PAT_KW', '_DISALLOWED', 'OP_FRAGMENT', 'OP_MIRROR_TAIL', 'STRUCT_KINDS', 'ALL_KINDS', 'W_SLOW', 'W_MEM', 'PERF_NORM_THRESH', 'BUG_BONUS_CRASH', 'BUG_BONUS_PERF', 'MUTATE_SKIP_KINDS_BUG', 'MUTATE_KIND_PRIORITY_BUG', 'MUTATE_KIND_WEIGHTS', 'TOOL_TIMEOUT_BASE_KINDS', '_MAX_LEN', '_MAX_LEN_TAC_NL', '_MAX_LEN_EXPR_CSPLIT', '_MAX_POSIX', '_MAX_WB', '_MAX_ALT', '_MAX_DEPTH', '_DOTSTAR_CAP', '_RE_LOOK', '_RE_PCRE', '_RE_BREF', '_RE_POSIX', '_RE_WB', '_RE_ALT', '_RE_NQ', '_RE_MID', '_RE_CTRL', '_PROF_CACHE', '_esq', '_esl', '_rnd_txt', '_pick', '_jac', '_tok', '_wsample', '_QS', '_MC', '_BS', '_EC', '_QRE']