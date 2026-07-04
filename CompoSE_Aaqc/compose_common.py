import argparse, os, sys, subprocess as sp, glob, shlex, random, string, tempfile, signal
import re, shutil, json, math, pickle, uuid, hashlib, time
from pathlib import Path
from _shared import get_regex_mode
from typing import Optional, List, Set, Dict, Tuple, Union
from collections import Counter
from dataclasses import dataclass, asdict, field
from difflib import SequenceMatcher


test_dir = {
    'grep': 'GR',
    'sed': 'SE',
    'gawk': 'GA',
    'nano': 'NA',
    'diff': 'DI',
    'find': 'FI',
    'csplit': 'CS',
    'ptx': 'PT',
    'expr': 'EX',
    'm4': 'M4',
    'tac': 'TC',
    'nl': 'NL',
}
flags = {
    'grep': '-max-memory=4000 -use-forked-solver -disable-inlining -watchdog -switch-type=internal -simplify-sym-indices',
    'gawk': '-max-memory=4000 -use-forked-solver -disable-inlining -watchdog -switch-type=internal -simplify-sym-indices',
    'nano': '-max-memory=4000 -use-forked-solver -disable-inlining -watchdog -switch-type=internal -simplify-sym-indices',
    'find': '-max-memory=4000 -use-forked-solver -disable-inlining -watchdog -switch-type=internal -simplify-sym-indices',
    'csplit': '-max-memory=4000 -allocate-determ -allocate-determ-start-address=0x0 -allocate-determ-size=4000 -search=dfs -use-forked-solver -disable-inlining -watchdog -switch-type=internal -simplify-sym-indices',
    'ptx': '-max-memory=4000 -allocate-determ -allocate-determ-start-address=0x0 -allocate-determ-size=4000 -search=dfs -use-forked-solver -disable-inlining -watchdog -switch-type=internal -simplify-sym-indices',
    'expr': '-max-memory=4000 -allocate-determ -allocate-determ-start-address=0x0 -allocate-determ-size=4000 -search=dfs -use-forked-solver -disable-inlining -watchdog -switch-type=internal -simplify-sym-indices',
    'm4': '-max-memory=4000 -use-forked-solver -disable-inlining -watchdog -switch-type=internal -simplify-sym-indices',
    'tac': '-max-memory=4000 -allocate-determ -allocate-determ-start-address=0x0 -allocate-determ-size=4000 -search=dfs -use-forked-solver -disable-inlining -watchdog -switch-type=internal -simplify-sym-indices',
    'nl': '-max-memory=4000 -allocate-determ -allocate-determ-start-address=0x0 -allocate-determ-size=4000 -search=dfs -use-forked-solver -disable-inlining -watchdog -switch-type=internal -simplify-sym-indices',
}
sym_commands = {
    'csplit': '-sym-args 0 1 10 -sym-args 0 2 2 -sym-files 1 8 -sym-stdin 8 -sym-stdout',
    'ptx': '-sym-args 0 1 10 -sym-args 0 2 2 -sym-files 1 8 -sym-stdin 8 -sym-stdout',
    'expr': '-sym-args 0 1 10 -sym-args 0 2 2 -sym-files 1 8 -sym-stdin 8 -sym-stdout',
    'tac': '-sym-args 0 1 10 -sym-args 0 2 2 -sym-files 1 8 -sym-stdin 8 -sym-stdout',
    'nl': '-sym-args 0 1 10 -sym-args 0 2 2 -sym-files 1 8 -sym-stdin 8 -sym-stdout',
}
SET_SIZE = 20
SAMPLE_REGEX = "[a-z]"
SRC_SAMPLE_COUNT = 100
REWARD_CLAMP_MAX = None
_MANUAL_SLASH = {"csplit", "gawk", "sed"}
_DUAL_SRC = {"diff"}
_RX_KW = [r'\bregex\b', r'\bregexp\b', r'\bregular\s+expression', r'\bpattern\b',
           r'\bBRE\b', r'\bERE\b', r'\bextended.*regular', r'\bbasic.*regular']
_RX_KW_RE = re.compile('|'.join(_RX_KW), re.IGNORECASE)
_FILE_KW = ['FILE', 'PATH', 'INPUT', 'DIR', 'SOURCE']
_PAT_KW = ['PATTERN', 'REGEXP', 'REGEX', 'EXPRESSION', 'BRE', 'ERE']
_DISALLOWED = {"--debug", "--help", "--version"}
_TAKES_VALUE_RE = re.compile(r'=\s*(FILE|DIR|PATH|NAME|DIRECTORY|NUM|NUMBER|LEVELS|FORMAT|COMMAND|MODE|TYPE|PROGRAM|RE|REGEXP|REGEX|PATTERN|PAT|LABEL|PALETTE|GFMT|LFMT|WHEN)\b', re.IGNORECASE)
OP_FRAGMENT = "fragment_replace"
OP_RANDOM   = "random_regex"
OP_MIRROR_TAIL = "mirror_tail"
STRUCT_KINDS = {"GROUP", "ALT_BRANCH", "CLASS", "ANCHOR", "BOUNDARY"}
ALL_KINDS = {"GROUP", "ALT_BRANCH", "CLASS", "WILDCARD", "ANCHOR", "BOUNDARY", "ESCAPE", "LITERAL", "QUANT", "BACKREF"}
BUG_BONUS_CRASH = 50.0
MUTATE_SKIP_KINDS_BUG = {"LITERAL"}
MUTATE_KIND_WEIGHTS = {"BACKREF":60,"GROUP":60,"WILDCARD":60,"QUANT":60,"LITERAL":0,
                       "ESCAPE":0,"BOUNDARY":0}
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
_RE_ALTP = re.compile(r'(?<!\\)\|'); _RE_NQ = re.compile(r'(?:\([^\)]*\)[*+]){2,}')
_RE_ALTP = re.compile(r'(?<!\\)\|'); _RE_NQ = re.compile(r'(?:\([^\)]*\)[*+]){2,}')
_RE_MID = re.compile(r'(?<!^)\^|\$(?!$)'); _RE_CTRL = re.compile(r'\\x[0-9a-fA-F]{2}|\\[0-7]{1,3}')
_RE_MID = re.compile(r'(?<!^)\^|\$(?!$)'); _RE_CTRL = re.compile(r'\\x[0-9a-fA-F]{2}|\\[0-7]{1,3}')
_QS = set(['*', '+', '?', '{']); _MC = set(r"\.^$|?*+()[]{}")
_QS = set(['*', '+', '?', '{']); _MC = set(r"\.^$|?*+()[]{}")
_BS = {r'\b', r'\<', r'\>'}; _EC = {r'\d', r'\s', r'\w', r'\D', r'\S', r'\W'}
_BS = {r'\b', r'\<', r'\>'}; _EC = {r'\d', r'\s', r'\w', r'\D', r'\S', r'\W'}
_QRE = re.compile(r'(?:\?|\*|\+|\{[0-9]+(?:,[0-9]*)?\})')
_BUG_CORPUS_PATH: Optional[Path] = None
argv = sys.argv[1:]


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
def _lcs_dice(a, b):


    if not a and not b: return 1.0
    if not a or not b: return 0.0
    la, lb = len(a), len(b); prev = [0]*(lb+1); longest = 0
    for i in range(1, la+1):
        cur = [0]*(lb+1); ai = a[i-1]
        for j in range(1, lb+1):
            if ai == b[j-1]:
                v = prev[j-1]+1; cur[j] = v
                if v > longest: longest = v
        prev = cur
    return (2.0*longest)/(la+lb)
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

__all__ = ['test_dir', 'flags', 'sym_commands', 'SET_SIZE', 'SAMPLE_REGEX', 'SRC_SAMPLE_COUNT', 'REWARD_CLAMP_MAX', '_MANUAL_SLASH', '_DUAL_SRC', '_RX_KW', '_RX_KW_RE', '_FILE_KW', '_PAT_KW', '_DISALLOWED', '_TAKES_VALUE_RE', 'OP_FRAGMENT', 'OP_RANDOM', 'OP_MIRROR_TAIL', 'STRUCT_KINDS', 'ALL_KINDS', 'BUG_BONUS_CRASH', 'MUTATE_SKIP_KINDS_BUG', 'MUTATE_KIND_WEIGHTS', '_MAX_LEN', '_MAX_LEN_TAC_NL', '_MAX_LEN_EXPR_CSPLIT', '_MAX_LEN', '_MAX_LEN_TAC_NL', '_MAX_LEN_EXPR_CSPLIT', '_MAX_LEN', '_MAX_LEN_TAC_NL', '_MAX_LEN_EXPR_CSPLIT', '_MAX_POSIX', '_MAX_WB', '_MAX_ALT', '_MAX_DEPTH', '_DOTSTAR_CAP', '_MAX_POSIX', '_MAX_WB', '_MAX_ALT', '_MAX_DEPTH', '_DOTSTAR_CAP', '_MAX_POSIX', '_MAX_WB', '_MAX_ALT', '_MAX_DEPTH', '_DOTSTAR_CAP', '_MAX_POSIX', '_MAX_WB', '_MAX_ALT', '_MAX_DEPTH', '_DOTSTAR_CAP', '_MAX_POSIX', '_MAX_WB', '_MAX_ALT', '_MAX_DEPTH', '_DOTSTAR_CAP', '_RE_LOOK', '_RE_PCRE', '_RE_LOOK', '_RE_PCRE', '_RE_BREF', '_RE_POSIX', '_RE_WB', '_RE_POSIX', '_RE_WB', '_RE_ALTP', '_RE_NQ', '_RE_ALTP', '_RE_NQ', '_RE_MID', '_RE_CTRL', '_RE_MID', '_RE_CTRL', '_QS', '_MC', '_QS', '_MC', '_BS', '_EC', '_BS', '_EC', '_QRE', '_BUG_CORPUS_PATH', 'argv', '_esq', '_esl', '_rnd_txt', '_pick', '_jac', '_lcs_dice', '_tok', '_wsample']