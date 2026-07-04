#!/usr/bin/env python3
import argparse
import json
import random
import re
import sys
import sniffles.pcrecomp
from sniffles.nfa import PCRE_OPT
from typing import List



MAX_GROUP_DEPTH       = 3
DOT_STAR_MAX          = 12
POSIX_CLASS_MAX       = 12
ALT_MAX               = 10
DEFAULT_WB_LIMIT      = 8

_BAD_NESTED_QUANT_RE  = re.compile(r'(?:\([^\)]*\)[*+]){2,}')
_BACKREF_RE           = re.compile(r'(?<!\\)(?:\\\\)*\\([1-9])')
_CHARCLASS_POSIX_RE   = re.compile(r'\[:[a-z]+:\]')
_WORD_BOUND_RE        = re.compile(r'(?:\\b|\\<|\\>)')


PREFER_TOKENS: List[str] = []
AVOID_TOKENS: List[str]  = []


class GenOpts:
    def __init__(self):

        self.no_cap_dotstar        = True
        self.allow_literal_meta    = True
        self.allow_fixed_count     = True
        self.allow_open_count      = True
        self.allow_bare_alt        = True
        self.allow_composite_class = True
        self.wb_limit              = DEFAULT_WB_LIMIT
        self.allow_pcre_backref    = True

OPTS = GenOpts()

def maybe_lazy(q: str) -> str:
    return q + '?' if random.random() < 0.3 else q


def _normalize_dist(vals, want_len=None):
    try:
        arr = [int(x) for x in vals]
    except Exception:
        return None
    if want_len and len(arr) != want_len:
        return None

    if sum(arr) <= 0:
        return None
    return arr

def apply_profile(profile: dict, mode_from_cli: str):
    global MAX_GROUP_DEPTH, POSIX_CLASS_MAX, ALT_MAX, DEFAULT_WB_LIMIT, PREFER_TOKENS, AVOID_TOKENS

    knobs = profile.get("knobs", {})
    if "max_group_depth" in knobs:
        MAX_GROUP_DEPTH = max(1, int(knobs["max_group_depth"]))
    if "posix_class_max" in knobs:
        POSIX_CLASS_MAX = max(1, int(knobs["posix_class_max"]))
    if "word_boundary_limit" in knobs:
        DEFAULT_WB_LIMIT = max(0, int(knobs["word_boundary_limit"]))
        OPTS.wb_limit = DEFAULT_WB_LIMIT
    if "alt_max" in knobs:
        ALT_MAX = max(1, int(knobs["alt_max"]))
    if "no_cap_dotstar" in knobs:
        OPTS.no_cap_dotstar = bool(knobs["no_cap_dotstar"])


    allow = profile.get("allow", {})
    if "literal_meta" in allow:
        OPTS.allow_literal_meta = bool(allow["literal_meta"])
    if "fixed_count" in allow:
        OPTS.allow_fixed_count = bool(allow["fixed_count"])
    if "open_count" in allow:
        OPTS.allow_open_count = bool(allow["open_count"])
    if "bare_alt" in allow:
        OPTS.allow_bare_alt = bool(allow["bare_alt"])
    if "composite_class" in allow:
        OPTS.allow_composite_class = bool(allow["composite_class"])
    if "pcre_backref" in allow:
        OPTS.allow_pcre_backref = bool(allow["pcre_backref"])


    global PREFER_TOKENS, AVOID_TOKENS
    PREFER_TOKENS = [t for t in (profile.get("prefer_tokens", []) or []) if t not in (r'\b', r'\<', r'\>')]
    AVOID_TOKENS  = list(profile.get("avoid_tokens", []) or [])



    slots = profile.get("slots", {})
    type_dist = None
    if slots:

        type_dist = [
            int(slots.get("char", 28)),
            int(slots.get("class", 20)),
            int(slots.get("alt", 9)),
            int(slots.get("anchor", 10)),
            int(slots.get("boundary", 10)),
            int(slots.get("lookaround", 10)),
            int(slots.get("backref", 13)),
        ]
        type_dist[4] = 0
        if sum(type_dist) <= 0:
            type_dist = None

    char_dist = _normalize_dist(profile.get("char_dist"), want_len=None)
    class_dist = _normalize_dist(profile.get("class_dist"), want_len=None)
    rep_dist = _normalize_dist(profile.get("rep_dist"), want_len=4)


    prof_mode = profile.get("mode") or mode_from_cli

    return type_dist, char_dist, class_dist, rep_dist, prof_mode


def main():



    default_type_dist  = [28, 20, 9, 10, 0, 10, 13]
    default_char_dist  = [5, 5, 40, 40, 10]
    default_class_dist = [50, 40, 10]
    default_rep_dist   = [5, 5, 10, 80]

    parser = argparse.ArgumentParser(description='Random Regular Expression Generator (combined: coverage + bug-fix)')
    parser.add_argument('--mode',choices=['pcre','ere','bre'], default='pcre')
    parser.add_argument('-C', '--chardist')
    parser.add_argument('-c', '--regexnum', type=int, default=1)
    parser.add_argument('-D', '--classdist')
    parser.add_argument('-f', '--output', default='rand.re')
    parser.add_argument('-g', '--group', action='store_true')
    parser.add_argument('-l', '--length', type=int, default=65)
    parser.add_argument('-M', '--maxlen', type=int, default=0)
    parser.add_argument('-m', '--minlen', type=int, default=3)
    parser.add_argument('-n', '--negation_prob', type=int, default=15)
    parser.add_argument('-o', '--option_chance', type=int, default=40)
    parser.add_argument('-R', '--repetition_chance', type=int, default=15)
    parser.add_argument('-r', '--repdist')
    parser.add_argument('-t', '--typedist')
    parser.add_argument('--profile', help='Path to generation profile JSON', default=None)
    args = parser.parse_args()


    type_dist  = default_type_dist[:]
    char_dist  = default_char_dist[:]
    class_dist = default_class_dist[:]
    rep_dist   = default_rep_dist[:]
    mode       = args.mode


    if args.profile:
        try:
            with open(args.profile, "r") as pf:
                prof = json.load(pf)
            t2, c2, cl2, r2, mode2 = apply_profile(prof, mode)
            if t2:  type_dist  = t2
            if c2:  char_dist  = c2
            if cl2: class_dist = cl2
            if r2:  rep_dist   = r2
            mode = mode2 or mode
        except Exception as e:
            print(f"[warn] failed to load profile {args.profile}: {e}", file=sys.stderr)


    if args.chardist:
        char_dist = [int(x) for x in re.split(r'[\s,;]+', args.chardist)]
    if args.classdist:
        class_dist = [int(x) for x in re.split(r'[\s,;]+', args.classdist)]
    if args.repdist:
        rep_dist = [int(x) for x in re.split(r'[\s,;]+', args.repdist)]
    if args.typedist:
        type_dist = [int(x) for x in re.split(r'[\s,;]+', args.typedist)]

    if args.minlen < 1:
        args.minlen = 1

    create_regex_list(args.regexnum, args.length, type_dist, char_dist, class_dist,
                      rep_dist, args.repetition_chance, args.option_chance,
                      args.negation_prob, args.output, args.minlen, args.maxlen,
                      args.group, mode)
    print("Finished creating random regular expressions.")
    sys.exit(0)


def verify_bre_escapes(regex):

    must = ['(', ')', '{', '}', '|']
    errs = []
    for m in must:
        if re.search(r'(?<!\\)\{}'.format(m), regex):
            errs.append(m)
    return errs

def get_anchor_at(pos, total_len):
    if pos == 0 and random.random() < 0.5:
        return '^'
    if pos == total_len - 1 and random.random() < 0.5:
        return '$'
    return ''

def get_word_boundary(mode):
    return r'\b' if mode == 'pcre' else random.choice([r'\<', r'\>'])

def get_backreference(capture_count, mode):
    if capture_count < 1:
        return ''
    if mode == 'pcre' and not OPTS.allow_pcre_backref:
        return ''

    if random.random() < 0.4:
        lo = max(1, min(9, capture_count - 2))
        hi = min(9, capture_count)
        k = random.randint(lo, hi)
    else:
        k = random.randint(1, min(9, capture_count))
    return f"\\{k}"

def get_lookaround(mode, *args, **kwargs):
    if mode != 'pcre':
        return '', kwargs.get('groups', 0)
    kind = random.choice(['?=','?!'])
    piece = []
    for _ in range(random.randint(1,3)):
        tok = random.choice([get_substitution_class(mode), get_letter(), get_digit()])
        piece.append(tok)
    inner = ''.join(piece)
    return f"({kind}{inner})", kwargs.get('groups', 0)

def _should_insert_prefer_token() -> bool:

    return bool(PREFER_TOKENS) and (random.random() < 0.10)

def _pick_prefer_token() -> str:
    return random.choice(PREFER_TOKENS) if PREFER_TOKENS else ''

def _violates_avoid(body: str) -> bool:
    for tok in AVOID_TOKENS:
        try:
            if tok and tok in body:
                return True
        except Exception:

            pass
    return False

def create_regex_list(number, lambd, type_dist, char_dist, class_dist,
                      rep_dist, rep_chance, option_chance, negation_prob,
                      re_file, min_regex_length, max_regex_length,
                      use_prefix_group: bool, mode='pcre'):
    myrelist = []
    mygroups = []
    if use_prefix_group and number > 1:
        mygroups = getREGroups(
            number, type_dist, char_dist, class_dist,
            rep_dist, rep_chance, negation_prob, mode
        )

    count = 0

    guard = 0
    while count < number and guard < number * 1000:
        guard += 1


        capture_count = 0

        myregex = '/' if mode == 'pcre' else ''

        if mygroups:
            myregex += random.choice(mygroups)

        chunk, capture_count = generate_regex(
            lambd, max_regex_length,
            type_dist, char_dist, class_dist,
            rep_dist, rep_chance, negation_prob,
            min_regex_length, mode, capture_count
        )
        myregex += chunk

        if mode == 'pcre':
            myregex += '/'
            if random.randint(0, 100) < option_chance:
                opts = random.sample(['i', 's', 'm', 'g'], random.randint(1, 4))
                myregex += ''.join(opts)


        if mode in ('ere', 'bre'):
            if myregex.startswith('/'):
                myregex = myregex[1:]
            myregex = re.sub(r'[ims]+$', '', myregex)
            if myregex.endswith('/'):
                myregex = myregex[:-1]


        if mode == 'pcre':
            if myregex.startswith('/'):
                optp = myregex.rfind('/')
                body = myregex[1:optp]
                body = sanitize_and_lint(body, mode)
                if not body or _violates_avoid(body):
                    continue
                myregex = '/' + body + myregex[optp:]
        else:
            body = sanitize_and_lint(myregex, mode)
            if not body or _violates_avoid(body):
                continue
            myregex = body


        if mode == 'bre':
            if verify_bre_escapes(myregex):
                continue
        elif mode == 'pcre':
            if not check_pcre_compile(myregex):
                continue
        elif mode == 'ere':
            try:
                re.compile(myregex)
            except re.error:
                continue

        myrelist.append(myregex + "\n")
        count += 1

    with open(re_file, 'wb') as fd:
        for rx in myrelist:
            fd.write(rx.encode('utf-8'))

def generate_regex(lambd, max_len, type_dist, char_dist,
                   class_dist, rep_dist, rep_chance,
                   negation_prob, min_regex_length, mode, groups=0):
    if lambd <= 0:
        lambd = 10
    mylen = int(random.expovariate(1 / lambd))
    if mylen < min_regex_length:
        mylen = min_regex_length
    if max_len > 0 and mylen > max_len:
        mylen = max_len

    total_types = len(type_dist)
    myregex = ''
    i = 0
    while i < mylen:

        if _should_insert_prefer_token():
            tok = _pick_prefer_token()
            if tok:
                myregex += tok

        idx = get_index(total_types, type_dist)


        if mode in ('ere', 'bre') and groups == 0 and i > 0 and random.random() < 0.25:
            idx = 5


        tail = (i > int(mylen * 0.75))


        if groups >= 1 and random.random() < 0.2:
            idx = 6


        if tail and groups >= 1 and random.random() < 0.5:
            idx = 6

        if idx == 0:
            myregex += get_char(mode, char_dist)

        elif idx == 1:
            myregex += get_class(mode, class_dist, negation_prob, char_dist)

        elif idx == 2:
            seg_len = random.randint(1, max(1, mylen - i))
            i += max(1, seg_len - 1)
            chunk, groups = get_alternation(
                seg_len, type_dist, char_dist,
                class_dist, rep_dist, rep_chance,
                negation_prob, mode, groups
            )
            myregex += chunk

        elif idx == 3:
            myregex += get_anchor_at(i, mylen)

        elif idx == 4:
            current_wb = len(_WORD_BOUND_RE.findall(myregex))
            if current_wb < OPTS.wb_limit:
                myregex += get_word_boundary(mode)

        elif idx == 5:
            if mode == 'pcre':

                if random.random() < 0.2:
                    chunk, groups = get_lookaround(
                        mode, type_dist, char_dist, class_dist,
                        rep_dist, rep_chance, negation_prob, groups=groups
                    )
                    myregex += chunk
                else:
                    myregex += get_char(mode, char_dist)
            else:

                cg, groups = get_capturing_group(mode, groups, inner_kind='dotstar')
                myregex += cg

        elif idx == 6:
            br = get_backreference(groups, mode)
            if br:
                myregex += br
            else:
                myregex += get_char(mode, char_dist)


        if random.randint(0, 99) < rep_chance:
            if not re.search(r'[?*+}]$', myregex):
                q = get_repetition(rep_dist, mode)
                if mode == 'pcre':
                    q = maybe_lazy(q)
                myregex += q

        i += 1

    return myregex, groups

def get_capturing_group(mode, groups, inner_kind='dotstar'):
    if mode == 'bre':
        open_p, close_p = r'\(', r'\)'
    else:
        open_p, close_p = '(', ')'


    if inner_kind == 'dotstar':
        if random.random() < 0.7:

            inner = '.' + random.choice(['*', '+'])
        else:

            cls = random.choice(['[[:alnum:][:space:]]', '[[:print:]]', '[[:graph:]]', '[[:alnum:]]'])
            inner = cls + random.choice(['*', '+'])
    else:
        inner = '.*'

    return f"{open_p}{inner}{close_p}", groups + 1

def get_char(mode, char_dist):

    total_char_options = 6
    index = get_index(total_char_options, char_dist if len(char_dist)>=5 else [5,5,40,40,10])
    if index == 0:
        return get_ascii_char(mode)
    elif index == 1:
        return get_bin_char(mode)
    elif index == 2:
        return get_letter()
    elif index == 3:
        return get_digit()
    elif index == 4:
        return get_substitution_class(mode)
    else:
        lm = get_literal_meta(mode) if OPTS.allow_literal_meta else None
        return lm if lm else get_ascii_char(mode)

CONTROL_CODES = set(range(0, 32)) | {127}
META_CODES = {ord('['), ord(']'), ord('\\'), ord('*'), ord('+'),
              ord('?'), ord('{'), ord('}'), ord('('), ord(')'),
              ord('|'), ord('.'), ord('^'), ord('$'), ord('/')}

def get_ascii_char(mode):
    pick = random.randint(0, 126)
    c = chr(pick)
    if pick in CONTROL_CODES:
        return "\\x%02X" % pick if mode == 'pcre' else "[[:cntrl:]]"
    if pick in META_CODES:
        return escape_literal_char(c, mode) if OPTS.allow_literal_meta else c
    return c

def get_bin_char(mode):
    pick = random.randint(0, 255)
    try:
        c = chr(pick)
    except ValueError:
        c = ''
    if mode == 'pcre':
        return f"\\x{pick:02X}"
    else:
        if 32 <= pick <= 126:
            return c
        else:
            return "[[:cntrl:]]"

def get_literal_meta(mode):
    metas = ['.', '*', '+', '?', '(', ')', '{', '}', '|', '^', '$', '[', ']', '\\', '/']
    ch = random.choice(metas)
    return escape_literal_char(ch, mode)

def escape_literal_char(ch, mode):
    if mode in ('ere','pcre'):
        if ch in '.^$*+?{}[]\\|()':
            return '\\' + ch
        if ch == '/':
            return '\\/'
        return ch

    if ch in '(){}|+?*.^$[]\\':
        return '\\' + ch
    if ch == '/':
        return '\\/'
    return ch

def get_substitution_class(mode):
    raw = random.choice(['d','s','w','D','S','W','.'])
    if mode in ('ere', 'bre'):
        mapping = {
            'd': '[[:digit:]]',
            's': '[[:space:]]',
            'w': '[[:alnum:]_]',
            'D': '[^[:digit:]]',
            'S': '[^[:space:]]',
            'W': '[^[:alnum:]_]',
            '.': '.'
        }
        return mapping[raw]
    return '.' if raw == '.' else '\\' + raw

def get_digit():
    return random.choice('0123456789')

def get_letter():
    char_tbl = [chr(i) for i in range(ord('A'), ord('Z')+1)]
    chr_pick = random.choice(char_tbl)
    if random.random() < 0.5:
        chr_pick = chr_pick.lower()
    return chr_pick

def get_class(mode, class_distribution, negation_prob, char_dist):

    if OPTS.allow_composite_class and random.random() < 0.6:
        return build_composite_class(mode, negation_prob)

    total_class_choices = len(class_distribution)
    index = get_index(total_class_choices, class_distribution)
    class_set = []
    myclass = '['
    neg = False
    if random.randint(0, 99) < negation_prob:
        myclass += '^'
        neg = True
    if index == 0:
        end = random.randint(1, 5)
        for _ in range(end):
            next_char = get_char(mode, char_dist)
            while next_char == '.' or next_char in class_set:
                next_char = get_char(mode, char_dist)
            class_set.append(next_char)
    elif index == 1:
        start = get_letter()
        if 'A' <= start < 'Z':
            endc = random.randint(ord(start) + 1, ord('Z'))
        elif start == 'Z':
            start, endc = 'Y', ord('Z')
        elif 'a' <= start < 'z':
            endc = random.randint(ord(start) + 1, ord('z'))
        else:
            start, endc = 'y', ord('z')
        next_char = start + '-' + chr(endc)
        class_set.append(next_char)
    elif index == 2:
        class_set.append('0-9')
    else:
        end = random.randint(1, 5)
        for _ in range(end):
            next_char = get_char(mode, char_dist)
            while next_char == '.' or next_char in class_set:
                next_char = get_char(mode, char_dist)
            class_set.append(next_char)

    for c in class_set:
        if neg and c in ['\\W', '\\D', '\\S']:
            continue
        myclass += c
    if myclass == '[' or myclass == '[^':
        myclass += 'a-z'
    myclass += ']'
    return myclass

def build_composite_class(mode, negation_prob):
    parts_catalog = [
        'a-z', 'A-Z', '0-9', '_', '-', '.', ':',
        '[[:digit:]]', '[[:alpha:]]', '[[:alnum:]]', '[[:space:]]'
    ]
    k = random.randint(2, 5)
    parts = random.sample(parts_catalog, k)
    neg = (random.randint(0,99) < negation_prob)
    body = '^' if neg else ''
    uniq = []
    for p in parts:
        if p not in uniq:
            uniq.append(p)
    body += ''.join(uniq)
    return f'[{body}]'

def get_alternation(max_length, type_dist, char_dist,
                    class_dist, rep_dist, rep_chance,
                    negation_prob, mode, groups):
    bare = OPTS.allow_bare_alt and random.random() < 0.6
    if mode == 'bre':
        open_paren, sep, close_paren = (r'\(', r'\|', r'\)') if not bare else ('', r'\|', '')
        inc_groups = 1 if not bare else 0
    elif mode == 'pcre':
        open_paren, sep, close_paren = ('(?:', '|', ')') if not bare else ('', '|', '')
        inc_groups = 0
    else:
        open_paren, sep, close_paren = ('(', '|', ')') if not bare else ('', '|', '')
        inc_groups = 0

    pattern = open_paren
    groups += inc_groups

    alternates = min(ALT_MAX, max(2, int(random.expovariate(1 / 2))))
    alt_max_length = max(1, min(max_length, 8))
    for i in range(alternates):
        this_length = alt_max_length if i == 0 else random.randint(1, alt_max_length)
        chunk, groups = generate_regex(
            0, this_length,
            type_dist, char_dist,
            class_dist, rep_dist,
            rep_chance, negation_prob,
            1, mode,
            groups
        )
        pattern += chunk
        if i < alternates - 1:
            pattern += sep

    pattern += close_paren
    return pattern, groups

def get_index(total_options, dist):
    if total_options <= 0:
        total_options = 1
    if dist is None:
        return random.randint(0, total_options - 1)
    else:
        index = 0
        s = 0
        pick = random.randint(0, 99)
        for prob in dist:
            s += int(prob)
            if pick < s:
                return index
            else:
                index += 1
        return total_options - 1

def get_repetition(rep_dist, mode, rep_start_max=5, rep_end_max=10):

    index = get_index(4, rep_dist)
    if index == 0:
        base = r'\?' if mode == 'bre' else '?'
    elif index == 1:
        base = '*'
    elif index == 2:
        base = r'\+' if mode == 'bre' else '+'
    else:
        if not (OPTS.allow_fixed_count or OPTS.allow_open_count):

            base = r'\+' if mode == 'bre' else '+'
        else:
            which = random.choice(
                [w for w in ['range','fixed','open']
                 if (w == 'fixed' and OPTS.allow_fixed_count) or
                    (w == 'open'  and OPTS.allow_open_count) or
                    (w == 'range')]
            )
            if which == 'fixed':
                n = random.randint(0, rep_end_max)
                base = f'{{{n}}}'
            elif which == 'open':
                m = random.randint(0, rep_start_max)
                base = f'{{{m},}}'
            else:
                start = random.randint(0, rep_start_max)
                end   = random.randint(start + 1, rep_end_max)
                base = f'{{{start},{end}}}'
        if mode == 'bre':
            base = base.replace('{', r'\{').replace('}', r'\}')
    return base

def getREGroups(number, type_dist, char_dist, class_dist,
                rep_dist, rep_chance, negation_prob, mode):
    new_groups = []
    if number > 1:
        num_groups = random.randint(1, int(number / 2))
        for _ in range(1, num_groups):
            prefix, _ = generate_regex(
                random.randint(5, 20), 0,
                type_dist, char_dist, class_dist, rep_dist,
                rep_chance, negation_prob, 1, mode, groups=0
            )
            new_groups.append(prefix)
    return new_groups

def check_pcre_compile(re_slashed):
    options = []
    if len(re_slashed) and re_slashed[0] == '/':
        optp = re_slashed.rfind('/')
        if optp > 0:
            options = list(re_slashed[optp + 1:])
            pattern = re_slashed[1:optp]
        else:
            pattern = re_slashed.strip('/')
    else:
        pattern = re_slashed

    opts_val = 0
    for opt in options:
        if opt in PCRE_OPT:
            opts_val |= PCRE_OPT[opt]
    try:
        sniffles.pcrecomp.compile(pattern, opts_val)
    except Exception:
        return False
    return True


def _limit_wildcards(s: str) -> str:

    if OPTS.no_cap_dotstar:
        return s
    s = re.sub(r'\.\*', f'.{{0,{DOT_STAR_MAX}}}', s)
    s = re.sub(r'\.\+', f'.{{1,{DOT_STAR_MAX}}}', s)
    return s

def _strip_mid_anchors(s: str) -> str:

    s = re.sub(r'(?<!^)\^', '', s)
    s = re.sub(r'\$(?!$)', '', s)
    return s

def _group_depth_ok(s: str) -> bool:
    depth = 0
    in_class = False
    esc = False
    for ch in s:
        if esc:
            esc = False
            continue
        if ch == '\\':
            esc = True
            continue
        if in_class:
            if ch == ']':
                in_class = False
            continue
        if ch == '[':
            in_class = True
            continue
        if ch == '(':
            depth += 1
            if depth > MAX_GROUP_DEPTH:
                return False
        elif ch == ')':
            depth = max(0, depth - 1)
    return True

def sanitize_and_lint(body: str, mode: str) -> str:

    if mode == 'pcre' and ('(?<=' in body or '(?<!' in body):
        return ''


    refs = _BACKREF_RE.findall(body)

    if mode == 'bre' and any(int(r) > 9 for r in refs):
        return ''


    if len(_WORD_BOUND_RE.findall(body)) > DEFAULT_WB_LIMIT:
        return ''


    if len(_CHARCLASS_POSIX_RE.findall(body)) > POSIX_CLASS_MAX:
        return ''


    if _BAD_NESTED_QUANT_RE.search(body):
        return ''

    body = _limit_wildcards(body)
    body = _strip_mid_anchors(body)

    if not _group_depth_ok(body):
        return ''

    return body

if __name__ == "__main__":
    main()