#!/usr/bin/env python3


import html as _html
import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional, Set, Tuple


@dataclass
class Option:
    flags: List[str] = field(default_factory=list)
    metavars: List[str] = field(default_factory=list)
    description: str = ""
    regex_related: bool = False
    co_regex: bool = False   # co-used with a regex option (shares its target object)


def load_text(path: str) -> str:

    if not os.path.isfile(path):
        raise FileNotFoundError(f"manual not found: {path}")
    low = str(path).lower()
    if low.endswith(".pdf"):
        try:
            p = subprocess.run(
                ["pdftotext", "-layout", str(path), "-"],
                capture_output=True, text=True,
            )
        except FileNotFoundError:
            raise RuntimeError(
                "pdftotext not found; install poppler-utils "
                "(e.g. `sudo apt install poppler-utils`)"
            )
        if p.returncode != 0:
            msg = (p.stderr or "").strip() or f"exit status {p.returncode}"
            raise RuntimeError(
                f"pdftotext failed on {path}: {msg}. "
                f"Check that the file is a valid, non-empty PDF "
                f"(try: file {path})."
            )
        if not (p.stdout or "").strip():
            raise RuntimeError(
                f"pdftotext produced no text for {path} "
                f"(scanned/image-only PDF? try an HTML or text manual instead)."
            )
        return p.stdout
    if low.endswith((".html", ".htm")):
        raw = open(path, encoding="utf-8", errors="replace").read()
        raw = re.sub(r"(?is)<(script|style).*?</\1>", "", raw)
        raw = re.sub(r"(?i)<br\s*/?>", "\n", raw)
        raw = re.sub(r"(?i)</(p|div|dt|dd|li|tr|h[1-6]|pre)>", "\n", raw)
        return _html.unescape(re.sub(r"<[^>]+>", "", raw))
    return open(path, encoding="utf-8", errors="replace").read()


_FLAG = re.compile(
    r"--?[A-Za-z][A-Za-z0-9-]*(?:\[=?[^\]\s]*\]|=(?:\"[^\"]*\"|'[^']*'|[^\s,]+))?"
)
_BARE = re.compile(r"--?[A-Za-z][A-Za-z0-9-]*")

_METAVAR = re.compile(
    r"\"[^\"]*\"|'[^']*'|"
    r"(?:[A-Z][A-Z0-9_-]*|script-file|script|file(?:name)?|num|word|label|width|"
    r"action|type|glob|string|sep|pattern|regexp?|re|suffix|N)\b"
)
_NOISE = re.compile(
    r"\.\s\.\s\.|man7\.org|manual page\s*$|^\s*\d+/\d+\s*$|"
    r"^\s*\d+\.\s\d+\.\s\d+\.|\x0c|^\s*\d+\s*$|"
    r"^\s*https?://\S+\s+\d+/\d+\s*$"
)
_TOPSEC = re.compile(r"^([A-Z][A-Z ]+?)\s+top\s*$")          # "OPTIONS top"
_SUBHDR = re.compile(r"^[A-Z][A-Za-z]+(?: [A-Z][A-Za-z]+){0,5}$")  # "Pattern Syntax"


def _parse_label(s: str) -> Tuple[Optional[List[str]], List[str], str]:
    """Greedily consume a leading option signature from a stripped line.

    Returns (flags, metavars, inline_description). Returns (None, [], "") for
    prose that merely begins with a dash (e.g. "-y is an obsolete synonym ..."):
    a genuine inline description is empty, starts uppercase/'['/digit, or is set
    off by 2+ spaces.
    """
    flags: List[str] = []
    metavars: List[str] = []
    i, n, last_flag = 0, len(s), False
    while i < n:
        sep = re.match(r"[\s,]+", s[i:])
        sl = sep.end() if sep else 0
        mf = _FLAG.match(s, i + sl)
        if mf and (i == 0 or sl):
            full = mf.group(0)
            bare = _BARE.match(full).group(0)
            flags.append(bare)
            tail = full[len(bare):]                # "=RE", "[=WHEN]", '="regex"'
            mv = re.search(r"[A-Za-z][A-Za-z0-9_-]*", tail)
            if mv:
                metavars.append(mv.group(0))
            i = mf.end(); last_flag = True; continue
        mvm = _METAVAR.match(s, i + sl)
        if mvm and last_flag and sl:
            tok = mvm.group(0).strip("\"'")
            if tok:
                metavars.append(tok)
            i = mvm.end(); last_flag = False; continue
        break
    if not flags:
        return None, [], ""
    rem = s[i:].lstrip()
    n_spaces = len(s[i:]) - len(s[i:].lstrip(" "))
    if rem and n_spaces < 2 and not re.match(r"[A-Z0-9[(]", rem):
        return None, [], ""
    return flags, metavars, rem


# --- regex-related classification --------------------------------------------
_RX_STRONG = re.compile(
    r"regexp?|regular\s+expression|\bBRE\b|\bERE\b|\bPCRE\b|perl-?compatible|"
    r"basic\s+regular|extended\s+regular", re.IGNORECASE,
)
_GLOB = re.compile(
    r"\bglob\b|\bwildcard\b|file\s*name|files?\s+that\s+match|\bshell\b", re.IGNORECASE
)

_RX_METAVAR_TOKENS = {"RE", "REGEX", "REGEXP", "REXP", "BRE", "ERE", "PCRE"}

_RX_NEG_CONTEXT = re.compile(r"\b(response|prompt|affirmative|negative)\b", re.IGNORECASE)

_RX_FIXED_STRINGS = re.compile(
    r"fixed\s+strings?|literal\s+strings?|"
    r"as\s+(?:a\s+)?(?:literal\s+|fixed\s+)?strings?|"
    r"not\s+(?:a\s+)?regular\s+expressions?",
    re.IGNORECASE,
)

_RX_SIDEEFFECT = re.compile(
    r"\bto make\b[^.]*?\bwork\b|\bwork correctly\b|"
    r"\bcause\w*\b[^.]*?\bto\s+fail\b|\bso that\b[^.]*?\bwork\b",
    re.IGNORECASE,
)

_ENUM_HDR = re.compile(r"\b([A-Z][A-Z0-9_]{1,})\s+is\s+one\s+of\b")


_STOP_NOUNS = {
    "regular", "expression", "expressions", "string", "strings", "number",
    "numbers", "character", "characters", "output", "input", "pattern",
    "patterns", "line", "lines", "file", "files", "name", "names", "value",
    "values", "word", "words", "text", "field", "fields", "search", "part",
}

_TARGET_PATS = [
    re.compile(r"interpret\s+the\s+([a-z]{4,})\s+as\s+a\s+regular", re.IGNORECASE),
    re.compile(r"\bthe\s+([a-z]{4,})\s+as\s+(?:a\s+)?regular\s+expression", re.IGNORECASE),
    re.compile(r"regular\s+expression\s+for\s+matching\s+the\s+([a-z]{4,})", re.IGNORECASE),
    re.compile(r"regexp?\s+to\s+match\s+(?:each\s+|the\s+)?([a-z]{4,})", re.IGNORECASE),
]


def _apply_co_use_groups(options: List[Option]) -> None:
    """Mark options co-used with a regex option because they configure the same
    target object.

    A regex option names the object its regex acts on (tac's -r: "interpret the
    *separator* as a regular expression"). Sibling options that also mention that
    object (-s --separator, -b "attach the separator") form one regex-injection
    group. Anchoring on the named target -- not on any shared word -- keeps this
    from pulling in unrelated options (e.g. find's case-insensitive tests).
    """
    def words(o: Option) -> Set[str]:
        text = o.description + " " + " ".join(o.flags)
        return set(re.findall(r"[a-z]{4,}", text.lower()))

    targets: Set[str] = set()
    for o in options:
        if not o.regex_related:
            continue
        for pat in _TARGET_PATS:
            m = pat.search(o.description)
            if m:
                noun = m.group(1).lower()
                if noun not in _STOP_NOUNS:
                    targets.add(noun)

    wsets = {id(o): words(o) for o in options}
    for noun in targets:
        members = [o for o in options if noun in wsets[id(o)]]
        if 2 <= len(members) <= 4 and any(o.regex_related for o in members):
            for o in members:
                o.co_regex = True


def detect_operand_regex(text: str) -> List[str]:
    """Evidence that the program takes a regex through an operand/script rather
    than an option (csplit's /REGEXP/, expr's STRING : REGEXP, gawk/sed /regex/).

    Returned as a list of matched snippets; empty if none found. This is a
    separate injection channel from the option list.
    """
    pats = [
        r"/\s*REGEXP?\s*/",                
        r"%\s*REGEXP?\s*%",                 
        r"STRING\s*:\s*REGEXP",            
        r"match\s+STRING\s+REGEXP",        
        r"/\s*regular\s+expression\s*/",  
    ]
    out: List[str] = []
    for p in pats:
        m = re.search(p, text, re.IGNORECASE)
        if m:
            out.append(m.group(0).strip())
    return out


def _regex_value_metavars(text: str) -> Set[str]:
    """Metavars whose documented value enumeration mentions a regex.

    Catches options like nl's -b/-f/-h whose own one-line description has no
    regex keyword, but whose STYLE value is later defined as
    "pBRE  number only lines that contain a match for the basic regular
    expression, BRE".
    """
    out: Set[str] = set()
    hits = list(_ENUM_HDR.finditer(text))
    for k, m in enumerate(hits):
        start = m.end()
        end = hits[k + 1].start() if k + 1 < len(hits) else min(len(text), start + 800)
        if _RX_STRONG.search(text[start:end]):
            out.add(m.group(1).upper())
    return out


def _classify(
    flags: List[str],
    metavars: List[str],
    desc: str,
    weak_pattern_signal: bool,
    rx_value_metavars: Set[str],
) -> bool:
    if any(re.search(r"regex", f, re.IGNORECASE) for f in flags):
        return True
    for mv in metavars:
        u = mv.upper()
        if u in _RX_METAVAR_TOKENS or u in rx_value_metavars:
            return True
        if re.search(r"regex", mv, re.IGNORECASE):
            return True
    if (_RX_STRONG.search(desc)
            and not _RX_NEG_CONTEXT.search(desc)
            and not _RX_SIDEEFFECT.search(desc)
            and not _RX_FIXED_STRINGS.search(desc)):
        return True

    if (re.search(r"\bmatch\w*\b", desc, re.IGNORECASE)
            and re.search(r"\bpattern\b", desc, re.IGNORECASE)
            and not _GLOB.search(desc)
            and not _RX_FIXED_STRINGS.search(desc)):
        return True
    if weak_pattern_signal and re.search(r"\bpattern", desc, re.IGNORECASE):
        return not (bool(_GLOB.search(desc)) or bool(_RX_FIXED_STRINGS.search(desc)))
    return False


def extract_options(
    text: str,
    weak_pattern_signal: bool = True,
    option_sections: Tuple[str, ...] = ("OPTIONS", "DESCRIPTION", "EXPRESSION"),
) -> List[Option]:

    rx_value_metavars = _regex_value_metavars(text)


    is_man7 = bool(re.search(r"^\s*[A-Z][A-Z ]+\s+top\s*$", text, re.MULTILINE))

    options: List[Option] = []
    cur: Optional[Option] = None
    prev_label = False
    in_opt = not is_man7

    def flush():
        nonlocal cur
        if cur and cur.flags and cur.description.strip():
            cur.description = " ".join(cur.description.split())
            options.append(cur)
        cur = None

    for raw in text.splitlines():
        if _NOISE.search(raw):
            continue
        s = raw.strip()

        top = _TOPSEC.match(s)
        if top:
            flush(); in_opt = top.group(1).strip() in option_sections; prev_label = False
            continue
        if not s:
      
            if cur is not None and cur.description.strip():
                flush()
            prev_label = False
            continue
        if not in_opt:
            continue

        flags, metavars, inline = _parse_label(s) if s[0] == "-" else (None, [], "")
        if flags:

            if cur and cur.description.strip():
                flush()
            if cur is None:
                cur = Option()
            cur.flags.extend(f for f in flags if f not in cur.flags)
            cur.metavars.extend(metavars)
            if inline:
                cur.description += " " + inline
            prev_label = True
        elif _SUBHDR.match(s):
            flush(); prev_label = False
        else:
            if cur is not None:
                cur.description += " " + s
            prev_label = False

    flush()

    merged: List[Option] = []
    by_prim = {}
    for o in options:
        prim = next((f for f in o.flags if f.startswith("--")), o.flags[0])
        if prim not in by_prim:
            by_prim[prim] = o
            merged.append(o)
        else:
            m = by_prim[prim]
            for f in o.flags:
                if f not in m.flags:
                    m.flags.append(f)
            m.metavars.extend(x for x in o.metavars if x not in m.metavars)
            if len(o.description) > len(m.description):
                m.description = o.description

    for o in merged:
        o.regex_related = _classify(
            o.flags, o.metavars, o.description, weak_pattern_signal, rx_value_metavars,
        )
    _apply_co_use_groups(merged)
    return merged


def _scan_flags(text: str) -> Set[str]:

    flags: Set[str] = set()
    for m in _FLAG.finditer(text):
        i = m.start()
        if i == 0 or text[i - 1] in " \t,(":
            flags.add(_BARE.match(m.group(0)).group(0))
    return flags


def binary_help_flags(binary: str, args: Tuple[str, ...] = ("--help",),
                      timeout: int = 10) -> Set[str]:

    try:
        p = subprocess.run([binary, *args], capture_output=True, text=True,
                           timeout=timeout)
        return _scan_flags((p.stdout or "") + "\n" + (p.stderr or ""))
    except (OSError, subprocess.SubprocessError):
        return set()


def extract_verified_regex_options(
    manual_path: str,
    binary: Optional[str] = None,
    weak_pattern_signal: bool = False,
) -> Tuple[List[Option], List[Option]]:

    opts = extract_options(load_text(manual_path), weak_pattern_signal=weak_pattern_signal)
    candidates = [o for o in opts if o.regex_related or o.co_regex]
    if binary is None:
        return candidates, []
    have = binary_help_flags(binary)
    kept = [o for o in candidates if any(f in have for f in o.flags)]
    dropped = [o for o in candidates if o not in kept]
    return kept, dropped


if __name__ == "__main__":
    import sys

    text = load_text(sys.argv[1])
    channel = detect_operand_regex(text)
    for weak in (True, False):
        opts = extract_options(text, weak_pattern_signal=weak)
        rx = [o for o in opts if o.regex_related]
        co = [o for o in opts if o.co_regex and not o.regex_related]
        mode = "recall-first" if weak else "precision-first"
        print(f"\n== {mode}: {len(opts)} entries, {len(rx)} regex-related ==")
        for o in rx:
            print(f"  {', '.join(o.flags):26} {o.description[:58]}")
        if co:
            print("  co-used (same regex target):")
            for o in co:
                print(f"    {', '.join(o.flags):24} {o.description[:56]}")
    if channel:
        print(f"\n== operand/script regex channel (not an option): {channel} ==")
