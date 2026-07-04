import os
import re
from typing import List, Optional, Set, Tuple, Dict


_MANUAL_SLASH_WRAP_PROGRAMS = {"csplit", "gawk", "sed"} 
_MANUAL_DUAL_SRC_PROGRAMS = {"diff"}  


_OPERAND_REGEX_PROGRAMS = {"gawk"}
_FILE_KEYWORDS = ['FILE', 'PATH', 'INPUT', 'DIR', 'SOURCE']
_PATTERN_KEYWORDS = ['PATTERN', 'REGEXP', 'REGEX', 'EXPRESSION', 'BRE', 'ERE']
_RE_LONG = re.compile(r"--[A-Za-z0-9][A-Za-z0-9\-]*")
_RE_SHORT = re.compile(r"(?<!-)-[A-Za-z]\b")
_RE_SHORT_LONG = re.compile(r"(?<![A-Za-z0-9\-])-[A-Za-z][A-Za-z0-9]*") 
_DISALLOWED_FLAGS = {"--debug"}
_RE_SHORT_TAKES_VALUE = re.compile(r'^\s*(-[A-Za-z])(?:\[|\s+[a-z]|\s+<|\s+\')')
_RE_LONG_TAKES_VALUE = re.compile(r'(--[A-Za-z0-9][A-Za-z0-9\-]*)(?:\[?=)')
_FILE_KW_RE = re.compile(
    r"\b(?:" + "|".join(k + "S?" for k in _FILE_KEYWORDS) + r")\b", re.IGNORECASE)
_PATTERN_KW_RE = re.compile(
    r"\b(?:" + "|".join(k + "S?" for k in _PATTERN_KEYWORDS) + r")\b", re.IGNORECASE)


mox = None
_MOX_TOPSEC = None


def _short_takes_value(ln: str) -> Set[str]:
    """Return set of short flags on this line that take a value argument."""
    return {m.group(1) for m in _RE_SHORT_TAKES_VALUE.finditer(ln)}

def _long_takes_value(ln: str) -> Set[str]:
    """Return set of long flags on this line that take a value argument."""
    return {m.group(1) for m in _RE_LONG_TAKES_VALUE.finditer(ln)}

def _filter_disallowed_flags(flags: List[str]) -> List[str]:
    return [flag for flag in flags if flag not in _DISALLOWED_FLAGS]

def _is_regex_related_option(flag: str, description: str) -> bool:
    """Check if an option is regex-related based on its description OR flag name."""

    if re.search(r'\bregex\b|\bregexp\b|\bregular\s+expression|\bBRE\b|\bERE\b|\bextended.*regular|\bbasic.*regular|\bperl.*regexp|\bposix.*regular', description, re.IGNORECASE):
        return True

    if re.search(r'\bRE\b', description):
        return True
    if re.search(r'regexp|regex', flag, re.IGNORECASE):
        return True
    if re.search(r'=\s*(REGEXP|REGEX)\b', description):
        return True

    if re.search(r'\bpattern\b', description, re.IGNORECASE):
        if re.search(r'\bexclude\b|\bfiles?\s+that\s+match\b|\bfile\s*name\b|\bglob\b|\bwildcard\b|\bshell\b', description, re.IGNORECASE):
            return False
        return True
    return False

def _extract_all_flags_from_help(help_text: str) -> List[str]:
    flags: Set[str] = set()
    for ln in help_text.splitlines():
        if "-" not in ln:
            continue
        stripped = ln.lstrip()
        if not stripped.startswith('-'):
            continue
        val_flags = _short_takes_value(ln)
        val_longs = _long_takes_value(ln)
        shorts = []
        longs = []
        for m in _RE_SHORT.finditer(ln):
            f = m.group(0).rstrip(",.;:)=]")
            if f not in val_flags:
                shorts.append(f)
        for m in _RE_LONG.finditer(ln):
            f = m.group(0).rstrip(",.;:)=]")
            if f not in val_longs:
                longs.append(f)
        single_dash_longs = []
        for m in _RE_SHORT_LONG.finditer(ln):
            f = m.group(0).rstrip(",.;:)=]")
            if len(f) > 2 and f not in shorts and f not in longs:
                single_dash_longs.append(f)

        if shorts and longs:
            for f in shorts + single_dash_longs: flags.add(f)
        else:
            for f in shorts + longs + single_dash_longs: flags.add(f)
    return _filter_disallowed_flags(
        sorted(flags, key=lambda x: (0 if x.startswith("--") else 1, x))
    )

def _extract_flags_with_descriptions(help_text: str) -> List[Tuple[str, str]]:

    results: List[Tuple[str, str]] = []
    for ln in help_text.splitlines():
        stripped = ln.lstrip()
        if not stripped.startswith('-'):
            continue
        
        val_flags = _short_takes_value(ln)
        val_longs = _long_takes_value(ln)
        shorts = []
        longs = []
        for m in _RE_SHORT.finditer(ln):
            f = m.group(0).rstrip(",.;:)=]")
            if f not in shorts and f not in val_flags: shorts.append(f)
        for m in _RE_LONG.finditer(ln):
            f = m.group(0).rstrip(",.;:)=]")
            if f not in longs and f not in val_longs: longs.append(f)

        single_dash_longs = []
        for m in _RE_SHORT_LONG.finditer(ln):
            f = m.group(0).rstrip(",.;:)=]")
            if len(f) > 2 and f not in shorts and f not in longs and f not in single_dash_longs:
                single_dash_longs.append(f)
        

        if shorts and longs:
            flags_in_line = shorts + single_dash_longs
        else:
            flags_in_line = shorts + longs + single_dash_longs
        
        for flag in flags_in_line:
            if flag not in _DISALLOWED_FLAGS:
                results.append((flag, ln))
    return results

def _parse_program_usage_profile(help_text: str, pgm: str) -> dict:

    profile = {
        "arg_order": "regex_first", 
        "regex_prefix": "",
        "regex_suffix": "",
        "regex_options": [],
        "all_options": [],
        "special_syntax": None,
        "uses_slash_wrap": pgm in _MANUAL_SLASH_WRAP_PROGRAMS,
        "needs_dual_src": pgm in _MANUAL_DUAL_SRC_PROGRAMS,
        "accepts_options": True,  
    }
    
    if not help_text:
        return profile
    
  
    usage_lines = []
    for ln in help_text.splitlines():
        ln_lower = ln.strip().lower()
        if ln_lower.startswith('usage:'):
            usage_lines.append(ln)
    
   
    has_option_in_usage = False
    for usage_ln in usage_lines:
        usage_upper = usage_ln.upper()

        if '[OPTION]' in usage_upper or '[OPTIONS]' in usage_upper:
            has_option_in_usage = True
            break
       
        if re.search(r'\[[^\]]*\bOPTIONS?\b[^\]]*\]', usage_upper):
            has_option_in_usage = True
            break

        if re.search(r'\[-[A-Za-z]', usage_ln) or re.search(r'\[--[A-Za-z]', usage_ln):
            has_option_in_usage = True
            break
    profile["accepts_options"] = has_option_in_usage
    

    for usage_ln in usage_lines:
        usage_upper = usage_ln.upper()
        

        file_pos = None
        for kw in _FILE_KEYWORDS:
            idx = usage_upper.find(kw)
            if idx != -1:

                if file_pos is None or idx < file_pos:
                    file_pos = idx
        

        pattern_pos = None
        for kw in _PATTERN_KEYWORDS:
            idx = usage_upper.find(kw)
            if idx != -1:
                if pattern_pos is None or idx < pattern_pos:
                    pattern_pos = idx
        

        if file_pos is not None and pattern_pos is not None:
            if file_pos < pattern_pos:
                profile["arg_order"] = "file_first"
            else:
                profile["arg_order"] = "regex_first"
        elif file_pos is None and pattern_pos is not None:
            profile["arg_order"] = "no_file"
        
        break  
    

    if re.search(r'STRING\s*:\s*REGEXP', help_text, re.IGNORECASE):
        profile["special_syntax"] = "string_colon_regex"
        profile["arg_order"] = "no_file"
    

    if re.search(r'\bpBRE\b', help_text):
        profile["regex_prefix"] = "p"
    
   
    if re.search(r'/REGEXP/', help_text):
        profile["uses_slash_wrap"] = True
    
  
    if profile["accepts_options"]:
        flags_with_desc = _extract_flags_with_descriptions(help_text)
        all_flags = list(set(f for f, _ in flags_with_desc))
        regex_flags = []
        
        for flag, desc in flags_with_desc:
            if _is_regex_related_option(flag, desc):
                if flag not in regex_flags:
                    regex_flags.append(flag)
      
        _VRX = re.compile(r'^\s*(-[A-Za-z])\s+<(regex|regexp|re|pattern)>', re.IGNORECASE)
        for ln in help_text.splitlines():
            m = _VRX.match(ln)
            if m and m.group(1) not in regex_flags and m.group(1) not in _DISALLOWED_FLAGS:
                regex_flags.append(m.group(1))
            if not m:
                m2 = re.match(r'^\s*(-[A-Za-z])\s+<\S+>', ln)
                if m2 and _is_regex_related_option(m2.group(1), ln) and m2.group(1) not in regex_flags and m2.group(1) not in _DISALLOWED_FLAGS:
                    regex_flags.append(m2.group(1))
  
        separator_flags = []
        separator_value_flag = None
        regex_mentions_separator = any(
            _is_regex_related_option(f, d) and re.search(r'\bseparator\b', d, re.IGNORECASE)
            for f, d in flags_with_desc
        )
        if regex_mentions_separator:
            for flag, desc in flags_with_desc:
                if re.search(r'\bseparator\b', desc, re.IGNORECASE):
                    if flag not in separator_flags:
                        separator_flags.append(flag)
                    if re.search(r'=\s*(STRING|REGEXP|REGEX|PATTERN|RE)\b', desc, re.IGNORECASE):
                        separator_value_flag = flag
            for sf in separator_flags:
                if sf not in regex_flags:
                    regex_flags.append(sf)
        profile["separator_flags"] = separator_flags
        profile["separator_value_flag"] = separator_value_flag
     
        if separator_flags and separator_value_flag:
            regex_flags = [separator_value_flag]
        

        for flag, desc in flags_with_desc:
            if re.search(r'^-i?regex$', flag, re.IGNORECASE):
                profile["accepts_options"] = False
                if flag not in regex_flags: regex_flags.append(flag)
                break
        
        profile["all_options"] = _filter_disallowed_flags(sorted(all_flags, key=lambda x: (0 if x.startswith("--") else 1, x)))
        profile["regex_options"] = _filter_disallowed_flags(regex_flags)
    else:
       
        _FIND_TOKEN = re.compile(r'(?<![A-Za-z0-9])-([a-z][a-z0-9_]*)\b')
        find_rx_opts = []
        for m in _FIND_TOKEN.finditer(help_text):
            tok = f"-{m.group(1)}"
            if re.search(r'^-i?regex$', tok, re.IGNORECASE) and tok not in find_rx_opts:
                find_rx_opts.append(tok)
        if find_rx_opts:
            profile["regex_options"] = find_rx_opts
            profile["all_options"] = find_rx_opts
            print(f"[profile] find-style regex options detected: {find_rx_opts}")
        else:
            profile["all_options"] = []
            profile["regex_options"] = []
        profile["separator_flags"] = []
        profile["separator_value_flag"] = None
    
    return profile

def _primary_flag(o) -> str:

    for f in o.flags:
        if re.match(r"^-[A-Za-z]$", f):
            return f
    return o.flags[0]

def _manual_synopsis_text(text: str) -> str:

    lines = text.splitlines()
    out: List[str] = []
    in_syn = False
    for raw in lines:
        s = raw.strip()
        top = _MOX_TOPSEC.match(s) if _MOX_TOPSEC else None
        if top:
            in_syn = top.group(1).strip() == "SYNOPSIS"
            continue
        if in_syn and s:
            out.append(s)
        if s.lower().startswith("usage:"):
            out.append(s)
    return "\n".join(out)

def _apply_synopsis_to_profile(profile: dict, text: str, pgm: str) -> None:

    syn = _manual_synopsis_text(text)
    if not syn.strip():
        return

   
    accepts = bool(
        re.search(r"\[[^\]]*\bOPTIONS?\b[^\]]*\]", syn, re.IGNORECASE)
        or re.search(r"\[--?[A-Za-z]", syn)
    )
    profile["accepts_options"] = accepts

    syn_lines = [ln for ln in syn.splitlines() if ln.strip()]
    usage_line = next(
        (ln for ln in syn_lines if re.search(r"(?<![\w-])" + re.escape(pgm) + r"(?![\w-])", ln)),
        syn_lines[0] if syn_lines else "",
    )
    fm = _FILE_KW_RE.search(usage_line)
    pm = _PATTERN_KW_RE.search(usage_line)
    file_pos = fm.start() if fm else None
    pat_pos = pm.start() if pm else None
    if file_pos is not None and pat_pos is not None:
        profile["arg_order"] = "file_first" if file_pos < pat_pos else "regex_first"
    elif file_pos is None and pat_pos is not None:
        profile["arg_order"] = "no_file"

    dual = bool(
        (re.search(r"\bFILE\s*1\b", syn, re.IGNORECASE)
         and re.search(r"\bFILE\s*2\b", syn, re.IGNORECASE))
        or re.search(r"\bFILES\b", syn, re.IGNORECASE)
    )
    if dual:
        profile["needs_dual_src"] = True

def _profile_from_manual_text(text: str, have_flags: Set[str], pgm: str) -> dict:

    profile = {
        "arg_order": "regex_first",
        "regex_prefix": "",
        "regex_suffix": "",
        "regex_options": [],
        "all_options": [],
        "special_syntax": None,
        "uses_slash_wrap": pgm in _MANUAL_SLASH_WRAP_PROGRAMS,
        "needs_dual_src": pgm in _MANUAL_DUAL_SRC_PROGRAMS,
        "accepts_options": True,
        "separator_flags": [],
        "separator_value_flag": None,
        "source": "manual",
    }
    if not text:
        return profile

    opts = mox.extract_options(text, weak_pattern_signal=False)

    def _exists(o) -> bool:
        
        return (not have_flags) or any(f in have_flags for f in o.flags)

    regex_opts: List[str] = []
    for o in opts:
        if o.regex_related and _exists(o):
            f = _primary_flag(o)
            if f not in regex_opts:
                regex_opts.append(f)


    separator_flags: List[str] = []
    separator_value_flag: Optional[str] = None
    co_objs = [o for o in opts if o.co_regex and _exists(o)]
    if co_objs:
        for o in co_objs:
            f = _primary_flag(o)
            if f not in separator_flags:
                separator_flags.append(f)
            if o.metavars and separator_value_flag is None:
                separator_value_flag = f
        if separator_value_flag:

            regex_opts = [separator_value_flag]

    all_opts: List[str] = []
    for o in opts:
        if _exists(o):
            f = _primary_flag(o)
            if f not in all_opts:
                all_opts.append(f)

    if pgm in _OPERAND_REGEX_PROGRAMS:
        regex_opts = []
        separator_flags = []
        separator_value_flag = None

    profile["regex_options"] = _filter_disallowed_flags(regex_opts)
    profile["all_options"] = _filter_disallowed_flags(
        sorted(all_opts, key=lambda x: (0 if x.startswith("--") else 1, x)))
    profile["separator_flags"] = separator_flags
    profile["separator_value_flag"] = separator_value_flag


    channel = mox.detect_operand_regex(text)
    chan_join = " ".join(channel)
    if (re.search(r"/\s*(?:REGEXP?|pattern|regular\s+expression)\s*/", text, re.IGNORECASE)
            or "/REGEXP/" in chan_join):
        profile["uses_slash_wrap"] = True
    if re.search(r"STRING\s*:\s*REGEXP", text, re.IGNORECASE):
        profile["special_syntax"] = "string_colon_regex"
        profile["arg_order"] = "no_file"
    if re.search(r"\bpBRE\b", text):
        profile["regex_prefix"] = "p"

  
    if profile["special_syntax"] is None:
        _apply_synopsis_to_profile(profile, text, pgm)

    findstyle = [f for f in profile["regex_options"] if re.match(r"^-i?regex$", f)]
    if findstyle:
        profile["regex_options"] = findstyle
        profile["accepts_options"] = False
        profile["arg_order"] = "file_first"

    return profile


def build_usage_profile_from_manual(manual_path, binary, pgm, mox_module):
    """Build a usage profile from a manual (cross-checked against binary --help).

    Returns None if the manual cannot be read (caller falls back to --help).
    `mox_module` is the shared manual_option_extractor module.
    """
    global mox, _MOX_TOPSEC
    mox = mox_module
    _MOX_TOPSEC = getattr(mox, "_TOPSEC", None) if mox is not None else None
    if mox is None:
        return None
    try:
        text = mox.load_text(manual_path)
    except Exception as e:
        print(f"[profile] manual load failed for {pgm} ({manual_path}): {e}")
        return None
    have = mox.binary_help_flags(binary) if binary else set()
    prof = _profile_from_manual_text(text, have, pgm)
    prof["manual_path"] = manual_path
    return prof


def parse_program_usage_profile(help_text, pgm):
    """Parse a program's --help text into a usage profile (no manual/mox needed)."""
    return _parse_program_usage_profile(help_text, pgm)
