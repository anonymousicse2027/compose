#!/usr/bin/env python3
import os, re, sys, json, time, math, random, uuid, hashlib, pickle, shutil
import subprocess
from subprocess import run
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple, Union
from collections import Counter
from dataclasses import dataclass, asdict

__all__ = [
    'ROOT',
    'SAMPLE_REGEX',
    '_MANUAL_SLASH_WRAP_PROGRAMS',
    '_MANUAL_DUAL_SRC_PROGRAMS',
    '_regex_compiles_with_grep',
    'escape_single_quotes',
    '_escape_regex_delim_slash',
    'make_abs'
]

ROOT = os.path.abspath(os.getcwd())

SAMPLE_REGEX = "[a-z]"

_MANUAL_SLASH_WRAP_PROGRAMS = {"csplit", "gawk", "sed"}  

_MANUAL_DUAL_SRC_PROGRAMS = {"diff"}  

def _regex_compiles_with_grep(pattern: str, regex_mode: str) -> bool:
    mode = (regex_mode or "").lower().strip()
    if mode == "ere":
        cmd = ["grep", "-E", "--", pattern]
    else:
        cmd = ["grep", "-G", "--", pattern]

    try:
        p = subprocess.run(
            cmd,
            input="",
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return p.returncode != 2
    except Exception:
        return False

def escape_single_quotes(s: str) -> str:
    return s.replace("'", "'\"'\"'")

def _escape_regex_delim_slash(p: str) -> str:
    return p.replace('/', r'\/')

def make_abs(path_str: str) -> str:
    if not path_str:
        return path_str
    return path_str if os.path.isabs(path_str) else os.path.abspath(os.path.join(ROOT, path_str))
