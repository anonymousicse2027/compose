import os
import importlib.util
from pathlib import Path
from typing import Optional

_ROOT_CACHE = None
_MOX_CACHE = None
_RMT_CACHE = None


def compose_root() -> Optional[Path]:
    global _ROOT_CACHE
    if _ROOT_CACHE is not None:
        return _ROOT_CACHE or None

    def _has_shared(d: Path) -> bool:
        return (d / "manual_option_extractor.py").is_file() and (d / "manuals").is_dir()

    candidates = []
    env = os.environ.get("COMPOSE_ROOT")
    if env:
        candidates.append(Path(env))
    candidates += list(Path(__file__).resolve().parents)
    candidates += [Path.cwd()] + list(Path.cwd().parents)

    for c in candidates:
        try:
            if _has_shared(c):
                _ROOT_CACHE = c
                return c
        except Exception:
            continue
    _ROOT_CACHE = False
    return None


def _load_from_root(filename: str, module_name: str):
    root = compose_root()
    if root is None:
        return None
    path = root / filename
    if not path.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location(module_name, str(path))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        return None


def load_mox():
    global _MOX_CACHE
    if _MOX_CACHE is not None:
        return _MOX_CACHE or None
    mod = _load_from_root("manual_option_extractor.py", "manual_option_extractor")
    _MOX_CACHE = mod or False
    return mod


def manuals_dir() -> Optional[Path]:
    root = compose_root()
    return (root / "manuals") if root else None


def manual_path(pgm: str) -> Optional[str]:
    d = manuals_dir()
    if not d:
        return None
    p = d / f"{pgm}.pdf"
    return str(p) if p.exists() else None


def get_regex_mode(pgm: str, default: str = "ere") -> str:
    global _RMT_CACHE
    if _RMT_CACHE is None:
        _RMT_CACHE = _load_from_root("regex_mode_table.py", "regex_mode_table") or False
    if not _RMT_CACHE:
        return default
    try:
        return _RMT_CACHE.get_regex_mode(pgm, default)
    except Exception:
        return default


_MP_CACHE = None


def load_manual_profile():
    global _MP_CACHE
    if _MP_CACHE is None:
        _MP_CACHE = _load_from_root("manual_profile.py", "manual_profile") or False
    return _MP_CACHE or None


def build_profile(manual_path, binary, pgm):
    mp = load_manual_profile()
    if mp is None:
        return None
    return mp.build_usage_profile_from_manual(manual_path, binary, pgm, load_mox())


def parse_help_profile(help_text, pgm):
    mp = load_manual_profile()
    if mp is None:
        return None
    return mp.parse_program_usage_profile(help_text, pgm)