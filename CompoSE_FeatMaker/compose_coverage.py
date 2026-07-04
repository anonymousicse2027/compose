#!/usr/bin/env python3
import os, re, sys, json, time, math, random, uuid, hashlib, pickle, shutil
import subprocess
from subprocess import run
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple, Union
from collections import Counter
from dataclasses import dataclass, asdict

__all__ = [
    '_parse_branch_keys_from_ktest_gcov',
    '_covered_set_in_idx_dir',
    '_covered_sets_for_iteration',
    '_freq_cum_path',
    '_atomic_write_text',
    '_load_freq_cum',
    '_save_freq_cum',
    '_src_score_path',
    '_option_score_path',
    '_load_score_map',
    '_save_score_map',
    '_score_from_freq_map',
    '_score_snapshot_path',
    '_load_iteration_score_snapshot',
    '_save_iteration_score_snapshot',
    'SeedCache',
    '_regex_data_path_for_ktest',
    '_parse_regex_data_file',
    '_classify_regex_tier',
    '_filter_and_rank_seed_candidates',
    '_ktest_path_for_gcov',
    '_store_best_seed_ktests',
    '_purge_iteration_ktest_gcov'
]

def _parse_branch_keys_from_ktest_gcov(gcov_path: Path) -> Set[str]:
    covered_branch: Set[str] = set()
    try:
        with open(gcov_path, 'r', errors='ignore') as f:
            content = f.read()
        parts = content.split('        -:    0:Source')[1:]
        for part in parts:
            s = part.split('\n')
            if not s: continue
            src_name = s[0].split('/')[-1]
            if src_name == 'signal.c': continue  
            line_number = 0
            code_line_start = 1
            while code_line_start < len(s) and "0:" in s[code_line_start]:
                code_line_start += 1
            for l in s[code_line_start:]:
                if ":" in l:
                    line_number += 1
                    continue
                if 'taken' in l:
                    tmp = l.split()
                    if len(tmp) >= 4 and tmp[3] != '0%':
                        covered_branch.add(f"{src_name}_{line_number}_{tmp[1]}")
    except Exception:
        pass
    return covered_branch

def _covered_set_in_idx_dir(idx_dir: Path) -> Set[str]:
    covered: Set[str] = set()
    if not idx_dir.exists():
        return covered
    for p in idx_dir.glob("*.ktest_gcov"):
        covered |= _parse_branch_keys_from_ktest_gcov(p)
    return covered

def _covered_sets_for_iteration(top_dir: str, iter_no: int, n_scores: int) -> List[Set[str]]:
    if iter_no < 0:
        return [set() for _ in range(n_scores)]
    it_dir = Path(top_dir) / f"result/iteration-{iter_no}"
    covered_sets: List[Set[str]] = []
    for idx in range(n_scores):
        kdir = it_dir / f"{idx}"
        covered_sets.append(_covered_set_in_idx_dir(kdir))
    return covered_sets

def _freq_cum_path(regex_dir: Path) -> Path:
    return regex_dir / "freq_cum.json"

def _atomic_write_text(path: Path, text: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)

def _load_freq_cum(regex_dir: Path) -> Counter:
    p = _freq_cum_path(regex_dir)
    if not p.exists():
        return Counter()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return Counter({k: int(v) for k, v in data.items()})
    except Exception:
        pass
    return Counter()

def _save_freq_cum(regex_dir: Path, freq: Counter) -> None:
    payload = {k: int(v) for k, v in freq.items()}
    _atomic_write_text(_freq_cum_path(regex_dir), json.dumps(payload, ensure_ascii=False, indent=2))

def _src_score_path(regex_dir: Path) -> Path:
    return regex_dir / "src_file_scores.json"

def _option_score_path(regex_dir: Path) -> Path:
    return regex_dir / "option_scores.json"

def _load_score_map(path: Path) -> Dict[str, float]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return {str(k): float(v) for k, v in data.items()}
    except Exception:
        pass
    return {}

def _save_score_map(path: Path, score_map: Dict[str, float]) -> None:
    payload = {k: float(v) for k, v in score_map.items()}
    _atomic_write_text(path, json.dumps(payload, ensure_ascii=False, indent=2))

def _score_from_freq_map(covered_sets: List[Set[str]], freq_map: Counter) -> List[float]:
    scores: List[float] = []
    for s in covered_sets:
        scr = 0.0
        for b in s:
            fb = int(freq_map.get(b, 0))
            scr += 1.0 / math.sqrt(fb + 1.0)
        scores.append(scr)
    return scores

def _score_snapshot_path(regex_dir: Path, iteration: int) -> Path:
    return regex_dir / f"iteration-{iteration}.freq_scores.json"

def _load_iteration_score_snapshot(regex_dir: Path, iteration: int, n_scores: int) -> List[float]:
    snap = _score_snapshot_path(regex_dir, iteration)
    if not snap.exists():
        return []
    try:
        data = json.loads(snap.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return [float(data.get(str(i), 0.0)) for i in range(n_scores)]
        if isinstance(data, list):
            arr = [float(x) for x in data]
            if len(arr) < n_scores:
                arr += [0.0] * (n_scores - len(arr))
            return arr[:n_scores]
    except Exception:
        pass
    return []

def _save_iteration_score_snapshot(regex_dir: Path, iteration: int, scores_now: List[float]) -> None:
    snap = _score_snapshot_path(regex_dir, iteration)
    payload = {str(i): float(scores_now[i]) for i in range(len(scores_now))}
    _atomic_write_text(snap, json.dumps(payload, ensure_ascii=False, indent=2))

class SeedCache:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.index_path = self.root / "seed_index.json"
        self.index = self._load()

    def _load(self) -> dict:
        try:
            return json.loads(self.index_path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _save(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        _atomic_write_text(self.index_path, json.dumps(self.index, ensure_ascii=False, indent=2))

    @staticmethod
    def _normalize_regex(regex: str) -> str:
        return re.sub(r"\s+", "", regex.strip())

    @staticmethod
    def _similarity(a: str, b: str) -> float:
        if not a and not b:
            return 1.0
        if not a or not b:
            return 0.0
        la, lb = len(a), len(b)
        prev = [0] * (lb + 1)
        longest = 0
        for i in range(1, la + 1):
            cur = [0] * (lb + 1)
            ai = a[i - 1]
            for j in range(1, lb + 1):
                if ai == b[j - 1]:
                    v = prev[j - 1] + 1
                    cur[j] = v
                    if v > longest:
                        longest = v
            prev = cur
        return (2.0 * longest) / (la + lb)

    @staticmethod
    def _tokenize(regex: str) -> Set[str]:
        tokens = re.findall(r"\\.|\w+|\W", regex)
        return {t for t in tokens if t.strip()}

    @staticmethod
    def _hash_regex(regex: str) -> str:
        return hashlib.sha1(regex.encode("utf-8", "ignore")).hexdigest()[:12]

    def prepare_seed_dir(self, regex: str, iteration: int, idx: int) -> Path:
        key = self._normalize_regex(regex)
        hashed = self.index.get(key, {}).get("hash") or self._hash_regex(key)
        seed_dir = self.root / hashed / f"iter-{iteration}-idx-{idx}"
        seed_dir.mkdir(parents=True, exist_ok=True)
        return seed_dir

    def add_entry(self, regex: str, iteration: int, idx: int, seed_dir: Path, score: float, files: List[str]) -> None:
        key = self._normalize_regex(regex)
        tokens = sorted(self._tokenize(key))
        rec = self.index.setdefault(key, {"hash": self._hash_regex(key), "entries": []})
        rec.setdefault("pattern", regex)
        rec["tokens"] = tokens
        rel_dir = os.path.relpath(seed_dir, self.root)
        rec.setdefault("hash", self._hash_regex(key))
        rec.setdefault("entries", [])
        rec["entries"].append({
            "iteration": iteration,
            "idx": idx,
            "score": float(score),
            "seed_dir": rel_dir,
            "files": sorted(list(files)),
        })
        self._save()

    def find(self, regex: str) -> List[str]:
        target = self._normalize_regex(regex)
        target_tokens = self._tokenize(target)

        best_sim = 0.0
        best_rec = None

        for stored_key, rec in self.index.items():
            stored_pattern = rec.get("pattern", stored_key)
            key_norm = self._normalize_regex(stored_pattern)
            sim = 1.0 if key_norm == target else self._similarity(target, key_norm)
            if sim > best_sim:
                best_sim = sim
                best_rec = rec

        if not best_rec or best_sim <= 0.0:
            return []

        entries = sorted(best_rec.get("entries", []), key=lambda e: float(e.get("score", 0.0)), reverse=True)
        if not entries:
            return []

        non_fallback_entries = []
        fallback_entries = []
        for entry in entries:
            sd = self.root / entry.get("seed_dir", "")
            if not sd.exists():
                continue
            meta_path = sd / "regex_seed_meta.json"
            if not meta_path.exists():
                meta_path = sd / "constraint_meta.json"
            is_fb = False
            if meta_path.exists():
                try:
                    meta = json.loads(meta_path.read_text())
                    is_fb = meta.get("is_fallback", False)
                except Exception:
                    pass
            if is_fb:
                fallback_entries.append(entry)
            else:
                non_fallback_entries.append(entry)

        chosen_entry = None
        if non_fallback_entries:
            chosen_entry = non_fallback_entries[0]  
        elif fallback_entries:
            chosen_entry = fallback_entries[0]
        else:
            chosen_entry = entries[0]

        sd = self.root / chosen_entry.get("seed_dir", "")
        return [str(sd)] if sd.exists() else []

def _regex_data_path_for_ktest(ktest_path: Path) -> Optional[Path]:
    """Return the .regex_data path corresponding to a ktest file."""
    name = ktest_path.name
    if name.endswith(".ktest"):
        rd_name = name[:-len(".ktest")] + ".regex_data"
        candidate = ktest_path.with_name(rd_name)
        if candidate.exists():
            return candidate
    return None

def _parse_regex_data_file(rd_path: Path) -> Optional[dict]:
    """
    Parse the .regex_data file and return the regex-reached flags.
    Format:
        regex_compile_reached=true/false
        regex_match_reached=true/false
        regex_functions=func1,func2,...
    """
    try:
        text = rd_path.read_text(encoding="utf-8", errors="replace").strip()
        if not text:
            return None

        result = {
            "regex_compile_reached": False,
            "regex_match_reached": False,
            "regex_functions": [],
        }

        for line in text.split("\n"):
            stripped = line.strip()
            if stripped.startswith("regex_compile_reached="):
                result["regex_compile_reached"] = stripped.endswith("true")
            elif stripped.startswith("regex_match_reached="):
                result["regex_match_reached"] = stripped.endswith("true")
            elif stripped.startswith("regex_functions="):
                funcs_str = stripped[len("regex_functions="):]
                if funcs_str:
                    result["regex_functions"] = [f.strip() for f in funcs_str.split(",") if f.strip()]

        return result
    except Exception:
        return None

def _classify_regex_tier(rd_data: dict) -> int:
    """
    Classify based on the regex-reached flags in the .regex_data file.
    Returns: 1 (regex compile or match reached), -1 (no regex reached)
    """
    regex_compile = rd_data.get("regex_compile_reached", False)
    regex_match = rd_data.get("regex_match_reached", False)

    if regex_compile or regex_match:
        return 1

    
    return -1

def _filter_and_rank_seed_candidates(
    candidates: List[Tuple[float, Path, Path]],  
    ktest_dir: Path,
    filter_regex: bool = True,
) -> Tuple[List[Tuple[float, Path, Path, int]], bool]:
    if not filter_regex:
        all_ranked = [(score, gcov_path, ktest_path, 3) for score, gcov_path, ktest_path in candidates]
        all_ranked.sort(key=lambda t: t[0], reverse=True)
        return all_ranked, False

    good_candidates = []  
    bad_candidates = []    

    for score, gcov_path, ktest_path in candidates:
        rd_path = _regex_data_path_for_ktest(ktest_path)

        if rd_path is None:
            tier = 3
        else:
            rd_data = _parse_regex_data_file(rd_path)
            if rd_data is None:
                tier = 3
            else:
                tier = _classify_regex_tier(rd_data)

        if tier == -1:
            bad_candidates.append((score, gcov_path, ktest_path, tier))
        else:
            good_candidates.append((score, gcov_path, ktest_path, tier))

    
    if good_candidates:
        good_candidates.sort(key=lambda t: t[0], reverse=True)
        return good_candidates, False

    return [], False

def _ktest_path_for_gcov(gcov_path: Path) -> Optional[Path]:
    name = gcov_path.name
    if name.endswith(".ktest_gcov"):
        base = name[:-len("_gcov")]
        candidate = gcov_path.with_name(base)
        if candidate.exists():
            return candidate
    return None

def _store_best_seed_ktests(top_dir: str, iteration: int, regexes: List[str], freq_map: Counter, cache: SeedCache, filter_regex: bool = True) -> None:
    it_dir = Path(top_dir) / f"result/iteration-{iteration}"
    if not it_dir.exists():
        return

    iter_stats = {"total": 0, "filtered": 0, "tier1": 0, "tier2": 0, "tier3": 0, "fallback": 0, "no_const": 0}

    for idx, regex in enumerate(regexes):
        kdir = it_dir / f"{idx}"
        if not kdir.exists():
            continue

        all_candidates: List[Tuple[float, Path, Path]] = []

        for gcov in kdir.glob("*.ktest_gcov"):
            covered = _parse_branch_keys_from_ktest_gcov(gcov)
            ktest_path = _ktest_path_for_gcov(gcov)
            if not covered or not ktest_path:
                continue
            score = _score_from_freq_map([covered], freq_map)[0]
            all_candidates.append((score, gcov, ktest_path))

        if not all_candidates:
            continue

        iter_stats["total"] += len(all_candidates)

        ranked, is_fallback = _filter_and_rank_seed_candidates(all_candidates, kdir, filter_regex=filter_regex)

        if not ranked:
            continue

        good = [(s, gp, kp, t) for s, gp, kp, t in ranked if t != -1]
        if not good:
            iter_stats["fallback"] += 1
            continue

        chosen = random.choice(good)
        chosen_score, chosen_gcov, chosen_ktest, chosen_tier = chosen

        if is_fallback:
            iter_stats["fallback"] += 1
        for _, _, kp, t in ranked:
            if t == -1:
                iter_stats["filtered"] += 1
            elif t == 1:
                iter_stats["tier1"] += 1
            elif t == 2:
                iter_stats["tier2"] += 1
            elif t == 3:
                iter_stats["tier3"] += 1
        for _, _, kp, t in ranked:
            rd_p = _regex_data_path_for_ktest(kp)
            if rd_p is None:
                iter_stats["no_const"] += 1
                break

        seed_dir = cache.prepare_seed_dir(regex, iteration, idx)
        copied: List[str] = []
        copied_tiers: List[int] = []

        try:
            shutil.copy2(chosen_ktest, seed_dir / chosen_ktest.name)
            copied.append(chosen_ktest.name)
            copied_tiers.append(chosen_tier)
        except Exception:
            continue
        try:
            rd_path = _regex_data_path_for_ktest(chosen_ktest)
            if rd_path and rd_path.exists():
                shutil.copy2(rd_path, seed_dir / rd_path.name)
        except Exception:
            pass

        if copied:
            avg_score = chosen_score

            tier_label = f"tier{copied_tiers[0]}" if copied_tiers else "unknown"
            if is_fallback:
                tier_label = f"FALLBACK(tier{copied_tiers[0]})" if copied_tiers else "FALLBACK"
                print(f"  [regex-seed] idx={idx} *** FALLBACK *** all {len(all_candidates)} candidates "
                      f"never reached regex functions, using best-coverage as fallback")

            cache.add_entry(regex, iteration, idx, seed_dir, avg_score, copied)

            meta = {
                "iteration": iteration, "idx": idx,
                "is_fallback": is_fallback,
                "tier_label": tier_label,
                "tiers": copied_tiers,
                "n_total_candidates": len(all_candidates),
                "n_no_regex_reached": sum(1 for _, _, _, t in ranked if t == -1) if is_fallback else
                                      len(all_candidates) - len(ranked),
                "n_good": len(ranked) if not is_fallback else 0,
                "copied_files": copied,
            }
            try:
                meta_path = seed_dir / "regex_seed_meta.json"
                meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2))
            except Exception:
                pass

    if iter_stats["total"] > 0:
        print(f"[regex-seed] iteration-{iteration} stats: "
              f"total={iter_stats['total']} "
              f"no_regex_reached={iter_stats['filtered']} "
              f"tier1_match={iter_stats['tier1']} tier2_compile={iter_stats['tier2']} tier3_unknown={iter_stats['tier3']} "
              f"fallback_regexes={iter_stats['fallback']} "
              f"no_const={iter_stats['no_const']}")

def _purge_iteration_ktest_gcov(top_dir: str, iter_no: int) -> int:
    it_dir = Path(top_dir) / f"result/iteration-{iter_no}"
    removed = 0
    if it_dir.exists():
        for p in it_dir.rglob("*.ktest_gcov"):
            try:
                p.unlink(); removed += 1
            except Exception:
                pass
    print(f"[cleanup] removed {removed} '*.ktest_gcov' in iteration-{iter_no}")
    return removed