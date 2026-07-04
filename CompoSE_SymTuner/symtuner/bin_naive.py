from pathlib import Path
import argparse
import json
import shutil
import sys
import os
import re
import random
from typing import List, Optional, Any, Set

from subprocess import run as _run, PIPE, STDOUT

from symtuner.klee import KLEE
from symtuner.klee import KLEESymTuner
from symtuner.logger import get_logger
from symtuner.symtuner import TimeBudgetHandler
from symtuner._shared import get_regex_mode

try:
    from symtuner._shared import compose_root as _compose_root
    _cr = _compose_root()
    _klee_bin = _cr / "CompoSE_Aaqc" / "src" / "valina-build" / "bin" if _cr else None
    _DEFAULT_KLEE = str(_klee_bin / "klee") if _klee_bin else "klee"
    _DEFAULT_KLEE_REPLAY = str(_klee_bin / "klee-replay") if _klee_bin else "klee-replay"
except Exception:
    _DEFAULT_KLEE = "klee"
    _DEFAULT_KLEE_REPLAY = "klee-replay"

_DUAL_SRC_PROGRAMS = {"diff"}


def _load_regex_sequence(search_space_path: Optional[str]) -> Optional[List[str]]:
    if not search_space_path:
        return None

    p = Path(search_space_path)
    if not p.exists():
        get_logger().debug(f'search-space file not found: {p}')
        return None

    try:
        raw = json.loads(p.read_text(encoding='utf-8'))
    except Exception as e:
        get_logger().debug(f'failed to read/parse search-space: {e}')
        return None

    space = raw.get('space') if isinstance(raw, dict) else None
    candidates: Any = None
    if isinstance(space, dict):
        candidates = space.get('-regex-options') or space.get('regex-options')
    else:
        candidates = raw.get('-regex-options') or raw.get('regex-options')

    if candidates is None:
        return None

    if isinstance(candidates, list):
        if candidates and isinstance(candidates[0], list):
            seq = candidates[0]
        else:
            seq = candidates
        seq = [str(x).strip() for x in seq if str(x).strip()]
        return seq if seq else None

    if isinstance(candidates, str):
        s = candidates.strip()
        return [s] if s else None

    return None


def _escape_single_quotes(s: str) -> str:
    return s.replace("'", "'\"'\"'")


def _derive_src_base_dir_from_pgm_dir(pgm_dir: str) -> Path:
    p = Path(pgm_dir).resolve()
    parts = list(p.parts)
    if "obj-llvm" in parts:
        idx = parts.index("obj-llvm")
        base = Path(*parts[:idx])
        return base
    return p.parent


def _build_all_files_pool(base_dir: Path) -> List[str]:
    pool: List[str] = []
    if not base_dir.exists():
        return pool
    try:
        for p in base_dir.rglob("*"):
            try:
                if p.is_file():
                    pool.append(str(p.resolve()))
            except Exception:
                continue
    except Exception:
        return pool
    return pool


def _pick_random_src_file(pool: List[str]) -> str:
    if not pool:
        return ""
    return random.choice(pool)


_RE_LONG = re.compile(r"--[A-Za-z0-9][A-Za-z0-9\-]*")
_RE_SHORT = re.compile(r"(?<!-)-[A-Za-z]\b")


def _extract_all_flags_from_help(help_text: str) -> List[str]:
    flags: Set[str] = set()
    for ln in help_text.splitlines():
        if "-" not in ln:
            continue
        for m in _RE_LONG.finditer(ln):
            flags.add(m.group(0).rstrip(",.;:)=]"))
        for m in _RE_SHORT.finditer(ln):
            flags.add(m.group(0).rstrip(",.;:)=]"))
    return sorted(flags, key=lambda x: (0 if x.startswith("--") else 1, x))


def _get_help_flag_candidates(binary_path: str) -> List[str]:
    if not binary_path or not os.path.isfile(binary_path):
        return []
    try:
        res = _run([binary_path, "--help"], stdout=PIPE, stderr=STDOUT, universal_newlines=True, check=False, timeout=10)
        txt = res.stdout or ""
        return _extract_all_flags_from_help(txt)
    except Exception:
        return []


_DISALLOWED_FLAGS = {"--debug", "--help", "--version", "-h", "-V"}


def _get_option_candidates(bin_path: str, pgm: str) -> List[str]:
    return _get_help_flag_candidates(bin_path)


def _pick_random_flag(candidates: List[str]) -> str:
    if not candidates:
        return ""
    return random.choice(candidates)


def _build_sym_option_line(pgm: str, regex: str, src_file: str, sym_args: str, extra_flag: str = "", src_file_2: str = "") -> str:
    q = _escape_single_quotes(regex.strip())
    sf = f"'{_escape_single_quotes(src_file)}'" if src_file else ""

    prefix = (extra_flag + " ") if extra_flag else ""

    if pgm in _DUAL_SRC_PROGRAMS and src_file_2:
        sf2 = f"'{_escape_single_quotes(src_file_2)}'" if src_file_2 else ""
        return f"{prefix}'{q}' {sf} {sf2}".strip()

    if pgm == 'm4':
        return f"--warn-macro-sequence='{q}' {sf}".strip()

    if pgm in ('gawk', 'sed', 'csplit'):
        return f"{prefix}'/{q}/' {sf}".strip()

    return f"{prefix}'{q}' {sf}".strip()


def _generate_regexes(n: int, mode: str, outfile: Path, regexgen_bin: str = "regexgen"):
    cmd = [regexgen_bin, "-c", str(n), "--mode", mode, "-f", str(outfile)]
    _run(cmd, check=True)


def main(argv=None):

    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser()

    executable = parser.add_argument_group('executable settings')
    executable.add_argument('--klee', default=_DEFAULT_KLEE, type=str,
                            help='Path to "klee" executable (default=klee)')
    executable.add_argument('--klee-replay', default=_DEFAULT_KLEE_REPLAY, type=str,
                            help='Path to "klee-replay" executable (default=klee-replay)')
    executable.add_argument('--gcov', default='gcov', type=str,
                            help='Path to "gcov" executable (default=gcov)')

    hyperparameters = parser.add_argument_group('hyperparameters')
    hyperparameters.add_argument('-s', '--search-space', default=None, type=str, metavar='JSON',
                                 help='Json file defining parameter search space')
    hyperparameters.add_argument('--exploit-portion', default=0.7, type=float, metavar='FLOAT',
                                 help='Portion of exploitation in SymTuner (default=0.7)')
    hyperparameters.add_argument('--step', default=20, type=int, metavar='INT',
                                 help='The number of symbolic execution runs before increasing small budget (default=20)')
    hyperparameters.add_argument('--minimum-time-portion', default=0.005, type=float, metavar='FLOAT',
                                 help='Minimum portion for one iteration (default=0.005)')
    hyperparameters.add_argument('--increase-ratio', default=2, type=float, metavar='FLOAT',
                                 help='A number that is multiplied to increase small budget. (default=2)')
    hyperparameters.add_argument('--minimum-time-budget', default=30, type=int, metavar='INT',
                                 help='Minimum time budget to perform symbolic execution (default=30)')
    hyperparameters.add_argument('--exploration-steps', default=20, type=int, metavar='INT',
                                 help='The number of symbolic execution runs that SymTuner focuses only on exploration (default=20)')

    parser.add_argument('-d', '--output-dir', default='symtuner-out', type=str,
                        help='Directory to store the generated files (default=symtuner-out)')
    parser.add_argument('--generate-search-space-json', action='store_true',
                        help='Generate the json file defining parameter spaces used in our ICSE\'22 paper')
    parser.add_argument('--debug', action='store_true',
                        help='Log the debug messages')
    parser.add_argument('--gcov-depth', default=1, type=int,
                        help='Depth to search for gcda and gcov files from gcov_obj to calculate code coverage (default=1)')

    regexcfg = parser.add_argument_group('regex & program settings (NAIVE)')
    regexcfg.add_argument('--pgm-config', default=None, type=str,
                          help='Program config JSON having fields like {"pgm": "...", "pgm_dir": "...", "sym_args": "..."}')
    regexcfg.add_argument('--regex-mode', default='ere', choices=['ere', 'bre', 'pcre'],
                          help='regexgen mode (default: ere)')
    regexcfg.add_argument('--regexgen-bin', default='regexgen', type=str,
                          help='Path to regexgen executable (default: regexgen)')
    regexcfg.add_argument('--regex-per-iter', default=1, type=int,
                          help='Number of regexes to generate per iteration (default: 1; only the first is used)')

    required = parser.add_argument_group('required arguments')
    required.add_argument('-t', '--budget', default=None, type=int, metavar='INT',
                          help='Total time budget in seconds')
    required.add_argument('llvm_bc', nargs='?', default=None,
                          help='LLVM bitecode file for klee')
    required.add_argument('gcov_obj', nargs='?', default=None,
                          help='Executable with gcov support')

    args = parser.parse_args(argv)

    if args.debug:
        get_logger().setLevel('DEBUG')

    if args.generate_search_space_json:
        space_json = KLEESymTuner.get_default_space_json()
        with Path('example-space.json').open('w') as stream:
            json.dump(space_json, stream, indent=4)
            get_logger().info('Example space configuration json is generated: example-space.json')
        sys.exit(0)

    if args.llvm_bc is None or args.gcov_obj is None or args.budget is None:
        parser.print_usage()
        print('following parameters are required: -t, llvm_bc, gcov_obj')
        sys.exit(1)

    regex_seq = _load_regex_sequence(args.search_space)
    if regex_seq:
        get_logger().info(f'Loaded {len(regex_seq)} regex-options from {args.search_space}')
    else:
        get_logger().info('No regex-options found; proceeding with NAIVE mode.')

    pgm_cfg = None
    fixed_src_file = ""
    fixed_src_file_2 = ""
    src_pool = []
    pool2 = []
    src_pool: List[str] = []
    help_flag_candidates: List[str] = []
    
    if args.pgm_config:
        cfg_path = Path(args.pgm_config)
        if not cfg_path.exists():
            get_logger().fatal(f'--pgm-config not found: {cfg_path}')
            sys.exit(1)
        try:
            pgm_cfg = json.loads(cfg_path.read_text(encoding='utf-8'))
            if 'pgm' not in pgm_cfg and 'pgm_name' in pgm_cfg:
                pgm_cfg['pgm'] = pgm_cfg['pgm_name']
            pgm_cfg.setdefault('pgm', '')
            pgm_cfg.setdefault('pgm_dir', '')
            pgm_cfg.setdefault('gcov_path', '')
            pgm_cfg.setdefault('exec_dir', '')
            pgm_cfg.setdefault('src_file', '')
            pgm_cfg.setdefault('sym_args', '')
            get_logger().info(f'Program config loaded from: {cfg_path}')
        except Exception as e:
            get_logger().fatal(f'Failed to load --pgm-config: {e}')
            sys.exit(1)

        pgm_dir = pgm_cfg.get('pgm_dir', '')
        if pgm_dir and not os.path.isabs(pgm_dir):
            possible_bases = [
                os.getcwd(),
                str(Path(args.pgm_config).parent.parent) if args.pgm_config else ''
            ]
            for base in possible_bases:
                if base:
                    candidate = os.path.join(base, pgm_dir)
                    if os.path.exists(candidate):
                        pgm_dir = candidate
                        break
        
        if pgm_dir:
            src_base_dir = _derive_src_base_dir_from_pgm_dir(pgm_dir)
            if src_base_dir.exists():
                src_pool = _build_all_files_pool(src_base_dir)
                get_logger().info(f'[NAIVE src_file] base_dir: {src_base_dir}, pooled files: {len(src_pool)}')
                if src_pool:
                    fixed_src_file = _pick_random_src_file(src_pool)
                    get_logger().info(f'[NAIVE src_file] FIXED for entire run: {fixed_src_file}')
                else:
                    fixed_src_file = pgm_cfg.get('src_file', '')
                    get_logger().warning(f'[NAIVE src_file] pool empty, fallback to config: {fixed_src_file}')
            else:
                fixed_src_file = pgm_cfg.get('src_file', '')
                get_logger().warning(f'[NAIVE src_file] base_dir not found, fallback to config: {fixed_src_file}')
        else:
            fixed_src_file = pgm_cfg.get('src_file', '')
            get_logger().warning(f'[NAIVE src_file] pgm_dir not set, using config src_file: {fixed_src_file}')

        if str(pgm_cfg.get('pgm', '')) in _DUAL_SRC_PROGRAMS:
            pool2 = [f for f in src_pool if f != fixed_src_file]
            if pool2:
                fixed_src_file_2 = _pick_random_src_file(pool2)
            elif fixed_src_file:
                fixed_src_file_2 = fixed_src_file
            else:
                fixed_src_file_2 = pgm_cfg.get('src_file', '')
            get_logger().info(f'[NAIVE src_file] dual-src 2nd FIXED for {pgm_cfg.get("pgm","")}: {fixed_src_file_2}')

        gcov_path = pgm_cfg.get('gcov_path', '')
        if gcov_path and not os.path.isabs(gcov_path):
            possible_bases = [
                os.getcwd(),
                str(Path(args.pgm_config).parent.parent) if args.pgm_config else ''
            ]
            for base in possible_bases:
                if base:
                    candidate = os.path.join(base, gcov_path)
                    if os.path.exists(candidate):
                        gcov_path = candidate
                        break
        
        exec_dir = pgm_cfg.get('exec_dir', '').strip('/')
        pgm_name = pgm_cfg.get('pgm', '')
        args.regex_mode = get_regex_mode(pgm_name, default=args.regex_mode)
        get_logger().info(f'[regex_mode] {pgm_name} -> {args.regex_mode}')
        
        binary_candidates = []
        if gcov_path:
            if exec_dir:
                binary_candidates.append(os.path.join(gcov_path, exec_dir, pgm_name))
            binary_candidates.append(os.path.join(gcov_path, 'src', pgm_name))
            binary_candidates.append(os.path.join(gcov_path, pgm_name))
        if args.gcov_obj:
            binary_candidates.append(args.gcov_obj)
        
        for bin_path in binary_candidates:
            if bin_path and os.path.isfile(bin_path) and os.access(bin_path, os.X_OK):
                help_flag_candidates = _get_option_candidates(bin_path, pgm_name)
                if help_flag_candidates:
                    get_logger().info(f'[NAIVE option] Found {len(help_flag_candidates)} flags from --help of {bin_path}')
                    get_logger().debug(f'[NAIVE option] Flags sample: {help_flag_candidates[:10]}')
                    break
        
        if not help_flag_candidates:
            get_logger().warning('[NAIVE option] No flags found from --help; will use no extra flag.')

    output_dir = Path(args.output_dir)
    if output_dir.exists():
        shutil.rmtree(str(output_dir))
        get_logger().warning('Existing output directory is deleted: '
                             f'{output_dir}')
    output_dir.mkdir(parents=True)
    coverage_csv = output_dir / 'coverage.csv'
    coverage_csv.touch()
    get_logger().info(
        f'Coverage will be recoreded at "{coverage_csv}" at every iteration.')
    found_bugs_txt = output_dir / 'found_bugs.txt'
    found_bugs_txt.touch()
    get_logger().info(
        f'Found bugs will be recoreded at "{found_bugs_txt}" at every iteration.')

    regex_dir = output_dir / 'regex'
    regex_dir.mkdir(parents=True, exist_ok=True)

    symbolic_executor = KLEE(args.klee)

    symtuner = KLEESymTuner(args.klee_replay, args.gcov, 10,
                            args.search_space, args.exploit_portion)
    evaluation_argument = {'folder_depth': args.gcov_depth}

    get_logger().info('All configuration loaded. Start testing (NAIVE mode).')
    time_budget_handler = TimeBudgetHandler(args.budget, args.minimum_time_portion,
                                            args.step, args.increase_ratio,
                                            args.minimum_time_budget)
    for i, time_budget in enumerate(time_budget_handler):

        iteration_dir = output_dir / f'iteration-{i}'

        policy = 'explore' if i < args.exploration_steps else None
        parameters = symtuner.sample(policy=policy)

        if pgm_cfg:
            regex_txt = regex_dir / f'iteration-{i}.txt'
            try:
                _generate_regexes(args.regex_per_iter, args.regex_mode, regex_txt, args.regexgen_bin)
            except Exception as e:
                get_logger().fatal(f'Failed to run regexgen: {e}')
                sys.exit(1)

            try:
                regexes = [ln.strip() for ln in regex_txt.read_text(encoding='utf-8').splitlines() if ln.strip()]
            except Exception as e:
                get_logger().fatal(f'Failed to read generated regex file: {e}')
                sys.exit(1)

            if not regexes:
                get_logger().fatal('regexgen produced no regex.')
                sys.exit(1)

            chosen_regex = regexes[0]
            
            extra_flag = _pick_random_flag(help_flag_candidates)

            cur_src = _pick_random_src_file(src_pool) if src_pool else fixed_src_file
            cur_src_2 = _pick_random_src_file(pool2) if pool2 else fixed_src_file_2

            sym_line = _build_sym_option_line(
                str(pgm_cfg.get('pgm', '')),
                chosen_regex,
                cur_src,  
                str(pgm_cfg.get('sym_args', '')),
                extra_flag,  
                cur_src_2
            ).strip()


            parameters['-regex-options'] = [sym_line]

            snap = {
                'iteration': i,
                'pgm': pgm_cfg.get('pgm', ''),
                'src_file_fixed': fixed_src_file,
                'sym_args': pgm_cfg.get('sym_args', ''),
                'regex_mode': args.regex_mode,
                'regex_used': chosen_regex,
                'extra_flag': extra_flag,
                'assembled_line': sym_line,
                'naive_mode': True
            }
            try:
                (regex_dir / f'iteration-{i}.json').write_text(
                    json.dumps(snap, ensure_ascii=False, indent=2),
                    encoding='utf-8'
                )
            except Exception:
                pass
            
            get_logger().debug(f'[iter {i}] regex={chosen_regex}, flag={extra_flag}, src={fixed_src_file}')

        elif regex_seq:
            chosen = regex_seq[i % len(regex_seq)]
            parameters['-regex-options'] = [chosen]

        parameters[symbolic_executor.get_time_parameter()] = time_budget
        parameters['-output-dir'] = str(iteration_dir)
        testcases = symbolic_executor.run(args.llvm_bc, parameters)

        parameters_for_symtuner = {k: v for k, v in parameters.items() 
                                   if k not in ['-regex-options', '--regex-options']}
        symtuner.add(args.gcov_obj, parameters_for_symtuner, testcases, evaluation_argument)

        elapsed = time_budget_handler.elapsed
        coverage, bugs = symtuner.get_coverage_and_bugs()
        get_logger().info(f'Iteration: {i + 1} '
                          f'Time budget: {time_budget} '
                          f'Time elapsed: {elapsed} '
                          f'Coverage: {len(coverage)} '
                          f'Bugs: {len(bugs)}')
        with coverage_csv.open('a') as stream:
            stream.write(f'{elapsed}, {len(coverage)}\n')
        with found_bugs_txt.open('w') as stream:
            stream.writelines((f'Testcase: {Path(symtuner.get_testcase_causing_bug(bug)).absolute()} '
                               f'Bug: {bug}\n' for bug in bugs))

    coverage, bugs = symtuner.get_coverage_and_bugs()
    get_logger().info(f'SymTuner done. Achieve {len(coverage)} coverage '
                      f'and found {len(bugs)} bugs.')


if __name__ == '__main__':
    main()