import argparse
import os
import json
from pathlib import Path
from _shared import compose_root
import sys
import subprocess as sp


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
    'csplit': '-max-memory=4000 -allocate-determ -allocate-determ-start-address=0x0 -allocate-determ-size=4000 -search=dfs -use-forked-solver -disable-inlining -watchdog -switch-type=internal -simplify-sym-indices',
    'ptx': '-max-memory=4000 -allocate-determ -allocate-determ-start-address=0x0 -allocate-determ-size=4000 -search=dfs -use-forked-solver -disable-inlining -watchdog -switch-type=internal -simplify-sym-indices',
    'expr': '-max-memory=4000 -allocate-determ -allocate-determ-start-address=0x0 -allocate-determ-size=4000 -search=dfs -use-forked-solver -disable-inlining -watchdog -switch-type=internal -simplify-sym-indices',
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

argv = sys.argv[1:]
parser = argparse.ArgumentParser()
# Required arguments
required = parser.add_argument_group('required arguments')
required.add_argument('-t', '--time-budget', default=86400, type=int, metavar='INT',
                      help='Total time budget (sec).')
required.add_argument('-p', '--program', required=True, type=str, metavar='STR',
                      help='Name of program to replay.')

# per sub-iteration budget
parser.add_argument('--small-budget', default=120, type=int, metavar='INT',
                    help='Per-sub-iteration time in seconds (default: 120)')

parser.add_argument('--pgm-config', type=str, default=None,
                    help='pgm_config JSON (defaults to shared CompoSE/pgm_config/<prog>100.json)')
args = parser.parse_args(argv)

budget = args.time_budget
prog = args.program
small_budget = args.small_budget

# ----------------------- pgm-config load + LLVM bitcode -----------------------
pcfg = None
_pgm_cfg_path = getattr(args, "pgm_config", None)
if not _pgm_cfg_path:
    _cr = compose_root()
    if _cr:
        _cand = _cr / "pgm_config" / f"{prog}100.json"
        if _cand.exists(): _pgm_cfg_path = str(_cand)
if _pgm_cfg_path and Path(_pgm_cfg_path).exists():
    try:
        pcfg = json.loads(Path(_pgm_cfg_path).read_text(encoding="utf-8"))
        if "pgm" not in pcfg and "pgm_name" in pcfg: pcfg["pgm"] = pcfg["pgm_name"]
        for k in ("pgm","pgm_dir","gcov_path","exec_dir","src_file","sym_args"): pcfg.setdefault(k, "")
        ROOT = str(compose_root() or Path.cwd())
        for k in ("pgm_dir","gcov_path"):
            v = pcfg.get(k, "")
            if v and not os.path.isabs(v):
                for base in [ROOT, os.getcwd(), str(Path(_pgm_cfg_path).parent.parent), str(Path(_pgm_cfg_path).parent)]:
                    c = os.path.join(base, v)
                    if os.path.exists(c): pcfg[k] = c; break
        print(f"[pgm-config] loaded: pgm={pcfg['pgm']}, pgm_dir={pcfg.get('pgm_dir','')}")
    except Exception as e:
        print(f"[pgm-config] parse failed: {e}"); pcfg = None

# LLVM bitcode (.bc) for KLEE: from pgm-config (pgm_dir + exec_dir + <prog>.bc)
llvm_path = ""
if pcfg and pcfg.get("pgm_dir"):
    _ed = pcfg.get("exec_dir", "").strip("/")
    llvm_path = os.path.join(pcfg["pgm_dir"], _ed, f"{prog}.bc") if _ed else os.path.join(pcfg["pgm_dir"], f"{prog}.bc")
if not llvm_path or not os.path.isfile(llvm_path):
    print(f"[ERROR] LLVM bitcode not found: {llvm_path or '(no pgm_dir in pgm-config)'}"); sys.exit(1)

x = input("Trial?")
_exp_root = os.environ.get("AAQC_EXP_ROOT") or str(Path(__file__).resolve().parent / "experiments")
test_path = f"{_exp_root}/Aaqc{test_dir[prog]}_depth_{x}"
os.makedirs(test_path, exist_ok=True)

iter_budget = budget // 4

if prog in sym_commands.keys():
    sym_cmd = sym_commands[prog]
    flag = flags[prog]
else:
    sym_cmd = "-sym-args 0 1 10 -sym-args 0 2 2 -sym-files 1 8 -sym-stdin 8 -sym-stdout"
    flag = "-simplify-sym-indices -write-cvcs -write-cov -output-module -max-memory=1000 -disable-inlining -use-forked-solver -max-sym-array-size=4096 -max-solver-time=30s -watchdog -max-memory-inhibit=false -max-static-fork-pct=1 -max-static-solve-pct=1 -max-static-cpfork-pct=1 -switch-type=internal -search=random-path -search=nurs:covnew -use-batching-search -batch-instructions=10000"


# ── KLEE binaries live inside this tool directory (CompoSE_Aaqc/src/...) ──
_AAQC_ROOT = Path(__file__).resolve().parent
_VANILLA_KLEE = str(_AAQC_ROOT / "src" / "valina-build" / "bin" / "klee")
_QC_KLEE = str(_AAQC_ROOT / "src" / "qc-build" / "bin" / "klee")

def build_base_cmd(i):
    cache_flag = "-use-node-cache-stp -use-global-id"
    if i == 0:
        return f"{_VANILLA_KLEE} {flag} -use-cex-cache -use-branch-cache"
    elif i == 1:
        return f"{_QC_KLEE} {flag} -use-cex-cache -use-branch-cache=false -use-iso-cache {cache_flag}"
    elif i == 2:
        return f"{_QC_KLEE} {flag} -use-rebase -use-recursive-rebase -reuse-segments -use-cex-cache=false -use-branch-cache {cache_flag}"
    else:
        return f"{_QC_KLEE} {flag} -use-rebase -use-recursive-rebase -use-cex-cache=false -use-branch-cache=false -use-iso-cache {cache_flag}"

# hook to decide which flags to "append" each sub-iteration (customize freely)
def extra_flags(i, j):
    # example) vary j within the same outer iteration to change the search strategy.
    # note: if the flag string already contains -search=..., adding here only appends, does not replace.
    if (j % 3) == 0:
        return "-search=random-path -search=nurs:covnew"
    elif (j % 3) == 1:
        return "-search=dfs"
    else:
        return "-search=nurs:md2u"

for i in range(4):
    print(f"Running Iteration {i}")
    os.makedirs(f"{test_path}/iteration-{i}", exist_ok=True)

    remaining = iter_budget
    j = 0
    prev_outdir = None  # previous sub-iteration output dir (seed reuse)

    while remaining > 0:
        sub_time = min(small_budget, remaining)
        print(f"  Running Iteration {i}-{j} for {sub_time}s")

        outdir = f"{test_path}/iteration-{i}/{j}"
        other_settings = (
            f"-libc=uclibc -posix-runtime -external-calls=all "
            f"-only-output-states-covering-new -output-dir={outdir} -max-time={sub_time}"
        )

        base_cmd = build_base_cmd(i)

        # pass the previous sub-iteration's result as seed (same path/domain assumed)
        seed_flags = ""
        if prev_outdir is not None:
            seed_flags = f"--seed-dir={prev_outdir} --allow-seed-extension"

        # extra options per sub-iteration ("" if none)
        xflags = extra_flags(i, j)

        cmd = f"{base_cmd} {seed_flags} {xflags} {other_settings} {llvm_path} {sym_cmd}"
        print(cmd)
        os.system(cmd)

        prev_outdir = outdir
        remaining -= sub_time
        j += 1