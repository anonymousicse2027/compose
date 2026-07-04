#!/usr/bin/env python3
import os
import time
import shlex
import subprocess
from pathlib import Path

_FM_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # CompoSE_FeatMaker/

# --------- global configs ---------
ROOT = os.path.abspath(os.getcwd())
configs = {
    "root_dir": ROOT,
    "klee_build_dir": os.path.join(_FM_ROOT, "klee", "build"),
}

search_options = {
    "batching": ["--use-batching-search", "--batch-instructions=10000"],
    "branching": ["--use-branching-search"],
}


def build_search_flags(top_dir: str, iteration: int, weight_idx: int):
    """
    iteration == 0  -> two explicit strategies
    else            -> auto strategy with feature/weight files
    Returns a list of --search / --feature / --weight flags.
    """
    if iteration == 0:
        return ["--search=random-path", "--search=nurs:covnew"]
    return [
        "--search=auto",
        f"--feature={top_dir}/features/{iteration}.f",
        f"--weight={top_dir}/weight/iteration-{iteration}/{weight_idx}.w",
    ]


class klee_executor:
    def __init__(self, pconfig, top_dir, options):
        self.pconfig = pconfig
        self.pgm = pconfig["pgm_name"]
        self.top_dir = top_dir
        self.n_scores = options.n_scores
        self.small_time = options.small_time
        self.main_option = options.main_option
        self.seed_dirs_map = pconfig.get("seed_dirs_map") or []
        self.extra_klee_args = pconfig.get("extra_klee_args") or []

        # make absolute
        self.bin_dir = os.path.join(_FM_ROOT, "klee", "build", "bin")
        exec_dir = pconfig.get("exec_dir", "").lstrip("/")
        self.llvm_dir = os.path.join(self.top_dir, "obj-llvm", exec_dir)

        self.slice_counter = 0  # round-robin index

    def gen_run_cmd(self, iteration, weight_idx, klee_max_time, seed_dirs=None):
        symbolic_args = self.pconfig["sym_options"]

        # choose search option preset
        search_key = "batching"
        if self.pgm in ["find", "sqlite3"]:
            search_key = "branching"

        args = [
            os.path.join(self.bin_dir, "klee"),
            "-only-output-states-covering-new",
            "--simplify-sym-indices",
            "--output-module=false",
            "--output-source=false",
            "--output-stats=false",
            "--disable-inlining",
            "--write-kqueries",
            "--optimize",
            "--use-forked-solver",
            "--use-cex-cache",
            "--libc=uclibc",
            "--ignore-solver-failures",
            "--posix-runtime",
            f"-env-file={os.path.join(_FM_ROOT, 'klee', 'test.env')}",
            "--max-sym-array-size=4096",
            "--max-memory-inhibit=false",
            "--switch-type=internal",
            *search_options[search_key],
            "--watchdog",
            f"--max-time={klee_max_time}",
            *build_search_flags(self.top_dir, iteration, weight_idx),
        ]


        if seed_dirs:
            for sd in seed_dirs:
                args.append(f"--seed-dir={sd}")

        # ── Constraint-based state pruning + any extra KLEE args ──
        if self.extra_klee_args:
            args.extend(self.extra_klee_args)

        args.extend([
            f"--output-dir={self.top_dir}/result/iteration-{iteration}/{weight_idx}",
            f"{self.pgm}.bc",
        ])
        # split user symbolic args safely
        args.extend(shlex.split(symbolic_args))
        return args

    def execute_klee(self, iteration, t):
        print("Execute KLEE in iteration", iteration)
        remaining_time = t

        old_cwd = os.getcwd()
        try:
            os.chdir(self.llvm_dir)

            sym_list = self.pconfig.get(
                "sym_options_list",
                [self.pconfig.get("sym_options", "")]
            ) or [""]

            # Refresh extra_klee_args from pconfig (may change per iteration)
            self.extra_klee_args = self.pconfig.get("extra_klee_args") or []
        

            for weight_idx in range(self.n_scores):
                if remaining_time <= 0:
                    break

                idx = self.slice_counter
                current_sym = sym_list[idx % len(sym_list)]
                self.pconfig["sym_options"] = current_sym
                self.slice_counter += 1


                klee_start = time.time()
                seed_dirs = []
                if weight_idx < len(self.seed_dirs_map):
                    raw_seeds = self.seed_dirs_map[weight_idx] or []
                    seed_dirs = [str(Path(sd)) for sd in raw_seeds if Path(sd).exists()]
                cmd = self.gen_run_cmd(
                    iteration,
                    weight_idx,
                    min(remaining_time, self.small_time),
                    seed_dirs=seed_dirs,
                )

                try:
                    with open(os.devnull, "w") as devnull:
                        subprocess.run(cmd, stdout=devnull, stderr=devnull, check=False)
                except Exception as e:
                    print(f"[WARN] KLEE run failed at weight_idx={weight_idx}: {e}")

                remaining_time -= int(time.time() - klee_start)

        finally:
            os.chdir(old_cwd)

        # record ktest timestamps (best-effort)
        ts_out = Path(self.top_dir) / f"result/iteration-{iteration}/time_result"
        try:
            subprocess.run(
                [
                    "bash",
                    "-c",
                    (
                        f"ls -l --time-style=full-iso "
                        f"{self.top_dir}/result/iteration-{iteration}/*/*.ktest "
                        f"> {ts_out} 2>/dev/null"
                    ),
                ],
                check=False,
            )
        except Exception as e:
            print(f"[WARN] time_result generation failed: {e}")