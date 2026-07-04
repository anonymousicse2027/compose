# CompoSE

**CompoSE** drives symbolic execution deeper into the regular-expression handling code of
GNU programs by *adaptively synthesizing* increasingly effective regular expressions for the
program under test, guided by the branches they reach inside the program's regex engine.

CompoSE is built on top of three symbolic-execution baselines. For each baseline we provide
three variants:

| Variant | Description |
| ------- | ----------- |
| **Base** | The original tool, unmodified. |
| **+Naive** | Baseline + randomly generated regexes (no adaptation). |
| **+CompoSE** | Baseline + adaptive regex synthesis (our approach). |

The three baselines are **FeatMaker**, **SymTuner**, and **AAQC**.

---

## Repository Structure

```
CompoSE/
├── build.sh                     Benchmark builder (12 GNU programs)
├── pgm_config/                  Shared per-program configuration (grep100.json ... nl100.json)
├── manual_option_extractor.py   Extracts regex-related CLI options from program manuals
├── manuals/                     Program manuals (PDF) used by the extractor
├── regex_mode_table.py          Per-program regex dialect table (BRE / ERE)
│
├── CompoSE_FeatMaker/           Baseline 1: FeatMaker
│   ├── run_featmaker.py                    Base
│   ├── run_compose_naive_featmaker.py      +Naive
│   ├── run_compose_featmaker.py            +CompoSE
│   ├── featmaker_subscript/                KLEE execution / coverage / feature helpers
│   ├── klee/                               FeatMaker's KLEE (build here; git-ignored)
│   └── test.env                            Environment file for KLEE's POSIX runtime
│
├── CompoSE_SymTuner/            Baseline 2: SymTuner
│   └── symtuner/
│       ├── bin.py                          Base
│       ├── bin_naive.py                    +Naive
│       ├── bin_compose.py                  +CompoSE
│       └── compose_*.py                    Adaptive profiling / selection modules
│
├── CompoSE_Aaqc/               Baseline 3: AAQC
│   ├── run_aaqc.py                         Base
│   ├── run_aaqc_naive.py                   +Naive
│   ├── run_aaqc_compose.py                 +CompoSE
│   ├── compose_*.py                        Adaptive profiling / selection modules
│   └── src/                                AAQC's KLEE (valina-build / qc-build; git-ignored)
│
├── sniffles/                    Regex generator (regexgen); a modified Petabi Sniffles
└── benchmarks/                  Target programs, produced by build.sh (git-ignored)
```

> **Note.** `benchmarks/`, the KLEE build trees (`klee/build`, `src/valina-build`,
> `src/qc-build`), Python virtual environments, and experiment outputs are **not** committed.
> They are produced locally by the steps below.

---

## Installation

We provide a `Dockerfile` that builds everything from scratch: the three KLEE variants,
the `regexgen` regex generator, and all 12 benchmark programs. This is the recommended
way to obtain a working environment.

```bash
# from the CompoSE root (the directory containing this README)
docker build -t compose .
docker run -it compose /bin/bash
```

The image is based on Ubuntu 18.04 with LLVM/Clang 6.0, and the build performs the
following steps automatically:

1. Build **FeatMaker's KLEE** → `CompoSE_FeatMaker/klee/build`, and generate its
   POSIX-runtime environment file `test.env`.
2. Build **AAQC's KLEE** → `CompoSE_Aaqc/src/valina-build` (vanilla, also used by
   SymTuner) and `CompoSE_Aaqc/src/qc-build`.
3. Install the **`regexgen`** command (a modified
   [Petabi Sniffles](https://github.com/petabi/sniffles)) via `sniffles/setup.py`.
4. Install **SymTuner**, which provides the `symtuner`, `symtuner-naive`, and
   `symtuner-compose` commands.
5. Build the **12 benchmarks** with `build.sh all`, producing a gcov-instrumented object
   (`obj-gcov1`) and an LLVM-bitcode object (`obj-llvm`) for each, under
   `benchmarks/<program>-<version>/`.

Inside the container, the working directory is `/root/compose` and all commands in the
[How to Run](#how-to-run) section can be executed directly.

> **Rebuilding a single benchmark.** `build.sh` also accepts individual program names,
> e.g. `./build.sh csplit` or `./build.sh grep`.

### Program configuration (`pgm_config`)

Each program has a JSON file in `pgm_config/` (e.g. `csplit100.json`). All paths are
**relative to the CompoSE root**, so the three tools resolve them consistently. A typical
entry looks like:

```json
{
    "pgm_name": "csplit",
    "pgm_dir":  "benchmarks/csplit-8.32/obj-llvm/",
    "exec_dir": "/src",
    "gcov_path": "benchmarks/csplit-8.32/obj-gcov1",
    "gcov_file": "../*/*.gcov ../*/*/*.gcov",
    "gcda_file": "../*/*.gcda ../*/*/*.gcda",
    "sym_args": "--sym-args 0 1 10 --sym-args 0 2 2 --sym-files 1 8 --sym-stdin 8 --sym-stdout"
}
```

- `pgm_dir` + `exec_dir` locate the LLVM bitcode (`obj-llvm/src/csplit.bc`).
- `gcov_path` locates the gcov-instrumented binary for coverage.
- `sym_args` is the symbolic-argument specification for KLEE.

---

## How to Run

Below, `csplit` is used as the running example with a short 1-hour budget (`-t 3600`).
Each command runs one tool in one variant. Run each command from the tool's own directory.

### FeatMaker (`cd CompoSE_FeatMaker`)

```bash
# Base
python3 run_featmaker.py --pgm csplit --config 100 --total_budget 3600 --output_dir test

# +Naive
python3 run_compose_naive_featmaker.py --pgm csplit --config 100 --total_budget 3600 --output_dir test

# +CompoSE
python3 run_compose_featmaker.py --pgm csplit --config 100 --total_budget 3600 --output_dir test
```

> `--config 100` selects `pgm_config/csplit100.json`.

### SymTuner (`cd CompoSE_SymTuner/symtuner`)

SymTuner is installed as a package (see Installation) and exposes the commands
`symtuner`, `symtuner-naive`, and `symtuner-compose`. Each takes the LLVM bitcode and the
gcov binary as positional arguments. Run the commands from `CompoSE_SymTuner/symtuner`,
where the parameter-space file `spaces.json` lives.

```bash
BC=../../benchmarks/csplit-8.32/obj-llvm/src/csplit.bc
GC=../../benchmarks/csplit-8.32/obj-gcov1/src/csplit

# Base
symtuner         -t 3600 -s spaces.json -d test $BC $GC

# +Naive
symtuner-naive   -t 3600 -s spaces.json -d test --pgm-config ../../pgm_config/csplit100.json $BC $GC

# +CompoSE
symtuner-compose -t 3600 -s spaces.json -d test --pgm-config ../../pgm_config/csplit100.json $BC $GC
```

> `-d test` sets the output directory (default `symtuner-out`). `-s spaces.json` supplies the
> KLEE parameter search space; `spaces.json` is provided in `CompoSE_SymTuner/symtuner/` and can
> be edited to change the tuning space (its format matches the output of
> `--generate-search-space-json`).

### AAQC (`cd CompoSE_Aaqc`)

```bash
# Base
python3 run_aaqc.py         -p csplit -t 3600 --pgm-config ../pgm_config/csplit100.json

# +Naive
python3 run_aaqc_naive.py   -p csplit -t 3600 --pgm-config ../pgm_config/csplit100.json

# +CompoSE
python3 run_aaqc_compose.py -p csplit -t 3600 --pgm-config ../pgm_config/csplit100.json
```

### Regex dialect (automatic)

The regex dialect (BRE / ERE) for each program is taken from `regex_mode_table.py`
automatically, so you do **not** need to pass it. A `--regex-mode {bre,ere,pcre}` option
exists only as an override for programs not listed in the table. On startup each tool prints
the resolved dialect, e.g.:

```
[regex_mode] csplit -> bre
```

### Regex-option extraction (automatic)

The +CompoSE and +Naive variants read each program's manual (from `manuals/`, e.g.
`manuals/csplit.pdf`) to discover which CLI options and operands take a regular expression, and
use them to guide regex generation. This happens automatically, using the manual that matches
the program name.

---

## Reporting Results

Following the evaluation in the paper, each configuration is measured by running a **baseline**
for half of the time budget and **+CompoSE** for the other half, and then reporting the
**combined** result of both runs.

### Branch coverage

`measure_coverage.py` replays the generated test cases and reports the cumulative covered
branches. Passing several directories to `--src_dirs` reports their **union**, which is how the
half-baseline / half-CompoSE runs are combined.

```bash
# 1) Baseline for half the budget, then +CompoSE for the other half:
python3 CompoSE_FeatMaker/run_featmaker.py \
        --pgm csplit --config 100 --total_budget 1800 --output_dir base_half
python3 CompoSE_FeatMaker/run_compose_featmaker.py \
        --pgm csplit --config 100 --total_budget 1800 --output_dir compose_half

# 2) Combined branch coverage of both runs:
python3 measure_coverage.py --gcov_num 1 \
        --src_dirs CompoSE_FeatMaker/featmaker_experiments/base_half/csplit/result \
                   CompoSE_FeatMaker/featmaker_experiments/compose_half/csplit/result
```

`config.json` (at the repository root) maps each program to its gcov directory and replay
command. The klee-replay binary defaults to FeatMaker's build and can be overridden with
`--klee_replay` (e.g. AAQC/SymTuner runs use
`CompoSE_Aaqc/src/valina-build/bin/klee-replay`).

### Bugs (crashes)

`measure_bugs.sh` replays every test case and collects the runs that crash:

```bash
chmod +x measure_bugs.sh
./measure_bugs.sh CompoSE_FeatMaker/klee/build/bin/klee-replay \
        benchmarks/csplit-8.32/obj-gcov1/src/csplit \
        CompoSE_FeatMaker/featmaker_experiments/compose_half/csplit/result
```

For each result directory this writes `crash_output.txt`, one line per crashing run
(`CRASHED` / `Received signal`). Several directories can be passed to combine the
half-baseline / half-CompoSE runs.

---

## Output

Each run creates an experiment directory containing, per iteration:

- **test cases** — `*.ktest` files generated by KLEE (replayable with `klee-replay`);
- **coverage** — accumulated branch coverage over time;
- **logs** — the KLEE command and metadata for each iteration.

Output locations:

- FeatMaker → `CompoSE_FeatMaker/featmaker_experiments/<output_dir>/<pgm>/`
- SymTuner → `CompoSE_SymTuner/symtuner/<output-dir>/` (set with `-d`, default `symtuner-out`)
- AAQC → `CompoSE_Aaqc/experiments/` (override with the `AAQC_EXP_ROOT` environment variable)

---

## Benchmarks

CompoSE targets 12 GNU programs whose regex handling reaches the bundled gnulib regex engine:

| | | | |
| ------ | ------ | ------ | ------ |
| grep   | sed    | gawk   | nano   |
| diff   | find   | csplit | ptx    |
| expr   | m4     | tac    | nl     |

Each is built by `build.sh` into `benchmarks/<program>-<version>/`.