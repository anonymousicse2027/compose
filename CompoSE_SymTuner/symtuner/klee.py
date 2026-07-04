from copy import deepcopy
from pathlib import Path
import os
import random
import subprocess as sp

from symtuner.logger import get_logger
from symtuner.symbolic_executor import SymbolicExecutor
from symtuner.symtuner import SymTuner


class GCov:

    def __init__(self, bin='gcov'):

        self.bin = bin
        self.smoke_test()
        if self.bin != 'gcov':
            get_logger().info(f'Use gcov executable at: {self.bin}')

    def smoke_test(self):

        try:
            _ = sp.run(f'{self.bin} -version', stdout=sp.PIPE, stderr=sp.PIPE,
                       shell=True, check=True)
        except sp.CalledProcessError as e:
            get_logger().fatal(f'Failed to find gcov: {self.bin}')
            raise e
        get_logger().debug(f'gcov found: {self.bin}')

    def run(self, target, gcdas, folder_depth=1):


        if len(gcdas) == 0:
            return set()


        original_path = Path().absolute()
        target_dir = Path(target).parent
        gcdas = [gcda.absolute() for gcda in gcdas]
        gcdas = [g for g in gcdas if "signal.gcda" not in str(g)]
        os.chdir(str(target_dir))


        cmd = [str(self.bin), '-b', *list(map(str, gcdas))]
        cmd = ' '.join(cmd)
        get_logger().debug(f'gcov command: {cmd}')
        _ = sp.run(cmd, stdout=sp.PIPE, stderr=sp.PIPE, shell=True, check=True)


        base = Path()
        for _ in range(folder_depth):
            base = base / '..'
        gcov_pattern = base / '**/*.gcov'
        gcovs = list(Path().glob(str(gcov_pattern)))
        gcovs = [g for g in gcovs if "signal.c.gcov" not in str(g)]
        get_logger().debug(f'found gcovs: {", ".join(map(str, gcovs))}')


        covered = set()
        for gcov in gcovs:
            try:
                with gcov.open(encoding='UTF-8', errors='replace') as f:
                    file_name = f.readline().strip().split(':')[-1]
                    for i, line in enumerate(f):
                        if ('branch' in line) and ('never' not in line) and ('taken 0%' not in line):
                            bid = f'{file_name} {i}'
                            covered.add(bid)
            except (FileNotFoundError, OSError) as e:


                get_logger().debug(f'Skipping unreadable gcov file {gcov}: {e}')
                continue


        os.chdir(str(original_path))
        return covered


class KLEE(SymbolicExecutor):

    def __init__(self, bin='klee'):

        self.bin = bin
        self.smoke_test()
        if self.bin != 'klee':
            get_logger().info(f'Use klee executable at: {self.bin}')

    def smoke_test(self):

        try:
            _ = sp.run(f'{self.bin} -version',  stdout=sp.PIPE, stderr=sp.PIPE,
                       shell=True, check=True)
        except sp.CalledProcessError as e:
            get_logger().fatal(f'Failed to find klee: {self.bin}')
            raise e
        get_logger().debug(f'klee found: {self.bin}')

    def run(self, target, parameters, **kwargs):

        target = Path(target).absolute()


        output_dir = None
        possible_output_dir = ['-output-dir', '--output-dir']
        for output_dir_param in possible_output_dir:
            if output_dir_param in parameters.keys():
                output_dir = Path(parameters[output_dir_param]).absolute()
                parameters[output_dir_param] = str(output_dir)
                break


        original_path = Path().absolute()
        os.chdir(str(target.parent))


        klee_options = []

        sym_arg_options = []
        regex_options = []
        sym_files_options = []
        sym_stdin_options = []
        sym_stdout_options = []

        space_seperate_keys = ['sym-arg', 'sym-args', 'sym-files', 'sym-stdin']
        sym_arg_keys = ['sym-arg', 'sym-args']

        for key, values in parameters.items():
            stripped_key = key.strip('-').split()[0]
            if not isinstance(values, list):
                values = [values]
            for value in values:
                if value is None:
                    param = key
                elif stripped_key in space_seperate_keys:
                    param = f'{key} {value}'
                elif stripped_key == 'sym-stdout':
                    if value == 'off':
                        continue
                    param = key
                else:
                    param = f'{key}={value}'

                if stripped_key in sym_arg_keys:
                    sym_arg_options.append(param)
                elif stripped_key == 'regex-options':


                    regex_options.append(f'{value}')
                elif stripped_key == 'sym-files':
                    sym_files_options.append(param)
                elif stripped_key == 'sym-stdin':
                    sym_stdin_options.append(param)
                elif stripped_key == 'sym-stdout':
                    sym_stdout_options.append(param)
                else:
                    klee_options.append(param)


        cmd_list = [str(self.bin), *klee_options, str(target)]

        if regex_options:
            cmd_list.extend(regex_options)
        cmd_list.extend(sym_arg_options)
        cmd_list.extend(sym_files_options)
        cmd_list.extend(sym_stdin_options)
        cmd_list.extend(sym_stdout_options)


        cmd = ' '.join(cmd_list)
        get_logger().debug(f'klee command: {cmd}')
        try:
            _ = sp.run(cmd, stdout=sp.PIPE, stderr=sp.PIPE,
                       shell=True, check=True)
        except sp.CalledProcessError as e:
            stderr = e.stderr.decode(errors='replace')
            lastline = stderr.strip().splitlines()[-1] if stderr.strip().splitlines() else ''
            if 'KLEE' in lastline and 'kill(9)' in lastline:
                get_logger().warning(f'KLEE process kill(9)ed. Failed to terminate nicely.')
            else:

                if output_dir is None:

                    candidate = target.parent / 'klee-last'
                    if candidate.exists():
                        output_dir = candidate.resolve()
                    else:
                        output_dir = original_path

                log_file = output_dir / 'symtuner.log'

                output_dir.mkdir(parents=True, exist_ok=True)

                get_logger().warning(f'Fail({e.returncode})ed to execute KLEE. '
                                     f'See for more details: {log_file}')
                with log_file.open('w', encoding='UTF-8') as f:
                    f.write(f'command: {cmd}\n')
                    f.write(f'return code: {e.returncode}\n')
                    f.write('\n')
                    f.write('-- stdout --\n')
                    stdout = e.stdout.decode(errors='replace')
                    f.write(f'{stdout}\n')
                    f.write('-- stderr --\n')
                    f.write(f'{stderr}\n')


        if output_dir is None:

            candidate = target.parent / 'klee-last'
            output_dir = candidate.resolve() if candidate.exists() else original_path

        testcases = list(output_dir.glob('*.ktest'))
        testcases = [tc.absolute() for tc in testcases]


        os.chdir(str(original_path))

        return testcases

    def get_time_parameter(self):

        return '-max-time'


class KLEEReplay:

    def __init__(self, bin='klee-replay'):

        self.bin = bin
        self.smoke_test()
        if self.bin != 'klee-replay':
            get_logger().info(f'Use klee-replay executable at: {self.bin}')

    def smoke_test(self):

        try:
            _ = sp.run(f'which {self.bin}',  stdout=sp.PIPE, stderr=sp.PIPE,
                       shell=True, check=True)
        except sp.CalledProcessError as e:
            get_logger().fatal(f'Failed to find klee-replay: {self.bin}')
            raise e
        get_logger().debug(f'klee-replay found: {self.bin}')

    def run(self, target, testcase, error_type=None, folder_depth=1):

        target = Path(target).absolute()
        testcase = Path(testcase).absolute()


        original_path = Path().absolute()
        os.chdir(str(target.parent))


        if error_type is None:
            error_type = ['CRASHED signal 11', 'CRASHED signal 6']
        if isinstance(error_type, str):
            error_type = [error_type]


        cmd = [str(self.bin), str(target), str(testcase)]
        cmd = ' '.join(cmd)
        get_logger().debug(f'klee-replay command: {cmd}')
        process = sp.Popen(cmd, stdout=sp.PIPE, stderr=sp.PIPE, shell=True, preexec_fn=os.setsid)
        errors = set()
        try:
            _, stderr = process.communicate(timeout=0.1)
            lastline = str(stderr.splitlines()[-1]) if stderr.splitlines() else ''


            for error in error_type:
                if error in lastline:
                    errs = list(testcase.parent.glob(testcase.stem + '.*.err'))

                    for err in errs:
                        with err.open(encoding='UTF-8', errors='replace') as f:
                            lines = f.readlines()
                            file_name = lines[1].split()[1]
                            line_num = lines[2].split()[1]
                            err_type = f'{file_name} {line_num}'
                            errors.add(err_type)
        except sp.TimeoutExpired:
            get_logger().warning(f'KLEE replay timeout: {testcase}')
        finally:
            try: os.killpg(os.getpgid(process.pid), 9)
            except: process.kill()


        base = Path()
        for _ in range(folder_depth):
            base = base / '..'
        gcda_pattern = base / '**/*.gcda'
        gcdas = list(target.parent.glob(str(gcda_pattern)))
        gcdas = [gcda.absolute() for gcda in gcdas]


        os.chdir(str(original_path))

        return errors, gcdas


class KLEESymTuner(SymTuner):

    def __init__(self, klee_replay=None, gcov=None, k_seeds=10, *args, **kwargs):

        super(KLEESymTuner, self).__init__(*args, **kwargs)

        if klee_replay is None:
            klee_replay = KLEEReplay()
        elif isinstance(klee_replay, str):
            klee_replay = KLEEReplay(klee_replay)
        self.klee_replay = klee_replay
        if gcov is None:
            gcov = GCov()
        elif isinstance(gcov, str):
            gcov = GCov(gcov)
        self.gcov = gcov

        self.k_seeds = k_seeds

    def sample(self, policy=None):

        parameters = super(KLEESymTuner, self).sample(policy)


        if '-seed-file' in parameters.keys() or '--seed-file' in parameters.keys():
            key = '-seed-file' if '-seed-file' in parameters.keys() else '--seed-file'
            value = parameters[key]

            if value == 'random_from_all':
                testcases = [tc for _, _, tc, _ in self.data]
                if len(testcases) > 0:
                    testcase = random.choice(testcases)
                    parameters[key] = str(testcase)
                else:
                    del parameters[key]

        return parameters

    def add(self, target, parameters, testcases, evaluation_kwargs=None):

        super(KLEESymTuner, self).add(target, parameters, testcases,
                                      evaluation_kwargs)


        if '-seed-file' not in self.space.keys() and '--seed-file' not in self.space.keys():
            return self


        buggy_seeds = []
        found_bugs = []
        for _, bugs, tc, _ in self.data[::-1]:
            for bug in bugs:
                if bug not in found_bugs:
                    found_bugs.append(bug)
                    buggy_seeds.append(tc)


        accumulated_coverage = set()
        copied_data = deepcopy(self.data)
        top_k_seeds = []

        for _ in range(self.k_seeds):
            if len(copied_data) == 0:
                break
            copied_data = sorted(copied_data,
                                 key=lambda elem: len(elem[0]),
                                 reverse=True)
            top_cov, _, tc, _ = copied_data.pop(0)
            if len(top_cov) > 0:
                accumulated_coverage = accumulated_coverage | top_cov
                copied_data = [(cov - accumulated_coverage, bug, tc, param)
                               for cov, bug, tc, param in copied_data]
                top_k_seeds.append(tc)
            else:
                break


        key = '-seed-file' if '-seed-file' in self.space.keys() else '--seed-file'
        seed_files = buggy_seeds + top_k_seeds
        self.space[key] = (seed_files, self.space[key][1])
        for seed in seed_files:
            if seed not in self.cnts[key].keys():
                self.cnts[key][seed] = 0
        return self

    def evaluate(self, target, testcase, folder_depth=1):


        base = Path(target).parent
        for _ in range(folder_depth):
            base = base / '..'
        cmd = ['rm', '-f', str(base / '**/*.gcda'), str(base / '**/*.gcov')]
        cmd = ' '.join(cmd)
        get_logger().debug(f'gcda gcov clean up command: {cmd}')
        _ = sp.run(cmd, shell=True, check=True)
        errors, gcdas = self.klee_replay.run(target, testcase,
                                             folder_depth=folder_depth)
        branches = self.gcov.run(target, gcdas, folder_depth=folder_depth)
        return branches, errors

    @classmethod
    def get_default_space(cls):

        search_heuristics = ['nurs:cpicnt', 'nurs:qc', 'nurs:covnew', 'random-path', 'bfs',
                             'nurs:md2u', 'nurs:icnt', 'nurs:depth', 'random-state', 'dfs']
        space = {

            '-simplify-sym-indices': (['true', 'false'], 1),
            '-use-forked-solver': (['true', 'false'], 1),
            '-use-cex-cache': (['true', 'false'], 1),
            '-max-memory-inhibit': (['true', 'false'], 1),
            '-optimize': (['true', 'false'], 1),
            '-sym-stdout': (['on', 'off'], 1),


            '-max-memory': ([500, 1000, 1500, 2000, 2500], 1),
            '-max-sym-array-size': ([3000, 3500, 4000, 4500, 5000], 1),
            '-max-instruction-time': ([10, 20, 30, 40, 50], 1),
            '-max-static-fork-pct': ([0.25, 0.5, 1, 2, 4], 1),
            '-max-static-solve-pct': ([0.25, 0.5, 1, 2, 4], 1),
            '-max-static-cpfork-pct': ([0.25, 0.5, 1, 2, 4], 1),
            '-batch-instructions': ([6000, 8000, 10000, 12000, 14000], 1),
            '-sym-arg': ([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 5),
            '-sym-files 1': ([4, 8, 12, 16, 20], 1),
            '-sym-stdin': ([4, 8, 12, 16, 20], 1),


            '-seed-file': ([], 1),
            '-search': (search_heuristics, 1),
            '-switch-type': (['simple', 'internal'], 1),
            '-external-calls': (['concrete', 'all'], 1),
        }
        return space

    @classmethod
    def get_default_default_parameters(cls):

        defaults = {
            '-output-module': 'false',
            '-output-source': 'false',
            '-output-stats': 'false',
            '-use-batching-search': None,
            '-posix-runtime': None,
            '-only-output-states-covering-new': None,
            '-watchdog': None,
            '-allow-seed-extension': None,
            '-allow-seed-truncation': None,
            '-ignore-solver-failures': None,
            '-libc': 'uclibc',
            '-disable-inlining': None,
        }
        return defaults