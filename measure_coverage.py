import os
import math, time
import re
import argparse
import pickle
import csv
import json


COMPOSE_ROOT = os.path.dirname(os.path.abspath(__file__))

parser = argparse.ArgumentParser(description='Run KLEE replay and calculate coverage for specified programs.')
parser.add_argument('--src_dirs', type=str, nargs="+", required=True, help='Path to the source directory containing KLEE output.')
parser.add_argument('--gcov_num', type=int, required=True, help='Number to replace in the gcov directory path.')
parser.add_argument('--output_dir', type=str, default='coverage_results', help='Directory for the output CSV files.')
parser.add_argument('--klee_replay', type=str,
                    default=os.path.join(COMPOSE_ROOT, 'CompoSE_FeatMaker', 'klee', 'build', 'bin', 'klee-replay'),
                    help='Path to the klee-replay binary.')


args = parser.parse_args()


config_path = os.path.join(os.path.dirname(__file__), 'config.json')
with open(config_path, 'r') as f:
    config_data = json.load(f)


def count_directories(path):
    try:
        items = os.listdir(path)
        directories = [item for item in items if os.path.isdir(os.path.join(path, item))]
        return len(directories)
    except FileNotFoundError:
        return "The specified path does not exist."
    except Exception as e:
        return f"An error occurred: {e}"


def find_ktest_files(src_dirs):
    def extract_numbers_homi(file_name):
        iteration_match = re.search(r'\d+__tc_dirs', file_name)
        test_match = re.search(r'test(\d+)\.ktest', file_name)
        if iteration_match and test_match:
            iteration_number = int(iteration_match.group(0).split('__')[0])
            test_number = int(test_match.group(1))
            return (iteration_number, test_number)
        else:
            return (float('inf'), float('inf'))

    def extract_numbers_default(file_name):
        iteration_match = re.search(r'/iteration(\d+)', file_name)
        test_match = re.search(r'test(\d+)\.ktest', file_name)
        if iteration_match and test_match:
            iteration_number = int(iteration_match.group(1))
            test_number = int(test_match.group(1))
            return (iteration_number, test_number)
        else:
            return (float('inf'), float('inf'))

    def extract_numbers_featmaker(file_name):
        iteration_match = re.search(r'/iteration-(\d+)', file_name)
        test_match = re.search(r'test(\d+)\.ktest', file_name)
        if iteration_match and test_match:
            iteration_number = int(iteration_match.group(1))
            test_number = int(test_match.group(1))
            return (iteration_number, test_number)
        else:
            return (float('inf'), float('inf'))

    def extract_numbers_learch(file_name):
        feedforward_match = re.search(r'feedforward_(\d+)', file_name)
        test_match = re.search(r'test(\d+)\.ktest', file_name)
        if feedforward_match and test_match:
            feedforward_number = int(feedforward_match.group(1))
            test_number = int(test_match.group(1))
            return (feedforward_number, test_number)
        else:
            return (float('inf'), float('inf'))

    def extract_numbers_aaqc(file_name):
        nested_match = re.search(r'/iteration-(\d+)/(\d+)/', file_name)
        test_match = re.search(r'test(\d+)\.ktest', file_name)
        if nested_match and test_match:
            i = int(nested_match.group(1))
            j = int(nested_match.group(2))
            test_number = int(test_match.group(1))
            return (j, i, test_number)
        flat_match = re.search(r'/iteration-(\d+)/', file_name)
        if flat_match and test_match:
            i = int(flat_match.group(1))
            test_number = int(test_match.group(1))
            return (0, i, test_number)
        return (float('inf'), float('inf'), float('inf'))

    ktest_files = []

    for src_dir in src_dirs:
        if 'aaqc' in src_dir.lower():
            extract_function = extract_numbers_aaqc
        elif 'featmaker' in src_dir.lower() or 'symtuner' in src_dir.lower():
            extract_function = extract_numbers_featmaker
        else:
            extract_function = extract_numbers_default

        if 'aaqc' in src_dir.lower():
            for iteration_dir in os.listdir(src_dir):
                if re.match(r'iteration-(\d+)', iteration_dir):
                    iteration_path = os.path.join(src_dir, iteration_dir)
                    if os.path.isdir(iteration_path):
                        for item in os.listdir(iteration_path):
                            item_path = os.path.join(iteration_path, item)
                            if os.path.isfile(item_path) and item.endswith('.ktest'):
                                ktest_files.append(item_path)
                            elif os.path.isdir(item_path):
                                for file_name in os.listdir(item_path):
                                    if file_name.endswith('.ktest'):
                                        ktest_files.append(os.path.join(item_path, file_name))

        elif 'featmaker' in src_dir.lower():
            for iteration_dir in os.listdir(src_dir):
                if re.match(r'iteration-(\d+)', iteration_dir):
                    iteration_path = os.path.join(src_dir, iteration_dir)
                    if os.path.isdir(iteration_path):
                        for sub_folder in range(20):
                            sub_folder_path = os.path.join(iteration_path, str(sub_folder))
                            if os.path.isdir(sub_folder_path):
                                for file_name in os.listdir(sub_folder_path):
                                    if file_name.endswith('.ktest'):
                                        ktest_files.append(os.path.join(sub_folder_path, file_name))

        elif 'symtuner' in src_dir.lower():
            for iteration_dir in os.listdir(src_dir):
                if re.match(r'iteration-(\d+)', iteration_dir):
                    klee_out_dir = os.path.join(src_dir, iteration_dir)
                    if os.path.isdir(klee_out_dir):
                        for file_name in os.listdir(klee_out_dir):
                            if file_name.endswith('.ktest'):
                                ktest_files.append(os.path.join(klee_out_dir, file_name))

        elif 'klee' in src_dir.lower():
            for file_name in os.listdir(src_dir):
                if file_name.endswith('.ktest'):
                    ktest_files.append(os.path.join(src_dir, file_name))

        else:
            for iteration_dir in os.listdir(src_dir):
                if re.match(r'iteration-(\d+)', iteration_dir):
                    klee_out_dir = os.path.join(src_dir, iteration_dir)
                    if os.path.isdir(klee_out_dir):
                        for file_name in os.listdir(klee_out_dir):
                            if file_name.endswith('.ktest'):
                                ktest_files.append(os.path.join(klee_out_dir, file_name))


    return sorted(ktest_files, key=extract_function)


def branch_handler(ktest_gcov, branch_visit_count, function_data):
    with open(ktest_gcov, 'r', errors='ignore') as f:
        lines = f.readlines()

    condition_visit_count = 0
    src_name = ""
    line_number = 0

    current_function = None
    function_branch_total = 0
    function_branch_taken = 0

    for line in lines:
        if "-:    0:Source:" in line:
            src_name = line.split('/')[-1].strip().replace('-:    0:Source:', '')
        elif re.match(r'\s*\d+:\s*\d+:', line):
            if "#####" in line:
                continue
            parts = line.split(":")
            try:
                condition_visit_count = int(parts[0].strip())
                line_number = int(parts[1].strip())
            except ValueError:
                condition_visit_count = 0
                line_number = 0
        elif line.lstrip().startswith("function") and "called" in line:
            tokens = line.split()
            function_name = tokens[1]
            if current_function is not None and function_name != current_function:
                if function_branch_total > 0:
                    coverage = (function_branch_taken / function_branch_total) * 100
                else:
                    coverage = 0.0
                function_data.append([src_name, current_function, coverage])
                current_function = function_name
                function_branch_total = 0
                function_branch_taken = 0
            elif current_function is None:
                current_function = function_name
                function_branch_total = 0
                function_branch_taken = 0
        elif "branch" in line and "taken 0%" not in line and "never" not in line:
            parts = line.split()
            if len(parts) < 4:
                print(f"Skipping malformed branch line: {line.strip()}")
                continue
            try:
                branch_id = parts[1]
                taken_percentage_str = parts[3].replace('%', '')
                taken_percentage = float(taken_percentage_str)
            except (IndexError, ValueError):
                print(f"Error parsing branch line: {line.strip()}")
                continue
            if math.isnan(condition_visit_count) or math.isnan(taken_percentage):
                branch_visits = 0
            else:
                branch_visits = int(condition_visit_count * (taken_percentage / 100))
            if branch_visits > 0:
                branch_key = f"{src_name} {line_number} {branch_id}"
                branch_visit_count[branch_key] = branch_visit_count.get(branch_key, 0) + branch_visits
            if current_function is not None:
                function_branch_total += 1
                if "never executed" not in line and taken_percentage > 0:
                    function_branch_taken += 1

    if current_function is not None:
        if function_branch_total > 0:
            coverage = (function_branch_taken / function_branch_total) * 100
        else:
            coverage = 0.0
        function_data.append([src_name, current_function, coverage])

    return branch_visit_count


def collect_covered_branches(gcov_glob_dirs):
    import glob as _glob
    if isinstance(gcov_glob_dirs, str):
        gcov_glob_dirs = [gcov_glob_dirs]
    covered_keys = set()
    gcov_files = []
    for d in gcov_glob_dirs:
        gcov_files.extend(_glob.glob(os.path.join(d, '**', '*.gcov'), recursive=True))
    for gf in gcov_files:
        fname = os.path.basename(gf)
        cur_line = '0'
        bidx = 0
        try:
            with open(gf, 'r', errors='ignore') as f:
                for line in f:
                    s = line.lstrip()
                    m = re.match(r'\s*[\d#=\-]+:\s*(\d+):', line)
                    if m:
                        cur_line = m.group(1)
                        bidx = 0
                        continue
                    if s.startswith('branch '):
                        if 'never executed' in line:
                            bidx += 1
                            continue
                        if 'taken 0%' not in line:
                            covered_keys.add(f"{fname}:{cur_line}:{bidx}")
                        bidx += 1
        except FileNotFoundError:
            continue
    return covered_keys, len(gcov_files)


def cal_coverage_from_gcov(gcov_glob_dirs, _step=None):
    import glob as _glob
    if isinstance(gcov_glob_dirs, str):
        gcov_glob_dirs = [gcov_glob_dirs]
    covered = 0
    total = 0
    gcov_files = []
    for d in gcov_glob_dirs:
        gcov_files.extend(_glob.glob(os.path.join(d, '**', '*.gcov'), recursive=True))
    for gf in gcov_files:
        try:
            with open(gf, 'r', errors='ignore') as f:
                for line in f:
                    s = line.lstrip()
                    if s.startswith('branch '):
                        if 'never executed' in line:
                            total += 1
                            continue
                        total += 1
                        if 'taken 0%' not in line:
                            covered += 1
        except FileNotFoundError:
            continue

    print(f"[diag] step={_step} gcov_files={len(gcov_files)} covered={covered} total={total}")
    return covered


def cal_coverage(cov_file):
    coverage = 0
    total_coverage = 0
    if not os.path.exists(cov_file):
        print(f"[warn] cov_file not found: {cov_file}, returning 0")
        return 0
    with open(cov_file, 'r') as f:
        lines = f.readlines()
        for line in lines:
            if "Taken at least" in line:
                data = line.split(':')[1]
                percent = float(data.split('% of ')[0])
                total_branches = float((data.split('% of ')[1]).strip())

                covered_branches = int(round(percent * total_branches / 100))
                coverage += covered_branches
                total_coverage += total_branches
    print("----------------Results--------------------------------------------")
    print("-------------------------------------------------------------------")
    print(f"The number of covered branches: {coverage}")
    print(f"The number of total branches: {int(total_coverage)}")
    print("-------------------------------------------------------------------")
    return coverage




_AAQC_ABBREV = {
    'gr': 'grep',    'grep': 'grep',
    'se': 'sed',     'sed': 'sed',
    'ga': 'gawk',    'gawk': 'gawk',
    'na': 'nano',    'nano': 'nano',
    'di': 'diff',    'diff': 'diff',
    'fi': 'find',    'find': 'find',
    'cs': 'csplit',  'csplit': 'csplit',
    'pt': 'ptx',     'ptx': 'ptx',
    'ex': 'expr',    'expr': 'expr',
    'm4': 'm4',
    'tc': 'tac',     'tac': 'tac',
    'nl': 'nl',
}

def detect_program(config_data, src_dirs):
    for key in config_data:
        if any(key in src_dir.lower() for src_dir in src_dirs):
            return key
    for src_dir in src_dirs:
        m = re.search(r'[Aa]aqc[_-]?([A-Za-z]+?)(?:_|$)', os.path.basename(src_dir))
        if m:
            abbrev = m.group(1).lower()
            if abbrev in _AAQC_ABBREV:
                mapped = _AAQC_ABBREV[abbrev]
                if mapped in config_data:
                    return mapped
    cwd = os.getcwd().lower()
    for key in config_data:
        if key in cwd:
            return key
    return 'unknown'



src_dirs = args.src_dirs
gcov_num = args.gcov_num

program = detect_program(config_data, src_dirs)

if program == 'unknown':
    print("Error: Program name could not be determined from src_dirs.")
    print(f"  src_dirs: {src_dirs}")
    print(f"  config keys: {list(config_data.keys())}")
    print(f"  cwd: {os.getcwd()}")
    print("Hint: add a mapping to _AAQC_ABBREV or ensure the program name appears in the path.")
    exit(1)

tool_name = [tool for tool in ['featmaker', 'symtuner', 'aaqc', 'klee']
             if any(tool in src_dir.lower() for src_dir in src_dirs)]

tool_suffix = tool_name[0] if tool_name else 'unknown'

if tool_suffix == 'featmaker' and any('depth' in src_dir.lower() for src_dir in src_dirs):
    tool_suffix = 'klee'

nxargs_match = next((re.search(r'(humanArgs)', src_dir, re.IGNORECASE) for src_dir in src_dirs if re.search(r'(humanArgs)', src_dir, re.IGNORECASE)), None)
nxargs_suffix = f"_{nxargs_match.group(1)}" if nxargs_match else ""

settings = config_data[program]

gcov_dir = settings['gcov_dir'].replace('<gcov_num>', str(gcov_num))
if not os.path.isabs(gcov_dir):
    gcov_dir = os.path.join(COMPOSE_ROOT, gcov_dir)
rm_cmd = settings['rm_cmd']
replay_cmd = settings['replay_cmd'].replace('<klee_replay>', args.klee_replay)
cov_cmd = settings['cov_cmd']

csv_filename = os.path.abspath(os.path.join(args.output_dir, f"klee-{program}", "branch_visit_count", f"{tool_suffix}_{program}{nxargs_suffix}_branch_visit_count.csv"))
function_csv_filename = os.path.abspath(os.path.join(args.output_dir, f"klee-{program}", "function_execution_data", f"{tool_suffix}_{program}{nxargs_suffix}_function_execution.csv"))

os.makedirs(os.path.dirname(csv_filename), exist_ok=True)
os.makedirs(os.path.dirname(function_csv_filename), exist_ok=True)

ktest_files_list = [os.path.abspath(p) for p in find_ktest_files(src_dirs)]

print(len(ktest_files_list))

coverage_list = []
time_coverage_dict = {}
branch_visit_count = {}
function_data = []
cumulative_covered = set()

print(f"Processing program: {program}")
os.chdir(gcov_dir)

os.system(rm_cmd)

for i, file_path in enumerate(ktest_files_list):
    os.chdir(gcov_dir)
    cmd = replay_cmd + file_path + ' 2> /dev/null'
    os.system(cmd)
    os.system(cov_cmd)

    if i == 0:
        start_time = os.path.getctime(file_path)

    elapsed_time = round(os.path.getctime(file_path) - start_time, 3)


    step_covered, n_gcov = collect_covered_branches(gcov_dir)
    before = len(cumulative_covered)
    cumulative_covered.update(step_covered)
    coverage = len(cumulative_covered)
    print(f"[diag] step={i} gcov_files={n_gcov} step_cov={len(step_covered)} "
          f"cumulative={coverage} (+{coverage - before})")
    coverage_list.append(coverage)
    time_coverage_dict[elapsed_time] = coverage

gcov_dir_upper = os.path.dirname(gcov_dir)
if program == 'gawk':
    gcov_dir_upper = gcov_dir
    
for root, dirs, files in os.walk(gcov_dir_upper):
    for file in files:
        if file.endswith('.gcov'):
            ktest_gcov = os.path.join(root, file)
            branch_visit_count = branch_handler(ktest_gcov, branch_visit_count, function_data)

if os.path.exists(csv_filename):
    os.remove(csv_filename)

with open(csv_filename, 'w', newline='') as csvfile:
    csv_writer = csv.writer(csvfile)
    csv_writer.writerow(['Branch Identifier', 'Visit Count'])
    for branch, count in branch_visit_count.items():
        csv_writer.writerow([branch, count])

if os.path.isdir(function_csv_filename):
    raise IsADirectoryError(f"Expected a file but found a directory: {function_csv_filename}")

with open(function_csv_filename, 'w', newline='') as csvfile:
    csv_writer = csv.writer(csvfile)
    csv_writer.writerow(['Source File', 'Function Name', 'Function Coverage'])
    csv_writer.writerows(function_data)

print(f"Branch visit count saved to {csv_filename}")
print(f"Function execution data saved to {function_csv_filename}")