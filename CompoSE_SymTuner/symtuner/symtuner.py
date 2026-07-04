from abc import ABC
from abc import abstractclassmethod
from abc import abstractmethod
from copy import deepcopy
from datetime import datetime
from pathlib import Path
import json
import numpy as np
import random
from symtuner.logger import get_logger
class TimeBudgetHandler:
    def __init__(self, total_budget,
                 minimum_ratio=0.005,
                 steps_per_round=20,
                 increase_ratio=2.,
                 minimum_time_budget=30):
        self.total_budget = total_budget
        self.steps_per_round = steps_per_round
        self.increase_ratio = increase_ratio
        self.steps_in_round = 0
        self.current_time_budget = int(self.total_budget * minimum_ratio)
        self.current_time_budget = max(self.current_time_budget,
                                       minimum_time_budget)
        self.start_time: datetime = datetime.now()
    def get_time_budget(self):

        time_elapsed = (datetime.now() - self.start_time).total_seconds()
        if time_elapsed > self.total_budget:
            return -1

        self.steps_in_round += 1
        if self.steps_in_round > self.steps_per_round:
            self.current_time_budget *= self.increase_ratio
            self.current_time_budget = int(self.current_time_budget)
            self.steps_in_round = 1
        remaining_time = self.total_budget - int(time_elapsed)
        time_budget = min(self.current_time_budget, remaining_time)
        return time_budget
    def __iter__(self):
        while True:
            time_budget = self.get_time_budget()
            if time_budget < 0:
                break
            yield time_budget
        return
    @property
    def elapsed(self):
        return int((datetime.now() - self.start_time).total_seconds())
class SymTuner(ABC):
    def __init__(self, parameter_space=None, exploit_portion=0.7):
        if parameter_space is None:
            self.space = self.get_default_space()
            self.defaults = self.get_default_default_parameters()
            get_logger().info('Parameter space not defined. Default space are loaded.')
        else:
            if isinstance(parameter_space, str):
                parameter_space = Path(parameter_space)
            if isinstance(parameter_space, Path):
                parameter_space_filename = parameter_space
                parameter_space = json.loads(parameter_space.read_text())
                get_logger().info('Parameter space loaded from a file: '
                                  f'{parameter_space_filename}')
            self.space = parameter_space['space']
            self.defaults = parameter_space['defaults']
        self.cnts = {}
        self.len_cnts = {}
        for param, (space, n_sample) in self.space.items():
            self.cnts[param] = {}
            for val in space:
                self.cnts[param][val] = 0
            self.len_cnts[param] = {}
            for i in range(1, n_sample + 1):
                self.len_cnts[param][i] = 0
        self.exploit_portion = exploit_portion
        self.data = []
    def count_used_parameters(self, parameters):
        for param, values in parameters.items():
            if param not in self.space.keys():
                continue
            self.len_cnts[param][len(values)] += 1
            for value in values:
                self.cnts[param][value] += 1
    def sample(self, policy=None):
        if policy is None:
            policy = random.choices(['exploit', 'explore'],
                                    [self.exploit_portion, 1 - self.exploit_portion])[0]
        policy_fn = getattr(self, policy)
        parameters = self.defaults.copy()
        prob_dict = policy_fn(self.data)
        sampled = {}
        for param, (space, n_sample) in self.space.items():
            if len(space) == 0:
                continue
            prob, n_prob = prob_dict[param]
            n_sample = list(range(1, n_sample + 1))
            n_sample = random.choices(n_sample, n_prob)[0]
            sampled[param] = random.choices(space, prob, k=n_sample)
        parameters.update(sampled)
        return parameters
    def normalize(self, a_list):
        if np.sum(a_list) == 0:
            a_list = [1 for _ in a_list]
        a_list = a_list / np.sum(a_list)
        return a_list
    def explore(self, data):
        prob_dict = {}
        for param in self.space.keys():
            prob = []
            for value in self.space[param][0]:
                if value in self.cnts[param].keys() and self.cnts[param][value] > 0:
                    p = 1.0 / self.cnts[param][value]
                    p = round(p, 2)
                else:
                    p = 10
                prob.append(p)
            n_prob = []
            for n in range(1, self.space[param][1] + 1):
                if self.len_cnts[param][n] > 0:
                    p = 1.0 / self.len_cnts[param][n]
                    p = round(p, 2)
                else:
                    p = 10
                n_prob.append(p)
            prob = self.normalize(prob)
            n_prob = self.normalize(n_prob)
            prob_dict[param] = (prob, n_prob)
        return prob_dict
    def exploit(self, data):

        core_parameters = self.extract_core_parameters(data)
        core_cnts = {}
        core_len_cnts = {}
        for param, (_, n_sample) in self.space.items():
            core_cnts[param] = {}

            cnt_keys = self.cnts[param].keys()
            for val in cnt_keys:
                core_cnts[param][val] = 0
            core_len_cnts[param] = {}
            for i in range(1, n_sample + 1):
                core_len_cnts[param][i] = 0
        for parameter in core_parameters:
            for param, values in parameter.items():
                if param not in self.space.keys():
                    continue
                core_len_cnts[param][len(values)] += 1
                for value in values:
                    core_cnts[param][value] += 1
        prob_dict = {}
        for param in self.space.keys():
            prob = []
            for value in self.space[param][0]:
                if value in core_cnts[param].keys() \
                        and value in self.cnts[param].keys() and self.cnts[param][value] > 0:
                    p = core_cnts[param][value] / self.cnts[param][value]
                    p = round(p, 2)
                elif value not in self.cnts[param].keys() or self.cnts[param][value] == 0:
                    p = 10
                else:
                    p = 0
                prob.append(p)
            n_prob = []
            for n in range(1, self.space[param][1] + 1):
                if self.len_cnts[param][n] > 0:
                    p = core_len_cnts[param][n] / self.len_cnts[param][n]
                    p = round(p, 2)
                else:
                    p = 0
                n_prob.append(p)
            prob = self.normalize(prob)
            n_prob = self.normalize(n_prob)
            prob_dict[param] = (prob, n_prob)
        return prob_dict
    def extract_core_parameters(self, data):

        core_paramters = []

        total_coverage = set()
        for cov, _, _, _ in data:
            total_coverage = total_coverage | cov

        accumulated_coverage = set()
        copied_data = deepcopy(data)
        while True:
            if len(copied_data) == 0:
                break
            copied_data = sorted(copied_data,
                                 key=lambda elem: len(elem[0]),
                                 reverse=True)
            top_cov, _, _, param = copied_data.pop(0)
            if len(top_cov) > 0:
                accumulated_coverage = accumulated_coverage | top_cov
                copied_data = [(cov - accumulated_coverage, bug, tc, param)
                               for cov, bug, tc, param in copied_data]
                core_paramters.append(param)
            else:
                break

        found_bugs = []
        for _, bugs, _, param in data[::-1]:
            for bug in bugs:
                if bug not in found_bugs:
                    found_bugs.append(bug)
                    core_paramters.append(param)
        return core_paramters
    def add(self, target, parameters, testcases, evaluation_kwargs=None):
        if evaluation_kwargs is None:
            evaluation_kwargs = {}
        self.count_used_parameters(parameters)
        for testcase in testcases:
            coverage, bug = self.evaluate(target, testcase,
                                          **evaluation_kwargs)
            self.data.append((coverage, bug, testcase, parameters))
        return self
    def get_space_json(self):
        json_dict = {
            'space': self.space,
            'defaults': self.defaults,
        }
        return json_dict
    def get_coverage_and_bugs(self):
        coverage = set()
        bugs = set()
        for cov, bug, _, _ in self.data:
            coverage = coverage | cov
            bugs = bugs | bug
        return coverage, bugs
    def get_testcase_causing_bug(self, bug):
        for _, bugs, tc, _ in self.data[::-1]:
            if bug in bugs:
                return tc
        return None
    @abstractmethod
    def evaluate(self, target, testcase, **kwargs):
        pass
    @abstractclassmethod
    def get_default_space(cls):
        pass
    @classmethod
    def get_default_default_parameters(cls):
        return {}
    @classmethod
    def get_default_space_json(cls):
        json_dict = {
            'space': cls.get_default_space(),
            'defaults': cls.get_default_default_parameters(),
        }
        return json_dict