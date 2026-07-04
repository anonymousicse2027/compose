from abc import ABC
from abc import abstractmethod
class SymbolicExecutor(ABC):
    @abstractmethod
    def run(self, target, parameters, **kwargs):
        pass
    @abstractmethod
    def get_time_parameter(self):
        pass