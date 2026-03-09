from abc import ABC, abstractmethod

class Converter(ABC):
    @abstractmethod
    def convert(self, log_filename, ts_index=True, aggressive_category=True, usecols=None):
        pass
