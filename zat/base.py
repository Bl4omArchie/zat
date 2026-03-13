from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Dict

from pandas import DataFrame


@dataclass
class FieldInfos:
    names: List[str]
    types: List[str]


class Converter(ABC):
    @abstractmethod
    def create_dataframe(self, path: str) -> DataFrame:
        pass

    @abstractmethod
    def _get_field_info(self, path: str) -> FieldInfos:
        pass

    @abstractmethod
    def _get_dataframe(self, path: str, field_infos: FieldInfos, usecols) -> DataFrame:
        pass

    @abstractmethod
    def _apply_type_map(self, field_infos: FieldInfos):
        pass
