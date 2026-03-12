from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Dict

from pandas import DataFrame


@dataclass
class FieldInfos:
    names: List[str]
    types: List[str]

@dataclass
class DataFrameInfos:
    path: str
    sep: str
    null_values: List[str]
    comment_prefix: str


class Converter(ABC):
    @abstractmethod
    def convert(self, path: str) -> DataFrame:
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
