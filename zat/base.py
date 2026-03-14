from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional, List, Dict

import fsspec
from pandas import DataFrame

from zat.zeek_log_reader import ZeekLogReader



@dataclass
class ZeekLogInfos:
    path: str
    extension: str
    field_names: List[str]
    field_types: List[str]


class Converter(ABC):
    @abstractmethod
    def create_dataframe(self, path: str) -> DataFrame:
        pass

    @abstractmethod
    def _get_dataframe(self, type_map, log_infos: ZeekLogInfos, usecols: Optional[List[str]]) -> DataFrame:
        pass

    @abstractmethod
    def _apply_type_map(self, log_infos: ZeekLogInfos) -> Dict:
        pass

    def _get_log_info(self, path: str) -> ZeekLogInfos:
        _zeek_reader = ZeekLogReader(path)
        _, field_names, field_types, _ = _zeek_reader._parse_zeek_header(path)
        return ZeekLogInfos(path=path, extension=_zeek_reader._extension, field_names = field_names, field_types = field_types)
