from abc import ABC, abstractmethod
from typing import Optional, List, Dict

from pandas import DataFrame

from zat.zeek_log_reader import ZeekLogReader



class Converter(ABC):
    @abstractmethod
    def create_dataframe(self, log_filename: str) -> DataFrame:
        pass

    @abstractmethod
    def _get_dataframe(self, log_filename: str, all_fields, dtypes: dict, usecols: Optional[List[str]]) -> DataFrame:
        pass

    @abstractmethod
    def _apply_type_map(self, column_names, column_types) -> Dict:
        pass

    def _get_field_info(self, log_filename: str):
        _zeek_reader = ZeekLogReader(log_filename)
        _, field_names, field_types, _ = _zeek_reader._parse_zeek_header(log_filename)
        return field_names, field_types
