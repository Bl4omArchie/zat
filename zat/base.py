from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Tuple

from zat.zeek_log_reader import ZeekLogReader



class Converter(ABC):
    @abstractmethod
    def create_dataframe(self, log_filename: str, usecols: Optional[List[str]]):
        pass

    @abstractmethod
    def _get_dataframe(self, log_filename: str, all_fields: List[str], dtypes: Dict):
        pass

    @abstractmethod
    def _apply_type_map(self, column_names: List[str], column_types: List[str]) -> Dict:
        pass

    def _get_field_info(self, log_filename: str) -> Tuple[List[str], List[str]]:
        _zeek_reader = ZeekLogReader(log_filename)
        _, field_names, field_types, _ = _zeek_reader._parse_zeek_header(log_filename)
        return field_names, field_types
