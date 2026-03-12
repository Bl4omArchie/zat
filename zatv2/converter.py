from abc import ABC, abstractmethod

class Converter(ABC):
    @abstractmethod
    def convert(self, path: str) -> "Dataframe":
        pass

    @abstractmethod
    def _get_field_info(self, path: str) -> "FieldInfo":
        pass

    @abstractmethod
    def _get_dataframe(self, path, all_fields, usecols, dtypes) -> "Dataframe":
        pass

    @abstractmethod
    def _apply_type_map(self, field_infos: "FieldInfo"):
        pass
