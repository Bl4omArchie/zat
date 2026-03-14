# Third Party
from typing import Dict
import fsspec
from pandas import DataFrame
import polars as pl

# Local
from zat.base import ZeekLogInfos, Converter


class LogToPolars(Converter):
    def __init__(self, fs: fsspec.filesystem):
        # Polars data types : https://docs.pola.rs/api/python/stable/reference/datatypes.html
        self.type_map = {
            'str': pl.String,
            'addr': pl.String,
            'table[string]': pl.String,
            'bool': pl.Categorical,
            'double': pl.Float64,
            'time': pl.Float64,
            'interval': pl.Float64,
            'int': pl.Int32,
            'count': pl.UInt64,
            'port': pl.UInt16,
            'enum': pl.Categorical,
        }
        
        super().__init__(fs)
    
    def create_dataframe(self, path: str) -> DataFrame:
        # 1. Get field infos.
        log_infos = self._get_log_info(path)

        # 2. Convert zeek types to polars types.
        #    Replace old types from FieldInfos struct with the converted ones.
        type_map = self._apply_type_map(log_infos)

        # 3. Get dataframe.
        self._df =  self._get_dataframe(type_map, log_infos)

        # 4. Convert time type.
        time_cols = [name for name, zt in zip(log_infos.field_names, log_infos.field_types) if zt == "time"]
        interval_cols = [name for name, zt in zip(log_infos.field_names, log_infos.field_types) if zt == "interval"]

        if time_cols:
            self._df = self._df.with_columns(
                [pl.from_epoch(pl.col(c), time_unit="s") for c in time_cols]
            )

        if interval_cols:
            self._df = self._df.with_columns(
                [(pl.col(c) * 1000).cast(pl.Duration("ms")) for c in interval_cols]
            )

        return self._df
  
    def _get_dataframe(self, type_map: dict, log_infos: ZeekLogInfos) -> DataFrame:
        """Internal Method: Create the initial dataframes by using Pandas read CSV (primary types correct)"""
        return pl.read_csv(log_infos.path, separator='\t', has_header=False, new_columns=log_infos.field_names, schema_overrides=type_map, comment_prefix="#", null_values=["-", "NA", ""])

    def _apply_type_map(self, log_infos: ZeekLogInfos) -> Dict:
        polars_types_map = {}
        for name, zeek_type in zip(log_infos.field_names, log_infos.field_types):

            # Grab the type
            item_type = self.type_map.get(zeek_type)

            # Sanity Check
            if not item_type:
                item_type = pl.String


            # Set the pandas type
            polars_types_map[name] = item_type

        return polars_types_map


def test():
    fs = fsspec.filesystem("local")
    obj = LogToPolars(fs)
    obj.create_dataframe("data/conn.log")
