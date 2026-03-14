# Third Party
from typing import Dict
from pandas import DataFrame
import polars as pl

# Local
from zat.base import  Converter


class LogToPolars(Converter):
    def __init__(self):
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
        
    
    def create_dataframe(self, log_filename: str) -> DataFrame:
        # 1. Get field infos.
        field_names, field_types = self._get_log_info(log_filename)

        # 2. Convert zeek types to polars types.
        #    Replace old types from FieldInfos struct with the converted ones.
        type_map = self._apply_type_map(field_names, field_types)

        # 3. Get dataframe.
        self._df =  self._get_dataframe(type_map, )

        # 4. Convert time type.
        time_cols = [name for name, zt in zip(field_names, field_types) if zt == "time"]
        interval_cols = [name for name, zt in zip(field_names, field_types) if zt == "interval"]

        if time_cols:
            self._df = self._df.with_columns(
                [pl.from_epoch(pl.col(c), time_unit="s") for c in time_cols]
            )

        if interval_cols:
            self._df = self._df.with_columns(
                [(pl.col(c) * 1000).cast(pl.Duration("ms")) for c in interval_cols]
            )

        return self._df
  
    def _get_dataframe(self, log_filename: str, type_map: dict, field_names) -> DataFrame:
        """Internal Method: Create the initial dataframes by using Pandas read CSV (primary types correct)"""
        return pl.read_csv(log_filename, separator='\t', has_header=False, new_columns=field_names, schema_overrides=type_map, comment_prefix="#", null_values=["-", "NA", ""])

    def _apply_type_map(self, column_names, column_types) -> Dict:
        polars_types_map = {}
        for name, zeek_type in zip(column_names, column_types):

            # Grab the type
            item_type = self.type_map.get(zeek_type)

            # Sanity Check
            if not item_type:
                item_type = pl.String


            # Set the pandas type
            polars_types_map[name] = item_type

        return polars_types_map


def test():
    obj = LogToPolars()
    obj.create_dataframe("data/conn.log")
