from zatv2.converter import Converter
from zat import zeek_log_reader
import polars as pl

from dataclasses import dataclass
from typing import List, Dict


@dataclass
class FieldInfos():
    names: List[str]
    types: List[str]


class ZeekLogToPolars(Converter):
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

    def convert(self, path: str) -> "Dataframe":
        # 1. Get field infos
        field_infos = self._get_field_info(path)

        # 2. Convert zeek types to polars types
        polars_types_map = self._apply_type_map(field_infos)

        print(polars_types_map)

        # 3. Get dataframe
        self._df =  self._get_dataframe(path, field_infos.names, polars_types_map)

        # 4. Convert time type
        time_cols = [name for name, zt in zip(field_infos.names, field_infos.types) if zt == "time"]
        interval_cols = [name for name, zt in zip(field_infos.names, field_infos.types) if zt == "interval"]

        if time_cols:
            self._df = self._df.with_columns(
                [pl.from_epoch(pl.col(c), time_unit="s") for c in time_cols]
            )

        if interval_cols:
            self._df = self._df.with_columns(
                [(pl.col(c) * 1000).cast(pl.Duration("ms")) for c in interval_cols]
            )

        return self._df


    def _get_field_info(self, path: str) -> "FieldInfos":
        """Internal Method: Use ZAT log reader to read header for names and types"""
        _zeek_reader = zeek_log_reader.ZeekLogReader(path)
        _, field_names, field_types, _ = _zeek_reader._parse_zeek_header(path)
        
        return FieldInfos(names=field_names, types=field_types)


    def _get_dataframe(self, path, all_fields, dtypes) -> "Dataframe":
        """Internal Method: Create the initial dataframes by using Pandas read CSV (primary types correct)"""
        return pl.read_csv(path, separator='\t', has_header=False, new_columns=all_fields, schema_overrides=dtypes, comment_prefix="#", null_values=["-", "NA", ""])


    def _apply_type_map(self, field_infos: "FieldInfos") -> Dict:
        polars_types_map = {}
        for name, zeek_type in zip(field_infos.names, field_infos.types):

            # Grab the type
            item_type = self.type_map.get(zeek_type)

            # Sanity Check
            if not item_type:
                item_type = pl.String


            # Set the pandas type
            polars_types_map[name] = item_type

        return polars_types_map
