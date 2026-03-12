from typing import Dict

from zatv2.base import Converter, FieldInfos
from zatv2.reader import ZeekLogReader

from pandas import DataFrame
import dask.dataframe as dd


class ZeekLogToDask(Converter):
    def __init__(self):
        self.type_map = {'bool': 'category',  # Can't hold NaN values in 'bool', so we're going to use category
                        'count': 'UInt64',
                        'int': 'Int32',
                        'double': 'float',
                        'time': 'float',      # Secondary Processing into datetime
                        'interval': 'float',  # Secondary processing into timedelta
                        'port': 'UInt16'
                        }


    def convert(self, path: str) -> DataFrame:
        # 1. Get field infos.
        field_infos = self._get_field_info(path)

        # 2. Convert zeek types to polars types.
        #    Replace old types from FieldInfos struct with the converted ones.
        field_infos.types = self._apply_type_map(field_infos)

        # 3. Get dataframe.
        self._df =  self._get_dataframe(path, field_infos)

        # 4. Convert time type.
        time_cols = [name for name, zt in zip(field_infos.names, field_infos.types) if zt == "time"]
        interval_cols = [name for name, zt in zip(field_infos.names, field_infos.types) if zt == "interval"]

        if time_cols:
            self._df = self._df.with_columns(
                [dd.from_epoch(dd.col(c), time_unit="s") for c in time_cols]
            )

        if interval_cols:
            self._df = self._df.with_columns(
                [(dd.col(c) * 1000).cast(dd.Duration("ms")) for c in interval_cols]
            )

        return self._df


    def _get_field_info(self, path: str) -> FieldInfos:
        """Internal Method: Use ZAT log reader to read header for names and types"""
        _zeek_reader = ZeekLogReader(path)
        _, field_names, field_types, _ = _zeek_reader._parse_zeek_header(path)
        
        return FieldInfos(names=field_names, types=field_types)


    def _get_dataframe(self, path, field_infos: FieldInfos) -> DataFrame:
        """Internal Method: Create the initial dataframes by using Pandas read CSV (primary types correct)"""
        return dd.read_csv(path, sep='\t', names=field_infos.names, dtype=field_infos.types, comment="#", na_values=["-", "NA", ""])


    def _apply_type_map(self, field_infos: FieldInfos, aggressive_category:bool = True, verbose: bool = False) -> Dict:
        unknown_type = 'category' if aggressive_category else 'object'

        dask_types_map = {}
        for name, zeek_type in zip(field_infos.names, field_infos.types):

            # Grab the type
            item_type = self.type_map.get(zeek_type)

            # Sanity check
            if not item_type:
                # UID/FUID/GUID always gets mapped to object
                if 'uid' in name:
                    item_type = 'object'
                else:
                    if verbose:
                        print('Could not find type for {:s} using {:s}...'.format(zeek_type, unknown_type))
                    item_type = unknown_type


            # Set the pandas type
            dask_types_map[name] = item_type

        return dask_types_map
