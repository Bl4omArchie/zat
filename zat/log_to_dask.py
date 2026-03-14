from typing import Dict, List, Optional

import fsspec

from zat.base import Converter, ZeekLogInfos

from pandas import DataFrame
import dask.dataframe as dd


class LogToDask(Converter):
    def __init__(self, fs: fsspec.filesystem):
        self.type_map = {'bool': 'category',  # Can't hold NaN values in 'bool', so we're going to use category
                        'count': 'UInt64',
                        'int': 'Int32',
                        'double': 'float',
                        'time': 'float',      # Secondary Processing into datetime
                        'interval': 'float',  # Secondary processing into timedelta
                        'port': 'UInt16'
                        }
        
        super().__init__(fs)


    def create_dataframe(self, path: str, ts_index: bool = True, aggressive_category: bool = True, usecols:Optional[List[str]] = None):
        """ Create a Dask dataframe from a single Bro/Zeek log file
            Args:
               log_fllename (string): The full path to the Zeek log
               ts_index (bool): Set the index to the 'ts' field (default = True)
               aggressive_category (bool): convert unknown columns to category (default = True)
               usecol (list): A subset of columns to read in (minimizes memory usage) (default = None)
        """

        # 1. Get field infos.
        log_infos = self._get_log_info(path)

        # If usecols is set then we'll subset the fields and types
        if usecols:
            # Usecols needs to include ts
            if 'ts' not in usecols:
                usecols.append('ts')
            log_infos.field_types = [t for t, field in zip(log_infos.field_types, log_infos.field_names) if field in usecols]
            log_infos.field_names = [field for field in log_infos.field_names if field in usecols]

        # Get the appropriate types for the Pandas Dataframe
        type_map = self._apply_type_map(log_infos, aggressive_category)

        # Now actually read in the initial dataframe
        self._df = self._get_dataframe(type_map, log_infos, usecols)

        # Now we convert 'time' and 'interval' fields to datetime and timedelta respectively
        for name, zeek_type in zip(log_infos.field_names, log_infos.field_types):
            if zeek_type == 'time':
                self._df[name] = dd.to_datetime(self._df[name], unit='s')
            if zeek_type == 'interval':
                self._df[name] = dd.to_timedelta(self._df[name], unit='s')

        # Set the index
        if len(self._df.index) == 0:
            try:
                self._df.set_index('ts', inplace=True)
            except KeyError:
                print('Could not find ts/timestamp for index...')
        return self._df


    def _get_dataframe(self, type_map: dict, log_infos: ZeekLogInfos, usecols) -> DataFrame:
        """Internal Method: Create the initial dataframes by using Pandas read CSV (primary types correct)"""
        return dd.read_csv(log_infos.path, sep='\t', names=log_infos.field_names, usecols=usecols, dtype=type_map, comment="#", na_values=["-", "NA", ""])


    def _apply_type_map(self, log_infos: ZeekLogInfos, aggressive_category: bool = True, verbose: bool = False) -> Dict:
        """Given a set of names and types, construct a dictionary to be used
           as the dask read_csv dtypes argument"""

        # Aggressive Category means that types not in the current type_map are
        # mapped to a 'category' if aggressive_category is False then they
        # are mapped to an 'object' type
        unknown_type = 'category' if aggressive_category else 'object'

        dask_types_map = {}
        for name, zeek_type in zip(log_infos.field_names, log_infos.field_types):

            # Grab the type
            item_type = self.type_map.get(zeek_type)

            # Sanity Check
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

        # Return the dictionary of name: type
        return dask_types_map


def test():
    fs = fsspec.filesystem("local")
    obj = LogToDask(fs)
    obj.create_dataframe("data/conn.log")
