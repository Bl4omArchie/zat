from zatv2.base import Converter, FieldInfos
from zat import zeek_log_reader

import pandas as pd


class ZeekLogToPandas(Converter):
    def __init__(self):
        self.type_map = {'bool': 'category',  # Can't hold NaN values in 'bool', so we're going to use category
                        'count': 'UInt64',
                        'int': 'Int32',
                        'double': 'float',
                        'time': 'float',      # Secondary Processing into datetime
                        'interval': 'float',  # Secondary processing into timedelta
                        'port': 'UInt16'
                        }


    def convert(self, path: str, ts_index: bool =True, aggressive_category: bool =True, usecols:bool =None):
        """ Create a Pandas dataframe from a Bro/Zeek log file
            Args:
               log_fllename (string): The full path to the Zeek log
               ts_index (bool): Set the index to the 'ts' field (default = True)
               aggressive_category (bool): convert unknown columns to category (default = True)
               usecol (list): A subset of columns to read in (minimizes memory usage) (default = None)
        """

        # 1. Get field infos.
        field_infos = self._get_field_info(path)

        # If usecols is set then we'll subset the fields and types
        if usecols:
            # Usecols needs to include ts
            if 'ts' not in usecols:
                usecols.append('ts')
            field_types = [t for t, field in zip(field_infos.types, field_infos.names) if field in usecols]
            field_names = [field for field in field_infos.names if field in usecols]

        # Get the appropriate types for the Pandas Dataframe
        field_infos.types = self._apply_type_map(field_infos, aggressive_category)

        # Now actually read in the initial dataframe
        self._df = self._get_dataframe(path, field_infos, usecols)

        # Now we convert 'time' and 'interval' fields to datetime and timedelta respectively
        for name, zeek_type in zip(field_infos.names, field_infos.types):
            if zeek_type == 'time':
                self._df[name] = pd.to_datetime(self._df[name], unit='s')
            if zeek_type == 'interval':
                self._df[name] = pd.to_timedelta(self._df[name], unit='s')

        # Set the index
        if ts_index and not self._df.empty:
            try:
                self._df.set_index('ts', inplace=True)
            except KeyError:
                print('Could not find ts/timestamp for index...')
        return self._df

    def _get_field_info(self, path: str) -> FieldInfos:
        """Internal Method: Use ZAT log reader to read header for names and types"""
        _zeek_reader = zeek_log_reader.ZeekLogReader(path)
        _, field_names, field_types, _ = _zeek_reader._parse_zeek_header(path)
        return FieldInfos(names=field_names, types=field_types)

    def _get_dataframe(self, path: str, field_infos: FieldInfos, usecols: bool):
        """Internal Method: Create the initial dataframes by using Pandas read CSV (primary types correct)"""
        return pd.read_csv(path, sep='\t', names=field_infos.names, usecols=usecols, dtype=field_infos.types, comment="#", na_values='-')

    def _apply_type_map(self, fiel_infos: FieldInfos, aggressive_category: bool = True, verbose: bool = False):
        """Given a set of names and types, construct a dictionary to be used
           as the Pandas read_csv dtypes argument"""

        # Aggressive Category means that types not in the current type_map are
        # mapped to a 'category' if aggressive_category is False then they
        # are mapped to an 'object' type
        unknown_type = 'category' if aggressive_category else 'object'

        pandas_types_map = {}
        for name, zeek_type in zip(fiel_infos.names, fiel_infos.types):

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
            pandas_types_map[name] = item_type

        # Return the dictionary of name: type
        return pandas_types_map
