from typing import Dict, List, Optional

from zat.base import Converter

from pandas import DataFrame
import dask.dataframe as dd


class LogToDask(Converter):
    def __init__(self):
        self.type_map = {'bool': 'category',  # Can't hold NaN values in 'bool', so we're going to use category
                        'count': 'UInt64',
                        'int': 'Int32',
                        'double': 'float',
                        'time': 'float',      # Secondary Processing into datetime
                        'interval': 'float',  # Secondary processing into timedelta
                        'port': 'UInt16',
                        'addr': 'string'
                        }


    def create_dataframe(self, log_filename: str, ts_index: bool = True, aggressive_category: bool = True, usecols:Optional[List[str]] =None):
        """ Create a Dask dataframe from a Bro/Zeek log file
            Args:
               log_filename (string): The full path to the Zeek log
               ts_index (bool): Set the index to the 'ts' field (default = True)
               aggressive_category (bool): convert unknown columns to category (default = True)
               usecol (list): A subset of columns to read in (minimizes memory usage) (default = None)
        """

        # 1. Get log infos.
        field_names, fiel_types = self._get_log_info(log_filename)
        all_fields = field_names

        # If usecols is set then we'll subset the fields and types
        if usecols:
            # Usecols needs to include ts
            if 'ts' not in usecols:
                usecols.append('ts')
            field_types = [t for t, field in zip(field_types, field_names) if field in usecols]
            field_names = [field for field in field_names if field in usecols]

        # Get the appropriate types for the Pandas Dataframe
        type_map = self._apply_type_map(aggressive_category)

        # Now actually read in the initial dataframe
        self._df = self._get_dataframe(log_filename, all_fields, type_map, usecols)

        # Now we convert 'time' and 'interval' fields to datetime and timedelta respectively
        for name, zeek_type in zip(field_names, field_types):
            if zeek_type == 'time':
                self._df[name] = dd.to_datetime(self._df[name], unit='s')
            if zeek_type == 'interval':
                self._df[name] = dd.to_timedelta(self._df[name], unit='s')

        # Set the index
        if ts_index and not self._df.empty:
            try:
                self._df.set_index('ts', inplace=True)
            except KeyError:
                print('Could not find ts/timestamp for index...')
        return self._df
    


    def _get_dataframe(self, log_filename: str, all_fields, usecols: Optional[List[str]], dtypes):
        """Internal Method: Create the initial dataframes by using dask read CSV (primary types correct)"""
        return dd.read_csv(log_filename, sep='\t', names=all_fields, usecols=usecols, dtype=dtypes, comment="#", na_values='-')


    def _apply_type_map(self, column_names, column_types, aggressive_category: bool = True, verbose: bool = False) -> Dict:
        """Given a set of names and types, construct a dictionary to be used
           as the Pandas read_csv dtypes argument"""

        # Aggressive Category means that types not in the current type_map are
        # mapped to a 'category' if aggressive_category is False then they
        # are mapped to an 'object' type
        unknown_type = 'category' if aggressive_category else 'object'

        pandas_types = {}
        for name, zeek_type in zip(column_names, column_types):

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
            pandas_types[name] = item_type

        # Return the dictionary of name: type
        return pandas_types



def test():
    obj = LogToDask()
    obj.create_dataframe("data/conn.log")
