"""LogToDataFrame: create_dataframes a Zeek log to a Pandas DataFrame"""


# Third Party
from typing import List, Dict, Optional
import fsspec
import pandas as pd

# Local
from zat.base import ZeekLogInfos, Converter


class LogToDataFrame(Converter):
    """LogToDataFrame: create_dataframes a Zeek log to a Pandas DataFrame
        Notes:
            This class has recently been overhauled from a simple loader to a more
            complex class that should in theory:
              - Select better types for each column
              - Should be faster
              - Produce smaller memory footprint dataframes
            If you have any issues/problems with this class please submit a GitHub issue.
        More Info: https://supercowpowers.github.io/zat/large_dataframes.html
    """
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


    def create_dataframe(self, path: str, ts_index: bool = True, aggressive_category: bool = True, usecols:Optional[List[str]] =None):
        """ Create a Pandas dataframe from a Bro/Zeek log file
            Args:
               log_fllename (string): The full path to the Zeek log
               ts_index (bool): Set the index to the 'ts' field (default = True)
               aggressive_category (bool): convert unknown columns to category (default = True)
               usecol (list): A subset of columns to read in (minimizes memory usage) (default = None)
        """

        # 1. Get log infos.
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
    
    
    def _get_dataframe(self, type_map, log_infos: ZeekLogInfos, usecols: Optional[List[str]]):
        """Internal Method: Create the initial dataframes by using Pandas read CSV (primary types correct)"""
        return pd.read_csv(log_infos.path, sep='\t', names=log_infos.field_names, usecols=usecols, dtype=type_map, comment="#", na_values='-')


    def _apply_type_map(self, log_infos: ZeekLogInfos, aggressive_category: bool = True, verbose: bool = False) -> Dict:
        """Given a set of names and types, construct a dictionary to be used
           as the Pandas read_csv dtypes argument"""

        # Aggressive Category means that types not in the current type_map are
        # mapped to a 'category' if aggressive_category is False then they
        # are mapped to an 'object' type
        unknown_type = 'category' if aggressive_category else 'object'

        pandas_types_map = {}
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
            pandas_types_map[name] = item_type

        # Return the dictionary of name: type
        return pandas_types_map


# Simple test of the functionality
def test():
    """Test for LogToDataFrame Class"""
    import os
    pd.set_option('display.width', 1000)
    from zat.utils import file_utils

    # Grab a test file
    data_path = file_utils.relative_dir(__file__, '../data')
    log_path = os.path.join(data_path, 'conn.log')

    # Fsspec
    fs = fsspec.filesystem("local")

    # create_dataframe it to a Pandas DataFrame
    log_to_df = LogToDataFrame(fs)
    my_df = log_to_df.create_dataframe(log_path)

    # Print out the head
    print(my_df.head())

    # Print out the datatypes
    print(my_df.dtypes)

    # Test a bunch
    tests = ['app_stats.log', 'dns.log', 'http.log', 'notice.log', 'tor_ssl.log',
             'conn.log', 'dhcp_002.log', 'files.log',  'smtp.log', 'weird.log',
             'ftp.log',  'ssl.log', 'x509.log']
    for log_path in [os.path.join(data_path, log) for log in tests]:
        print('Testing: {:s}...'.format(log_path))
        my_df = log_to_df.create_dataframe(log_path)
        print(my_df.head())
        print(my_df.dtypes)

    # Test out usecols arg
    conn_path = os.path.join(data_path, 'conn.log')
    my_df = log_to_df.create_dataframe(conn_path, usecols=['id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
                                                           'proto', 'orig_bytes', 'resp_bytes'])

    # Test an empty log (a log with header/close but no data rows)
    log_path = os.path.join(data_path, 'http_empty.log')
    my_df = log_to_df.create_dataframe(log_path)

    # Print out the head
    print(my_df.head())

    # Print out the datatypes
    print(my_df.dtypes)

    print('LogToDataFrame Test successful!')


if __name__ == '__main__':
    # Run the test for easy testing/debugging
    test()
