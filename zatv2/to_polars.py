from zatv2.converter import Converter
from zat import zeek_log_reader
import polars as pl


class ZeekLogToPolars(Converter):
    def __init__(self):
        # Polars data types : https://docs.pola.rs/api/python/stable/reference/datatypes.html
        self.type_map = {
            'str': pl.String,
            'bool': pl.Boolean,
            'count': pl.UInt64,
            'int': pl.Int32,
            'double': pl.Float64,
            'time': pl.Datetime("ms"),
            'interval': pl.Duration("ms"),
            'port': pl.UInt16
        }

    def convert(self, path, ts_index=True, aggressive_category=True, usecols=None):
        """ Create a Pandas dataframe from a Bro/Zeek log file
            Args:
               log_fllename (string): The full path to the Zeek log
               ts_index (bool): Set the index to the 'ts' field (default = True)
               aggressive_category (bool): convert unknown columns to category (default = True)
               usecol (list): A subset of columns to read in (minimizes memory usage) (default = None)
        """

        # Grab the field information
        field_names, field_types = self._get_field_info(path)
        all_fields = field_names  # We need ALL the fields for later

        # If usecols is set then we'll subset the fields and types
        if usecols:
            # Usecols needs to include ts
            if 'ts' not in usecols:
                usecols.append('ts')
            field_types = [t for t, field in zip(field_types, field_names) if field in usecols]
            field_names = [field for field in field_names if field in usecols]

        # Get the appropriate types for the Pandas Dataframe
        pandas_types = self.pd_column_types(field_names, field_types, aggressive_category)

        # Now actually read in the initial dataframe
        self._df = self._create_initial_df(path, all_fields, usecols, pandas_types)

        # Now we convert 'time' and 'interval' fields to datetime and timedelta respectively
        for name, zeek_type in zip(field_names, field_types):
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

    def _get_field_info(self, path):
        """Internal Method: Use ZAT log reader to read header for names and types"""
        _zeek_reader = zeek_log_reader.ZeekLogReader(path)
        _, field_names, field_types, _ = _zeek_reader._parse_zeek_header(path)
        return field_names, field_types

    def _create_initial_df(self, path, all_fields, usecols, dtypes):
        """Internal Method: Create the initial dataframes by using Pandas read CSV (primary types correct)"""
        return pl.read_csv(path, separator='\t', columns=all_fields, schema_overrides=dtypes, comment_prefix="#yy")

    def pd_column_types(self, column_names, column_types, aggressive_category=True, verbose=False):
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
