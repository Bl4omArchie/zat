import fsspec

from zat.base import ZeekLogInfos, Converter
from zat.zeek_log_reader import ZeekLogReader

# Third Party
try:
    from pyspark.sql.types import StructType, StringType, IntegerType, FloatType, LongType, DoubleType
    from pyspark.sql.functions import col, when
except ImportError:
    print('\npip install pyspark')

from typing import Dict
from pandas import DataFrame


class LogToSparkDF(Converter):
    """LogToSparkDF: Converts a Zeek log to a Spark DataFrame"""

    def __init__(self, fs: fsspec.filesystem, spark):
        """Initialize the LogToSparkDF class"""

        # Grab the spark context
        self.spark = spark

        # First Level Type Mapping
        #    This map defines the types used when first reading in the Zeek log into a 'chunk' dataframes.
        #    Types (like time and interval) will be defined as one type at first but then
        #    will undergo further processing to produce correct types with correct values.
        # See: https://spark.apache.org/docs/latest/sql-reference.html
        #      for more info on supported types.
        self.type_map = {'bool': StringType(),   # Secondary Processing into BooleanType()
                         'count': LongType(),
                         'int': IntegerType(),
                         'double': FloatType(),
                         'time': DoubleType(),    # Secondary Processing into TimestampType()
                         'interval': FloatType(),
                         'port': IntegerType(),
                         'enum': StringType(),
                         'addr': StringType(),
                         'string': StringType()
                         }
        
        super().__init__(fs)

    def create_dataframe(self, path: str, fillna=True) -> DataFrame:
        # 1. Get field infos.
        field_infos = self._get_field_info(path)

        # 2. Convert zeek types to polars types.
        #    Replace old types from FieldInfos struct with the converted ones.
        field_infos.types = self._apply_type_map(field_infos)

        # 3. Get dataframe.
        self._df =  self._get_dataframe(path, field_infos)

        fixed_columns = list(map(lambda x: x.replace('.', '_'), self._df.columns))
        self._df = self.self._df.toDF(*fixed_columns)

        # Fill in NULL values
        if fillna:
            self._df = self._df.na.fill(0)    # For numeric columns
            self._df = self._df.na.fill('-')  # For string columns

        # Convert timestamp and boolean columns
        for name, f_type in zip(field_infos.names, field_infos.types):
            # Some field names may have '.' in them, so we create a reference name to those fields
            ref_name = name.replace('.', '_')
            if f_type == 'time':
                self._df = self._df.withColumn(name, self._df[ref_name].cast('timestamp'))
            if f_type == 'bool':
                self._df = self._df.withColumn(name, when(col(ref_name) == 'T', 'true').when(col(ref_name) == 'F', 'false')
                                     .otherwise('null').cast('boolean'))

        # Return the spark dataframe
        return self.self._df

    def _get_dataframe(self, log_infos: ZeekLogInfos, usecols) -> DataFrame:
        spark_schema = self.build_spark_schema(log_infos.field_names, log_infos.field_types)

        # Now actually read the Zeek Log using Spark read CSV
        return self.spark.read.csv(log_infos.path, schema=spark_schema, sep='\t', comment="#", nullValue='-')

    def _apply_type_map(self, log_infos: ZeekLogInfos, verbose: bool) -> Dict:
        """Given a set of names and types, construct a dictionary to be used
           as the Spark read_csv dtypes argument"""

        # If we don't know the type put it into a string
        unknown_type = StringType()

        schema = StructType()
        for name, zeek_type in zip(log_infos.field_names, log_infos.field_types):

            # Grab the type
            spark_type = self.type_map.get(zeek_type)

            # Sanity Check
            if not spark_type:
                if verbose:
                    print('Could not find type for {:s} using StringType...'.format(zeek_type))
                spark_type = unknown_type

            # Add the Spark type for this column
            schema.add(name, spark_type)

        # Return the Spark schema
        return schema



# Simple test of the functionality
def test():
    """Test for LogToSparkDF Class"""
    import os
    import pytest
    from zat.utils import file_utils

    try:
        from pyspark.sql import SparkSession
    except ImportError:
        pytest.skip('pip install pyspark')

    # Spin up a local Spark Session (with 4 executors)
    spark = SparkSession.builder.master('local[4]').appName('my_awesome').getOrCreate()

    # Grab a test file
    data_path = file_utils.relative_dir(__file__, '../data')
    log_path = os.path.join(data_path, 'ftp.log')

    # Convert it to a Spark DataFrame
    log_to_spark = LogToSparkDF(spark)
    spark_df = log_to_spark.create_dataframe(log_path)

    # Print out the head
    print(spark_df.show())

    # Print out the datatypes
    print(spark_df.printSchema())

    num_rows = spark_df.count()
    print("Number of Spark DataFrame rows: {:d}".format(num_rows))
    columns = spark_df.columns
    print("Columns: {:s}".format(','.join(columns)))

    # Test a bunch
    tests = ['app_stats.log', 'dns.log', 'http.log', 'notice.log', 'tor_ssl.log',
             'conn.log', 'dhcp.log', 'dhcp_002.log', 'files.log',  'smtp.log', 'weird.log',
             'ftp.log',  'ssl.log', 'x509.log']
    for log_path in [os.path.join(data_path, log) for log in tests]:
        print('Testing: {:s}...'.format(log_path))
        spark_df = log_to_spark.create_dataframe(log_path)
        print(spark_df.show())
        print(spark_df.printSchema())

    # Test an empty log (a log with header/close but no data rows)
    log_path = os.path.join(data_path, 'http_empty.log')
    spark_df = log_to_spark.create_dataframe(log_path)
    print(spark_df.show())
    print(spark_df.printSchema())

    print('LogToSparkDF Test successful!')


if __name__ == '__main__':
    # Run the test for easy testing/debugging
    test()
