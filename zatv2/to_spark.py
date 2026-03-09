from zatv2.converter import Converter
from zat import zeek_log_reader


try:
    from pyspark.sql.types import StructType, StringType, IntegerType, FloatType, LongType, DoubleType
    from pyspark.sql.functions import col, when
except ImportError:
    print('\npip install pyspark')


class ZeekLogToSpark(Converter):
    def __init__(self, spark):
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

    def convert(self, log_filename, fillna=True):
        """ Create a Spark dataframe from a Bro/Zeek log file
            Args:
               log_fllename (string): The full path to the Zeek log
               fillna (bool): Fill in NA/NaN values (default=True)
        """

        # Create a Zeek log reader just to read in the header for names and types
        _zeek_reader = zeek_log_reader.ZeekLogReader(log_filename)
        _, field_names, field_types, _ = _zeek_reader._parse_zeek_header(log_filename)

        # Get the appropriate types for the Spark Dataframe
        spark_schema = self.build_spark_schema(field_names, field_types)

        # Now actually read the Zeek Log using Spark read CSV
        _df = self.spark.read.csv(log_filename, schema=spark_schema, sep='\t', comment="#", nullValue='-')

        ''' Secondary processing (cleanup)
            - Fix column names with '.' in them
            - Fill in Nulls (optional)
            - timestamp convert
            - boolean convert
        '''

        # Fix column names
        ''' Note: Yes column names with '.' in them can be escaped with backticks when selecting them BUT
                  many pipeline operations will FAIL internally if the column names have a '.' in them.
        '''
        fixed_columns = list(map(lambda x: x.replace('.', '_'), _df.columns))
        _df = _df.toDF(*fixed_columns)

        # Fill in NULL values
        if fillna:
            _df = _df.na.fill(0)    # For numeric columns
            _df = _df.na.fill('-')  # For string columns

        # Convert timestamp and boolean columns
        for name, f_type in zip(field_names, field_types):
            # Some field names may have '.' in them, so we create a reference name to those fields
            ref_name = name.replace('.', '_')
            if f_type == 'time':
                _df = _df.withColumn(name, _df[ref_name].cast('timestamp'))
            if f_type == 'bool':
                _df = _df.withColumn(name, when(col(ref_name) == 'T', 'true').when(col(ref_name) == 'F', 'false')
                                     .otherwise('null').cast('boolean'))

        # Return the spark dataframe
        return _df

    def build_spark_schema(self, column_names, column_types, verbose=False):
        """Given a set of names and types, construct a dictionary to be used
           as the Spark read_csv dtypes argument"""

        # If we don't know the type put it into a string
        unknown_type = StringType()

        schema = StructType()
        for name, zeek_type in zip(column_names, column_types):

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
