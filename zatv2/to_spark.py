from zatv2.base import Converter, FieldInfos
from zatv2.reader import ZeekLogReader

# Third Party
try:
    from pyspark.sql.types import StructType, StringType, IntegerType, FloatType, LongType, DoubleType
    from pyspark.sql.functions import col, when
except ImportError:
    print('\npip install pyspark')


from pandas import DataFrame


class ZeekLogToPandas(Converter):
    """LogToSparkDF: Converts a Zeek log to a Spark DataFrame"""

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

    def convert(self, path: str, fillna=True) -> DataFrame:
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

    def _get_field_info(self, path: str) -> FieldInfos:
        _zeek_reader = ZeekLogReader(path)
        _, field_names, field_types, _ = _zeek_reader._parse_zeek_header(path)
        return FieldInfos(names=field_names, types=field_types)

    def _get_dataframe(self, path: str, field_infos: FieldInfos, usecols) -> DataFrame:
        spark_schema = self.build_spark_schema(field_infos.names, field_infos.types)

        # Now actually read the Zeek Log using Spark read CSV
        return self.spark.read.csv(path, schema=spark_schema, sep='\t', comment="#", nullValue='-')

    def _apply_type_map(self, field_infos: FieldInfos, verbose:bool = False):
        """Given a set of names and types, construct a dictionary to be used
           as the Spark read_csv dtypes argument"""

        # If we don't know the type put it into a string
        unknown_type = StringType()

        schema = StructType()
        for name, zeek_type in zip(field_infos.names, field_infos.types):

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
