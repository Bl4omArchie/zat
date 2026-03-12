from zatv2.to_dask import ZeekLogToDask
from zatv2.to_pandas import ZeekLogToPandas
from zatv2.to_spark import ZeekLogToSpark
from zatv2.to_polars import ZeekLogToPolars

from zatv2.reader import ZeekLogReader

import glob


class ZAT:
    def __init__(self, path: str):
        self.path = path

    def read_log(self) -> ZeekLogReader:
        return ZeekLogReader(self.path)

    def to_dask(self):
        obj = ZeekLogToDask()
        obj.convert(path)

    def to_pandas(self):
        obj = ZeekLogToPandas()
        obj.convert(path)

    def to_polars(self):
        obj = ZeekLogToPolars()
        obj.convert(path)

    def to_spark(self):
        pass
