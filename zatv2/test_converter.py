from zatv2.to_dask import ZeekLogToDask
from zatv2.to_pandas import ZeekLogToPandas
from zatv2.to_polars import ZeekLogToPolars


path = "data/conn.log"

def test_to_pandas():
    obj = ZeekLogToPandas()
    pf = obj.convert(path)

    print(pf.head)

def test_to_polars():
    obj = ZeekLogToPolars()
    pf = obj.convert(path)

    print(pf.head)

def test_to_dask():
    obj = ZeekLogToDask()
    df = obj.convert(path)

    print(df.columns)


def main():
    #test_to_pandas()
    #test_to_dask()
    test_to_polars()
