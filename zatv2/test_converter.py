from zatv2.to_dask import ZeekLogToDask
from zatv2.to_pandas import ZeekLogToPandas
from zatv2.to_polars import ZeekLogToPolars
from zatv2.zat import ZAT

import pandas as pd


path = "data/conn.log"



def test_to_pandas():
    """Test for ZeekLogToPandas Class"""
    import os
    pd.set_option('display.width', 1000)
    from zat.utils import file_utils

    # Grab a test file
    data_path = file_utils.relative_dir(__file__, '../data')
    log_path = os.path.join(data_path, 'conn.log')

    # Convert it to a Pandas DataFrame
    log_to_df = ZeekLogToPandas()
    my_df = log_to_df.convert(log_path)

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
        my_df = log_to_df.convert(log_path)
        print(my_df.head())
        print(my_df.dtypes)

    # Test out usecols arg
    conn_path = os.path.join(data_path, 'conn.log')
    my_df = log_to_df.convert(conn_path, usecols=['id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
                                                           'proto', 'orig_bytes', 'resp_bytes'])

    # Test an empty log (a log with header/close but no data rows)
    log_path = os.path.join(data_path, 'http_empty.log')
    my_df = log_to_df.convert(log_path)

    # Print out the head
    print(my_df.head())

    # Print out the datatypes
    print(my_df.dtypes)

    print('LogToDataFrame Test successful!')

def test_to_polars():
    obj = ZeekLogToPolars()
    pl = obj.convert(path)

    print(pl)

def test_to_dask():
    obj = ZeekLogToDask()
    df = obj.convert(path)

    print(df.columns)

def test_zat():
    obj = ZAT("file")
    obj.open("data/*.log")


def main():
    #test_to_pandas()
    #test_to_dask()
    #test_to_polars()
    test_zat()
