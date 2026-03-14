from typing import Any, List
import fsspec
import glob

from zat.zeek_log_reader import ZeekLogReader

"""
Goal : improve ZAT library with more features.

ZAT class purpose is to represent a unique interface where the user can load one or several files from any source (local, s3, ftp etc).
This class will alow glob and reading multiple files. Then it will read each files with ZeekLogReader.

Issues :
- json support
- classes like to_dask_, to_polars still can't read multiple files

Note : should I modify ZeekLogReader so it can read directly multiple files ?
"""

class ZAT:
    def __init__(self, protocol: str, **storage_options: Any):
        self.fs = fsspec.filesystem(protocol=protocol, **storage_options)
        
    def open(self, path: str) -> List[ZeekLogReader]:
        logfiles: List[ZeekLogReader] = []
        
        files = glob.glob(path)
        for file in files:
            logfiles.append(ZeekLogReader(file, self.fs))

        return logfiles


def test():
    obj = ZAT("local")
    print(obj.open("data/*.log"))
