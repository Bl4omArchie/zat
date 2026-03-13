from typing import Any, List
import fsspec
import glob

from zatv2.reader import ZeekLogReader



class ZAT:
    def __init__(self, protocol: str, **storage_options: Any):
        self.fs = fsspec.filesystem(protocol=protocol, **storage_options)
        
        self.logfiles: List[ZeekLogReader] = []

    def open(self, path: str):
        files = glob.glob(path)
        
        for file in files:
            self.logfiles.append(ZeekLogReader(file))

    def get_files(self):
        return self.logfiles
