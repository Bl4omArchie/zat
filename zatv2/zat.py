import glob

class ZAT:
    def __init__(self, path):
        self.path = path

    def resolve_path(self):
        self.path_list = glob.glob(self.path)
