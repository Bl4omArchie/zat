__author__ = "Brian Wylie"
__email__ = "support@supercowpowers.com"

from importlib.metadata import version

try:
    __version__ = version("zat")
except Exception:
    __version__ = "unknown"
