"""Backward-compatible alias for :mod:`forace.paths`."""
from importlib import import_module
import sys

sys.modules[__name__] = import_module("forace.paths")
