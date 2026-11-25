"""Backward-compatible alias for :mod:`forace.monitor`."""
from importlib import import_module
import sys

sys.modules[__name__] = import_module("forace.monitor")
