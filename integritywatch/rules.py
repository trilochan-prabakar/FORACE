"""Backward-compatible alias for :mod:`forace.rules`."""
from importlib import import_module
import sys

sys.modules[__name__] = import_module("forace.rules")
