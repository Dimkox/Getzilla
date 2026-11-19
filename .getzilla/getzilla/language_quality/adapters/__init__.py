"""Pure tool adapters. Execution belongs to the shared sandbox."""

import importlib


def load_adapter(module: str):
    """Load only the existing four trusted adapter families, never a project module."""
    if type(module) is not str or module not in {'eslint', 'kotlin', 'dart', 'swift'}:
        raise ValueError('unknown language adapter family')
    return importlib.import_module('.' + module, __package__)
