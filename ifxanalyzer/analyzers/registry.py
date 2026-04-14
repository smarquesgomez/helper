"""
Registry de analizadores.
Se auto-descubren todos los módulos en esta carpeta que tengan clases
que hereden de BaseAnalyzer (excepto la propia BaseAnalyzer).
"""

import importlib
import pkgutil
import inspect
import os

from analyzers.base import BaseAnalyzer

_analyzers: list = []


def _load():
    global _analyzers
    if _analyzers:
        return

    pkg_dir = os.path.dirname(__file__)

    for finder, module_name, ispkg in pkgutil.iter_modules([pkg_dir]):
        if module_name in ("base", "registry"):
            continue
        try:
            mod = importlib.import_module(f"analyzers.{module_name}")
            for name, obj in inspect.getmembers(mod, inspect.isclass):
                if issubclass(obj, BaseAnalyzer) and obj is not BaseAnalyzer:
                    _analyzers.append(obj())
        except Exception as e:
            print(f"[WARN] No se pudo cargar analyzers.{module_name}: {e}")


def get_all() -> list:
    """Devuelve instancias de todos los analizadores disponibles."""
    _load()
    return _analyzers


def get_required_patterns() -> list:
    """Devuelve todos los file_patterns distintos requeridos."""
    _load()
    patterns = set()
    for a in _analyzers:
        patterns.update(a.file_patterns)
    return sorted(patterns)
