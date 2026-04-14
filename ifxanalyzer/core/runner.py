"""
runner.py — Orquestador central del análisis.
Recibe una carpeta o lista de archivos, los mapea a los analizadores
correspondientes y devuelve los resultados.
"""

import os
import glob
from analyzers.registry import get_all
from analyzers.base import AnalyzerResult, Finding, Severity

FILTER_PATTERNS = [
    "onstat.g.ntd", "onstat.g.act", "onstat.g.rea",
    "onstat.g.seg", "onstat.g.ckp", "onstat.g.glo",
    "onstat.k", "onstat.l", "onstat.p",
]


def _match_pattern(filename: str, pattern: str) -> bool:
    return os.path.basename(filename).startswith(pattern)


def find_files_in_folder(folder: str) -> dict:
    """
    Busca en la carpeta archivos que coincidan con los patrones
    de todos los analizadores registrados.
    Devuelve dict {pattern: ruta_absoluta}.
    """
    from analyzers.registry import get_required_patterns
    patterns = get_required_patterns()
    found = {}
    for f in os.listdir(folder):
        full = os.path.join(folder, f)
        if not os.path.isfile(full):
            continue
        for p in patterns:
            if f.startswith(p) and p not in found:
                found[p] = full
    return found


def map_files(file_list: list) -> dict:
    """
    Mapea una lista de rutas de archivos a patrones conocidos.
    """
    from analyzers.registry import get_required_patterns
    patterns = get_required_patterns()
    found = {}
    for path in file_list:
        name = os.path.basename(path)
        for p in patterns:
            if name.startswith(p) and p not in found:
                found[p] = path
    return found


def run_analysis(files: dict) -> list:
    """
    Ejecuta todos los analizadores sobre el dict de archivos.
    Devuelve lista de AnalyzerResult.
    """
    results = []
    analyzers = get_all()

    for analyzer in analyzers:
        # Solo ejecutar si tiene al menos un archivo requerido
        has_any = any(p in files for p in analyzer.file_patterns)
        if not has_any:
            continue
        result = analyzer.run(files)
        results.append(result)

    return results


def run_on_folder(folder: str) -> list:
    files = find_files_in_folder(folder)
    return run_analysis(files)


def run_on_files(file_list: list) -> list:
    files = map_files(file_list)
    return run_analysis(files)


def results_to_dict(results: list) -> list:
    """Convierte lista de AnalyzerResult a lista de dicts serializables (para JSON)."""
    out = []
    for r in results:
        out.append({
            "analyzer": r.analyzer_name,
            "status": r.status,
            "error": r.error,
            "findings": [
                {
                    "title": f.title,
                    "message": f.message,
                    "severity": f.severity.value,
                    "detail": f.detail,
                    "metric": f.metric,
                }
                for f in r.findings
            ],
        })
    return out
