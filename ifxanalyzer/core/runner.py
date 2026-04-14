"""
runner.py — Orquestador central del análisis.
Recibe una carpeta (con filtrado automático) o lista de archivos sueltos,
ejecuta todos los analizadores y genera los .txt de salida.
"""

import os
import shutil
import tempfile
from analyzers.registry import get_all, get_required_patterns
from core.filtrar import filtrar


def _map_files(folder: str) -> dict:
    """Mapea los archivos de una carpeta a los patrones requeridos."""
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


def run_on_folder(ifx_folder: str, out_folder: str) -> list:
    """
    Flujo 1: recibe la carpeta completa del ifxcollect.
    - Filtra los archivos relevantes a una subcarpeta temporal
    - Ejecuta todos los analizadores
    - Escribe los .txt en out_folder
    Devuelve lista de resultados {"name", "output_file", "ok", "error"}.
    """
    # Filtrar a carpeta temporal
    tmp = tempfile.mkdtemp(prefix="ifx_filtered_")
    try:
        filtrar(ifx_folder, tmp)
        return _run(tmp, out_folder)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def run_on_files(file_paths: list, out_folder: str) -> list:
    """
    Flujo 2: recibe una lista de archivos sueltos.
    - Los copia a una carpeta temporal
    - Ejecuta todos los analizadores
    - Escribe los .txt en out_folder
    Devuelve lista de resultados {"name", "output_file", "ok", "error"}.
    """
    tmp = tempfile.mkdtemp(prefix="ifx_loose_")
    try:
        for path in file_paths:
            shutil.copy2(path, tmp)
        return _run(tmp, out_folder)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _run(src_folder: str, out_folder: str) -> list:
    """Ejecuta todos los analizadores sobre src_folder y escribe en out_folder."""
    os.makedirs(out_folder, exist_ok=True)
    files = _map_files(src_folder)
    results = []
    for analyzer in get_all():
        has_files = any(p in files for p in analyzer.file_patterns)
        if not has_files:
            results.append({
                "name": analyzer.name,
                "output_file": analyzer.output_file,
                "ok": False,
                "error": "Archivos requeridos no encontrados: " + ", ".join(analyzer.file_patterns),
            })
            continue
        result = analyzer.run(files, out_folder)
        results.append(result)
    return results
