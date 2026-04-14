"""
filtrar.py — Copia solo los archivos relevantes de una carpeta ifxcollect.
"""

import os
import shutil

PATTERNS = [
    "onstat.g.ntd", "onstat.g.act", "onstat.g.rea",
    "onstat.g.seg", "onstat.g.ckp", "onstat.g.glo",
    "onstat.k", "onstat.l", "onstat.p",
]


def filtrar(origen: str, destino: str) -> list:
    """
    Copia archivos relevantes de 'origen' a 'destino'.
    Devuelve lista de nombres copiados.
    """
    os.makedirs(destino, exist_ok=True)
    copiados = []
    for nombre in os.listdir(origen):
        ruta_origen = os.path.join(origen, nombre)
        if not os.path.isfile(ruta_origen):
            continue
        if any(nombre.startswith(p) for p in PATTERNS):
            shutil.copy2(ruta_origen, os.path.join(destino, nombre))
            copiados.append(nombre)
    return copiados
