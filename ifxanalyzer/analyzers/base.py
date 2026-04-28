"""
BaseAnalyzer: clase base que deben heredar todos los analizadores.

Para crear un nuevo analizador:
  1. Creá un archivo .py en la carpeta analyzers/
  2. Importá BaseAnalyzer y heredá de ella
  3. Definí los atributos de clase y el método analyze_to_file()

Ejemplo mínimo:
  from analyzers.base import BaseAnalyzer

  class MiAnalizador(BaseAnalyzer):
      name         = "Mi Analizador"
      description  = "Qué hace este analizador"
      order        = 10
      output_file  = "salida_mi_analizador.txt"   # nombre del .txt de salida
      file_patterns = ["onstat.g.xxx"]             # archivos que consume

      def analyze_to_file(self, files: dict, out):
          # files = {patron: ruta_absoluta}
          # out   = file object abierto para escribir
          path = files.get("onstat.g.xxx")
          lines = self.read_file(path)
          print("Mi análisis", file=out)
          # ...
"""

import os
import sys
from typing import Optional


class BaseAnalyzer:
    """
    Clase base para todos los analizadores.

    Atributos de clase a definir en cada subclase:
      name          (str)  : nombre legible del analizador
      description   (str)  : qué analiza
      order
      output_file   (str)  : nombre del archivo .txt de salida
      file_patterns (list) : prefijos de archivos que necesita
                             ej: ["onstat.g.ckp"] o ["onstat.g.act", "onstat.g.glo"]
    """
    name: str = "Analizador base"
    description: str = ""
    order: int   = 99   # posición en la salida (99 = al final si no se define)
    output_file: str = "salida.txt"
    file_patterns: list = []

    def analyze_to_file(self, files: dict, out):
        """
        Recibe un dict {patron: ruta_absoluta} y un file object para escribir.
        Debe ser implementado por cada subclase.
        """
        raise NotImplementedError("Implementá analyze_to_file() en tu analizador.")

    def run(self, files: dict, out_dir: str) -> dict:
        """
        Ejecuta el análisis y escribe el .txt en out_dir.
        Devuelve {"name", "output_file", "ok", "error"}.
        """
        out_path = os.path.join(out_dir, self.output_file)
        try:
            with open(out_path, "w", encoding="utf-8") as out:
                self.analyze_to_file(files, out)
            return {"name": self.name, "output_file": self.output_file, "ok": True, "error": None}
        except Exception as e:
            return {"name": self.name, "output_file": self.output_file, "ok": False, "error": str(e)}

    # ── Helpers comunes ───────────────────────────────────────────

    @staticmethod
    def read_file(path: str) -> list:
        """Lee un archivo y devuelve sus líneas."""
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.readlines()

    @staticmethod
    def split_into_blocks(lines: list) -> list:
        """
        Separa líneas en bloques por 'File Iteration ...'.
        Devuelve lista de (contexto, [líneas]).
        """
        blocks = []
        current_lines = []
        current_ctx = None

        for line in lines:
            if line.startswith("File Iteration"):
                if current_lines:
                    blocks.append((current_ctx, current_lines))
                    current_lines = []
                current_ctx = line.strip()
            current_lines.append(line.rstrip("\n"))

        if current_lines:
            blocks.append((current_ctx, current_lines))

        return blocks or [(None, lines)]
