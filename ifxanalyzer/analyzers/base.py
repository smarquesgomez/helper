"""
BaseAnalyzer: clase base que deben heredar todos los analizadores.

Para crear un nuevo analizador:
  1. Creá un archivo .py en esta carpeta (analyzers/)
  2. Importá BaseAnalyzer y heredá de ella
  3. Definí los atributos de clase y el método analyze()

Ejemplo mínimo:
  from analyzers.base import BaseAnalyzer, Finding, Severity

  class MiAnalizador(BaseAnalyzer):
      name        = "Mi Analizador"
      description = "Qué hace este analizador"
      file_patterns = ["onstat.g.xxx"]   # patrones de archivos que consume

      def analyze(self, files: dict) -> list[Finding]:
          # files es un dict {patron: ruta_del_archivo}
          # retorna lista de Finding
          findings = []
          # ... tu lógica acá ...
          return findings
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    OK      = "ok"
    WARNING = "warning"   # ATENCIÓN (amarillo)
    ALERT   = "alert"     # ALERTA (rojo)
    INFO    = "info"      # informativo (azul)


@dataclass
class Finding:
    """Un hallazgo individual del análisis."""
    title:    str
    message:  str
    severity: Severity
    detail:   Optional[str] = None   # texto extra / tabla / raw data
    metric:   Optional[str] = None   # valor numérico clave (ej: "75.3%")


@dataclass
class AnalyzerResult:
    """Resultado completo de un analizador."""
    analyzer_name: str
    findings: list = field(default_factory=list)
    raw_output: str = ""
    error: Optional[str] = None

    @property
    def has_alerts(self):
        return any(f.severity == Severity.ALERT for f in self.findings)

    @property
    def has_warnings(self):
        return any(f.severity == Severity.WARNING for f in self.findings)

    @property
    def status(self):
        if self.error:
            return "error"
        if self.has_alerts:
            return "alert"
        if self.has_warnings:
            return "warning"
        return "ok"


class BaseAnalyzer:
    """
    Clase base para todos los analizadores.

    Atributos de clase a definir en cada subclase:
      name          (str)  : nombre legible del analizador
      description   (str)  : qué analiza
      file_patterns (list) : prefijos de archivos que necesita
                             ej: ["onstat.g.ckp"] o ["onstat.g.act", "onstat.g.glo"]
    """
    name: str = "Analizador base"
    description: str = ""
    file_patterns: list = []

    def analyze(self, files: dict) -> list:
        """
        Recibe un dict {patron: ruta_absoluta} con los archivos encontrados.
        Retorna una lista de Finding.
        Debe ser implementado por cada subclase.
        """
        raise NotImplementedError("Implementá el método analyze() en tu analizador.")

    def run(self, files: dict) -> AnalyzerResult:
        """Ejecuta el análisis y captura errores."""
        result = AnalyzerResult(analyzer_name=self.name)
        try:
            result.findings = self.analyze(files)
        except Exception as e:
            result.error = str(e)
        return result

    # ---- helpers comunes ----

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
