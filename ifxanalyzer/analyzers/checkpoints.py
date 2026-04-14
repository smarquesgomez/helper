from collections import Counter
from analyzers.base import BaseAnalyzer, Finding, Severity


class CheckpointsAnalyzer(BaseAnalyzer):
    name = "Checkpoints (onstat -g ckp)"
    description = "Analiza triggers, tiempos y advertencias del physical log."
    file_patterns = ["onstat.g.ckp"]

    def analyze(self, files: dict) -> list:
        path = files.get("onstat.g.ckp")
        if not path:
            return []

        lines = self.read_file(path)
        blocks = self.split_into_blocks(lines)
        findings = []

        for ctx, block in blocks:
            findings.extend(self._analyze_block(block, ctx))

        return findings

    def _analyze_block(self, lines, ctx):
        findings = []
        triggers, total_times = self._parse_ckp_table(lines)
        warning = self._extract_physical_log_warning(lines)
        prefix = f"[{ctx}] " if ctx else ""

        if not total_times:
            findings.append(Finding(
                title=f"{prefix}Sin datos de checkpoints",
                message="No se encontraron filas de checkpoints en onstat -g ckp.",
                severity=Severity.INFO,
            ))
            return findings

        # Triggers
        norm = [t.upper() for t in triggers]
        counts = Counter(triggers)
        if set(norm) == {"CKPTINTVL"}:
            findings.append(Finding(
                title=f"{prefix}Triggers de checkpoints",
                message="Todos los checkpoints fueron disparados por CKPTINTVL (normal).",
                severity=Severity.OK,
                metric=f"{len(triggers)} ckpts",
            ))
        else:
            detalle = "\n".join(f"  {t}: {c} veces" for t, c in counts.items())
            findings.append(Finding(
                title=f"{prefix}Triggers no esperados",
                message="Se encontraron triggers distintos a CKPTINTVL.",
                severity=Severity.ALERT,
                detail=detalle,
            ))

        # Tiempos
        avg = sum(total_times) / len(total_times)
        max_t = max(total_times)
        sev = Severity.ALERT if max_t > 10 else (Severity.WARNING if max_t > 5 else Severity.OK)
        findings.append(Finding(
            title=f"{prefix}Tiempos de checkpoints",
            message=f"Promedio: {avg:.2f}s | Máximo: {max_t:.2f}s | Total: {len(total_times)} ckpts",
            severity=sev,
            metric=f"máx {max_t:.1f}s",
            detail=f"Mínimo: {min(total_times):.2f}s\nPromedio: {avg:.2f}s\nMáximo: {max_t:.2f}s",
        ))

        if warning:
            findings.append(Finding(
                title=f"{prefix}Physical log posiblemente pequeño",
                message="Informix detectó que el physical log podría ser demasiado chico.",
                severity=Severity.WARNING,
                detail=warning,
            ))

        return findings

    def _parse_ckp_table(self, lines):
        triggers, total_times = [], []
        header_idx = None
        for idx, line in enumerate(lines):
            if "Interval" in line and "Trigger" in line:
                header_idx = idx
                break
        if header_idx is None:
            return triggers, total_times
        i = header_idx + 1
        while i < len(lines):
            s = lines[i].strip()
            if not s or s.startswith("Max Plog"):
                break
            parts = s.split()
            if len(parts) < 5 or not parts[0].isdigit():
                i += 1
                continue
            try:
                triggers.append(parts[2])
                total_times.append(float(parts[4]))
            except (ValueError, IndexError):
                pass
            i += 1
        return triggers, total_times

    def _extract_physical_log_warning(self, lines):
        start = None
        for idx, line in enumerate(lines):
            if line.strip().startswith("Based on the current workload"):
                start = idx
                break
        if start is None:
            return None
        result = []
        for j in range(start, len(lines)):
            if j > start and not lines[j].strip():
                break
            result.append(lines[j].rstrip("\n"))
        return "\n".join(result)
