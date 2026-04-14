from analyzers.base import BaseAnalyzer, Finding, Severity

class NtdAnalyzer(BaseAnalyzer):
    name = "Red / Clientes (onstat -g ntd)"
    description = "Analiza conexiones de red y porcentaje de rejected por tipo de cliente."
    file_patterns = ["onstat.g.ntd"]

    def analyze(self, files: dict) -> list:
        path = files.get("onstat.g.ntd")
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
        clients = self._parse(lines)
        prefix = f"[{ctx}] " if ctx else ""

        if not clients:
            findings.append(Finding(
                title=f"{prefix}Sin datos de clientes",
                message="No se encontró la tabla de Client Type.",
                severity=Severity.INFO,
            ))
            return findings

        alerts = [c for c in clients if c["pct_rejected"] and c["pct_rejected"] > 1.0]
        sev = Severity.ALERT if alerts else Severity.OK
        resumen = "\n".join(
            f"  {c['client_type']:12s} accepted={c['accepted']:>10,}  rejected={c['rejected']:>8,}"
            + (f"  ({c['pct_rejected']:.3f}%)" if c["pct_rejected"] else "")
            for c in clients
        )
        msg = (f"{len(alerts)} cliente(s) superan 1% de rejected." if alerts
               else "Ningún cliente supera el 1% de rejected.")
        findings.append(Finding(
            title=f"{prefix}Conexiones de red",
            message=msg,
            severity=sev,
            detail=resumen,
        ))
        return findings

    def _parse(self, lines):
        in_table = False
        clients = []
        for line in lines:
            s = line.strip()
            if s.startswith("Client Type"):
                in_table = True
                continue
            if in_table:
                if s.startswith("Totals"):
                    break
                if not s or len(s.split()) < 6:
                    continue
                parts = s.split()
                try:
                    accepted = int(parts[2])
                    rejected = int(parts[3])
                except ValueError:
                    continue
                pct = (rejected * 100.0 / accepted) if accepted > 0 else None
                clients.append({"client_type": parts[0], "accepted": accepted,
                                 "rejected": rejected, "pct_rejected": pct})
        return clients
