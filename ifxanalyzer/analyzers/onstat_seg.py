from analyzers.base import BaseAnalyzer, Finding, Severity

class SharedMemoryAnalyzer(BaseAnalyzer):
    name = "Shared Memory (onstat -g seg)"
    description = "Analiza segmentos de clase V y disponibilidad de memoria compartida."
    file_patterns = ["onstat.g.seg"]

    def analyze(self, files: dict) -> list:
        path = files.get("onstat.g.seg")
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
        v_segs = self._parse(lines)
        prefix = f"[{ctx}] " if ctx else ""

        if not v_segs:
            findings.append(Finding(
                title=f"{prefix}Sin segmentos V",
                message="No se encontraron segmentos de clase V.",
                severity=Severity.INFO,
            ))
            return findings

        total_v = len(v_segs)
        if total_v == 1:
            used, free = v_segs[0]
            total = used + free
            pct_free = (free / total * 100) if total > 0 else 0
            sev = Severity.ALERT if free == 0 else (Severity.WARNING if pct_free < 5 else Severity.OK)
            findings.append(Finding(
                title=f"{prefix}Shared memory",
                message=f"Segmento V: {pct_free:.1f}% libre ({free} bloques libres de {total}).",
                severity=sev,
                metric=f"{pct_free:.1f}% libre",
                detail=f"blkused: {used}\nblkfree: {free}\n% libre: {pct_free:.2f}%",
            ))
        else:
            findings.append(Finding(
                title=f"{prefix}Segmentos extra de memoria",
                message=f"Hay {total_v - 1} segmento(s) V adicional(es) alocados.",
                severity=Severity.WARNING,
                metric=f"{total_v} segmentos",
            ))
        return findings

    def _parse(self, lines):
        v_segs = []
        in_summary = False
        header_seen = False
        for line in lines:
            s = line.strip()
            if s.startswith("Segment Summary:"):
                in_summary = True
                header_seen = False
                continue
            if in_summary:
                if not header_seen:
                    if s.startswith("id"):
                        header_seen = True
                    continue
                if not s or s.startswith("Total:"):
                    break
                parts = s.split()
                if len(parts) < 8:
                    continue
                seg_class = parts[5]
                if seg_class.startswith("V"):
                    try:
                        v_segs.append((int(parts[6]), int(parts[7])))
                    except ValueError:
                        pass
        return v_segs
