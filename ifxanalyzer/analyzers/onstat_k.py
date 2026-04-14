import re
from collections import Counter
from analyzers.base import BaseAnalyzer, Finding, Severity


class LocksAnalyzer(BaseAnalyzer):
    name = "Locks (onstat -k)"
    description = "Analiza tipos de locks activos y lock table overflows."
    file_patterns = ["onstat.k"]

    def analyze(self, files: dict) -> list:
        path = files.get("onstat.k")
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
        counts, total = self._parse_locks_table(lines)
        overflows = self._parse_lock_summary(lines)
        prefix = f"[{ctx}] " if ctx else ""

        # Locks por tipo
        if total == 0:
            findings.append(Finding(
                title=f"{prefix}Locks activos",
                message="No se encontraron locks activos.",
                severity=Severity.INFO,
            ))
        else:
            detalle = "\n".join(
                f"  {t}: {c}" for t, c in sorted(counts.items(), key=lambda x: -x[1])
            )
            findings.append(Finding(
                title=f"{prefix}Locks activos",
                message=f"Total de locks: {total}",
                severity=Severity.INFO,
                metric=f"{total} locks",
                detail=detalle,
            ))

        # Overflows
        if overflows is not None:
            sev = Severity.ALERT if overflows > 0 else Severity.OK
            msg = (f"Se registraron {overflows} lock table overflow(s)."
                   if overflows > 0 else "No se registraron lock table overflows.")
            findings.append(Finding(
                title=f"{prefix}Lock table overflows",
                message=msg,
                severity=sev,
                metric=str(overflows),
            ))

        return findings

    def _parse_locks_table(self, lines):
        in_locks = False
        header_seen = False
        counts = Counter()
        for line in lines:
            s = line.strip()
            if s == "Locks":
                in_locks = True
                header_seen = False
                continue
            if in_locks:
                if not header_seen:
                    if s.startswith("address") and "type" in s:
                        header_seen = True
                    continue
                if "lock table overflows" in s:
                    break
                if not s:
                    continue
                parts = s.split()
                if len(parts) < 5 or parts[0] == "address":
                    continue
                counts[parts[4]] += 1
        return counts, sum(counts.values())

    def _parse_lock_summary(self, lines):
        pattern = re.compile(r"(\d+)\s+lock table overflows", re.IGNORECASE)
        for line in lines:
            m = pattern.search(line)
            if m:
                return int(m.group(1))
        return None
