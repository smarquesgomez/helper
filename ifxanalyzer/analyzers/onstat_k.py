import re
from collections import Counter
from analyzers.base import BaseAnalyzer


class LocksAnalyzer(BaseAnalyzer):
    name          = "Locks (onstat -k)"
    description   = "Analiza tipos de locks activos y lock table overflows."
    output_file   = "salida_locks_onstat_k.txt"
    file_patterns = ["onstat.k"]

    def analyze_to_file(self, files: dict, out):
        path = files.get("onstat.k")
        lines = self.read_file(path)
        for ctx, block in self.split_into_blocks(lines):
            self._bloque(block, ctx, out)

    def _bloque(self, lines, ctx, out):
        counts, total = self._parse_locks(lines)
        overflows = self._parse_overflows(lines)
        print("=" * 60, file=out)
        if ctx:
            print(ctx, file=out); print("-" * 60, file=out)

        print("1) Locks por tipo (columna 'type')", file=out)
        print("----------------------------------", file=out)
        if total == 0:
            print("No se encontraron filas de locks en la sección 'Locks'.", file=out)
        else:
            print(f"Total de locks contados: {total}", file=out)
            print("Detalle por tipo:", file=out)
            for t, c in sorted(counts.items(), key=lambda x: -x[1]):
                print(f"  {t}: {c}", file=out)
        print(file=out)

        print("2) Lock table overflows", file=out)
        print("------------------------", file=out)
        if overflows is not None:
            print(f"Cantidad de lock table overflows: {overflows}", file=out)
        else:
            print("No se encontró la línea de resumen con 'lock table overflows'.", file=out)

        print("=" * 60, file=out); print(file=out)

    def _parse_locks(self, lines):
        in_locks = header_seen = False
        counts = Counter()
        for line in lines:
            s = line.strip()
            if s == "Locks": in_locks = True; header_seen = False; continue
            if in_locks:
                if not header_seen:
                    if s.startswith("address") and "type" in s: header_seen = True
                    continue
                if "lock table overflows" in s: break
                if not s: continue
                parts = s.split()
                if len(parts) >= 5 and parts[0] != "address":
                    counts[parts[4]] += 1
        return counts, sum(counts.values())

    def _parse_overflows(self, lines):
        p = re.compile(r"(\d+)\s+lock table overflows", re.IGNORECASE)
        for line in lines:
            m = p.search(line)
            if m: return int(m.group(1))
        return None
